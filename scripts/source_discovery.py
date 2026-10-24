#!/usr/bin/env python3
"""Bounded public-source discovery for the existing Best50 builder.

No authentication is sent to public-source APIs. Only public HTTPS addresses
are contacted; DNS is validated and the selected address is pinned for TLS.
The state contains public source URLs and aggregate counters, never VLESS URIs.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import math
import re
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.robotparser
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit, parse_qsl

USER_AGENT = "Best50PublicSourceDiscovery/1.0"
SHARE_SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "socks")
SHARE_PATTERN = r"(?:vless|vmess|trojan|ss|hysteria2|hy2|socks)://"

MAX_SOURCE_BYTES = 2_000_000
MAX_LINK_LENGTH = 8192
MAX_LINKS_PER_SOURCE = 4000
MAX_CANDIDATES = 8000
MAX_SOURCES = 160
MAX_FETCH_SOURCES = 72
MAX_STATE_BYTES = 2_000_000
MAX_RETIRED_SOURCES = 320
MAX_DORMANT_SOURCES = 2 * MAX_SOURCES
MAX_DORMANT_REPROBES = 2
RETIREMENT_COOLDOWN = 7 * 86400
_DNS_SLOTS = threading.BoundedSemaphore(8)


def public_host(host: str) -> bool:
    """Syntactic check. Hostname DNS is checked immediately before use."""
    host = host.lower().rstrip(".")
    if not host or len(host) > 253 or re.search(r"[\s\x00-\x1f\x7f/@%\\]", host):
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.is_global and not address.is_multicast
    except ValueError:
        labels = host.split(".")
        return (len(labels) >= 2 and labels[-1] not in {"localhost", "local", "internal", "lan", "home", "invalid", "test", "onion"}
                and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
                and not re.fullmatch(r"[0-9.]+", host))


def canonical_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError("invalid source URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or not public_host(parsed.hostname or ""):
        raise ValueError("source must use public HTTPS without credentials")
    # Public subscriptions may use formatting parameters; reject credential-like ones.
    if any(key.lower() in {"token", "key", "password", "auth", "access_token", "api_key"} for key, _ in parse_qsl(parsed.query, max_num_fields=24)):
        raise ValueError("credential-bearing source URL")
    path = parsed.path or "/"
    host = parsed.hostname.lower().rstrip(".")
    if host == "github.com":
        parts = path.split("/")
        if len(parts) >= 6 and parts[3] in {"blob", "raw"}:
            host = "raw.githubusercontent.com"
            path = "/" + "/".join(parts[1:3] + parts[4:])
    if host == "raw.githubusercontent.com":
        path = path.replace("/refs/heads/", "/", 1)
    netloc = f"[{host}]" if ":" in host else host
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def public_addresses(host: str, timeout: float = 5) -> list[tuple]:
    # getaddrinfo has no portable timeout. Daemon workers cannot delay process
    # shutdown; the global cap bounds resources even if the system resolver hangs.
    if not _DNS_SLOTS.acquire(blocking=False):
        raise TimeoutError("source DNS worker budget exhausted")
    results = queue.Queue(maxsize=1)
    def resolve():
        try:
            results.put((socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM), None))
        except Exception as error:
            results.put((None, error))
        finally:
            _DNS_SLOTS.release()
    threading.Thread(target=resolve, daemon=True, name="best50-source-dns").start()
    try:
        infos, error = results.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError("source DNS deadline exceeded") from None
    if error is not None:
        raise error
    if not infos or any(not ipaddress.ip_address(info[4][0]).is_global or ipaddress.ip_address(info[4][0]).is_multicast for info in infos):
        raise ValueError("source resolves to a non-public address")
    return infos


class RateLimited(RuntimeError):
    def __init__(self, retry_at: int):
        self.retry_at = retry_at
        super().__init__("public source rate limited")


class SourceBudgetExhausted(RuntimeError):
    """Our own scheduling limit, never evidence that a public feed failed."""
    def __init__(self, stop_collection: bool = True):
        self.stop_collection = stop_collection
        super().__init__("discovery resource budget exhausted")


class SourcePolicyUnavailable(RuntimeError):
    """A missing/temporary policy response forbids fetching until retry_at."""
    def __init__(self, retry_at=0, *, now=None):
        now = int(time.time() if now is None else now)
        if type(retry_at) not in (int, float) or (type(retry_at) is float and not math.isfinite(retry_at)):
            retry_at = 0
        self.retry_at = min(now + 86400, max(now + 60, int(retry_at) if retry_at else now + 1800))
        super().__init__("public source policy temporarily unavailable")


def rate_limit_retry_at(headers: dict, now: int | None = None) -> int:
    """Honor both HTTP Retry-After forms, with bounded malformed-header fallback."""
    now = int(time.time() if now is None else now)
    deadlines = [now + 60]
    reset = headers.get("x-ratelimit-reset")
    if reset is not None:
        if isinstance(reset, str) and re.fullmatch(r"[0-9]{1,15}", reset.strip()):
            deadlines.append(int(reset.strip()))
        else:
            deadlines.append(now + 3600)
    retry = headers.get("retry-after")
    if retry is not None:
        try:
            if not isinstance(retry, str) or len(retry) > 128:
                raise ValueError("invalid retry header")
            retry = retry.strip()
            if re.fullmatch(r"[0-9]{1,15}", retry):
                deadlines.append(now + int(retry))
            else:
                date = parsedate_to_datetime(retry)
                if date.tzinfo is None or date.utcoffset() is None:
                    raise ValueError("retry HTTP date has no timezone")
                deadlines.append(int(date.timestamp()))
        except (ValueError, TypeError, OverflowError):
            deadlines.append(now + 3600)
    return min(now + 86400, max(deadlines))


def safe_get(url: str, max_bytes: int = MAX_SOURCE_BYTES, timeout: float = 12, redirect_policy=None) -> tuple[bytes, dict]:
    """Fetch bounded HTTPS without env proxies, revalidating every redirect.

    Pin the connection address after DNS validation, preserving the original
    hostname for certificate verification/SNI. This closes DNS rebinding SSRF.
    """
    deadline = time.monotonic() + timeout
    for _ in range(4):
        url = canonical_url(url)
        parsed = urlsplit(url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("source total deadline exceeded")
        addresses = public_addresses(parsed.hostname, timeout=min(5, remaining))
        address = addresses[0]
        owned_socket = [None]
        response_holder = [None]

        def connect_pinned(_address, timeout=timeout, source_address=None, **_kwargs):
            sock = socket.socket(address[0], socket.SOCK_STREAM)
            owned_socket[0] = sock
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                sock.close()
                raise TimeoutError("source total deadline exceeded")
            sock.settimeout(min(timeout, remaining))
            try:
                sock.connect(address[4])
            except BaseException:
                sock.close()
                raise
            return sock

        conn = http.client.HTTPSConnection(parsed.hostname, timeout=timeout, context=ssl.create_default_context())
        conn._create_connection = connect_pinned
        def abort_owned_request(conn=conn, response_holder=response_holder, owned_socket=owned_socket):
            # Socket inactivity timeouts alone allow arbitrarily slow headers.
            # Shutdown only this request's socket at its absolute deadline.
            current = conn.sock
            if current is None and response_holder[0] is not None:
                raw = getattr(getattr(response_holder[0], "fp", None), "raw", None)
                current = getattr(raw, "_sock", None)
            current = current if current is not None else owned_socket[0]
            if current is not None:
                try:
                    current.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        timer = threading.Timer(max(.001, deadline - time.monotonic()), abort_owned_request)
        timer.daemon = True
        timer.start()
        try:
            conn.request("GET", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""), headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json" if parsed.hostname == "api.github.com" else "text/plain, application/json;q=0.9, */*;q=0.5", "Accept-Encoding": "identity"})
            response = conn.getresponse()
            response_holder[0] = response
            headers = {k.lower(): v for k, v in response.getheaders()}
            if response.status in {301, 302, 303, 307, 308}:
                url = canonical_url(urljoin(url, headers.get("location", "")))
                if redirect_policy is not None and not redirect_policy(url):
                    raise ValueError("redirect disallowed by source policy")
                continue
            if response.status in {403, 429}:
                raise RateLimited(rate_limit_retry_at(headers))
            if response.status != 200:
                raise RuntimeError(f"source HTTP {response.status}")
            if int(headers.get("content-length", "0") or 0) > max_bytes:
                raise ValueError("source exceeds byte budget")
            body = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("source total deadline exceeded")
                # read1 performs one buffered/raw read rather than waiting for
                # the full budget; a slow drip cannot reset a per-read deadline.
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                chunk = response.read1(min(65536, max_bytes + 1 - len(body)))
                if not chunk:
                    return bytes(body), headers
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ValueError("source exceeds byte budget")
        finally:
            timer.cancel()
            conn.close()
    raise ValueError("source redirect limit exceeded")


def decode_subscription(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    if not re.search(SHARE_PATTERN, text, re.I):
        compact = re.sub(r"\s+", "", text)
        if len(compact) <= MAX_SOURCE_BYTES:
            try:
                decoded = base64.b64decode(compact + "===", validate=False).decode("utf-8", "replace")
                if re.search(SHARE_PATTERN, decoded, re.I):
                    text = decoded
            except (ValueError, UnicodeError):
                pass
    return text


def extract_links(text: str) -> list[str]:
    found = []
    seen = set()
    # finditer, bounded input and bounded link length avoid line-based greedy scans.
    for match in re.finditer(SHARE_PATTERN + r"[^\s<>\"`]{1,8193}", text[:MAX_SOURCE_BYTES], re.I):
        link = match.group().rstrip("`,)]}>\"'")
        if len(link) <= MAX_LINK_LENGTH and link not in seen:
            found.append(link)
            seen.add(link)
        if len(found) >= MAX_LINKS_PER_SOURCE:
            break
    return found


def feed_urls(text: str) -> list[str]:
    urls = []
    for match in re.finditer(r"https://[^\s<>\"`\]\)]+", text[:MAX_SOURCE_BYTES], re.I):
        candidate = match.group().rstrip(".,;'")
        try:
            url = canonical_url(candidate)
        except ValueError:
            continue
        parsed = urlsplit(url)
        path = parsed.path.lower()
        if parsed.hostname == "raw.githubusercontent.com" or (re.search(r"(?:vless|vmess|trojan|hysteria|socks|shadowsocks|subscription|/sub(?:/|$)|config|feed)", path) and path.endswith((".txt", ".sub", ".list", "/sub"))):
            urls.append(url)
        if len(urls) >= 40:
            break
    return list(dict.fromkeys(urls))


class SourcePool:
    def __init__(self, seeds: list[dict], state_path: Path, now: int | None = None):
        self.path = Path(state_path)
        self.now = int(time.time() if now is None else now)
        self.state = {"version": 1, "sources": {}, "repositories": {}, "retired_sources": {},
                      "dormant_sources": {}, "last_discovery": 0, "last_qualified": 0}
        try:
            if self.path.stat().st_size <= MAX_STATE_BYTES:
                value = json.loads(self.path.read_text())
                if isinstance(value, dict) and type(value.get("version", 1)) is int and value.get("version", 1) == 1:
                    self._restore_state(value)
        except (OSError, ValueError, TypeError, RecursionError):
            pass
        self.sources = self.state["sources"]
        seed_keys = set()
        for seed in seeds:
            try:
                url = canonical_url(seed.get("url", "")) if isinstance(seed, dict) else ""
                if url:
                    seed_keys.add(hashlib.sha256(url.encode()).hexdigest()[:24])
            except (ValueError, TypeError):
                pass
        for key, item in self.sources.items():
            if item["origin"] == "seed" and key not in seed_keys:
                item["origin"] = "public-feed-link"
        for seed in seeds:
            if not isinstance(seed, dict):
                continue
            # A corrupt/full registry must never evict configured working seeds.
            try:
                seed_url = canonical_url(seed.get("url", ""))
            except (ValueError, TypeError):
                continue
            key = hashlib.sha256(seed_url.encode()).hexdigest()[:24]
            if key in self.sources:
                self.sources[key]["origin"] = "seed"
                continue
            if len(self.sources) >= MAX_SOURCES:
                removable = next((key for key, item in reversed(self.sources.items()) if item["origin"] != "seed"), None)
                if removable is not None:
                    self._remember_dormant(self.sources[removable])
                    self.state["retired_sources"][removable] = self.now + RETIREMENT_COOLDOWN
                    del self.sources[removable]
            self.add(seed.get("url", ""), origin="seed")
        self.state["retired_sources"] = dict(sorted(
            self.state["retired_sources"].items(), key=lambda pair: pair[1], reverse=True,
        )[:MAX_RETIRED_SOURCES])
        self.requests = 0
        self.started = time.monotonic()
        self.robots = {}
        self.origin_last_request = {}
        self.stats = {"discovered_sources": 0, "fetched_sources": 0, "source_failures": 0, "rate_limited": False}
        self.link_sources: dict[str, set[str]] = {}

    @staticmethod
    def _integer(value, default=0, maximum=1_000_000):
        if type(value) not in (int, float) or value < 0:
            return default
        if type(value) is float and (not math.isfinite(value) or int(value) != value):
            return default
        return min(int(value), maximum)

    def _restore_state(self, value: dict) -> None:
        """Retain only typed, bounded public metadata from a cached registry."""
        restored = {}
        raw_sources = value.get("sources", {})
        if isinstance(raw_sources, dict):
            for item in raw_sources.values():
                if not isinstance(item, dict):
                    continue
                try:
                    url = canonical_url(item.get("url", ""))
                except (ValueError, TypeError):
                    continue
                key = hashlib.sha256(url.encode()).hexdigest()[:24]
                if key in restored:
                    continue
                origin = item.get("origin")
                if not isinstance(origin, str) or origin not in {"seed", "github-search", "public-feed-link", "grok-research"}:
                    origin = "public-feed-link"
                clean = {"url": url, "origin": origin}
                clean["first_seen"] = self._integer(item.get("first_seen"), self.now, self.now)
                for name in ("last_fetch", "last_changed", "last_success", "last_tested"):
                    clean[name] = self._integer(item.get(name), maximum=self.now)
                clean["next_fetch"] = self._integer(item.get("next_fetch"), maximum=self.now + 86400)
                for name in ("empty_runs", "validation_runs"):
                    clean[name] = self._integer(item.get(name))
                clean["failures"] = self._integer(item.get("failures"), maximum=16)
                for name in ("candidate_count", "last_tested_count", "last_functional_count"):
                    clean[name] = self._integer(item.get(name), maximum=MAX_LINKS_PER_SOURCE)
                reputation = item.get("functional_ema", 0)
                clean["functional_ema"] = (float(reputation) if type(reputation) in (int, float)
                                           and 0 <= reputation <= 1 and math.isfinite(reputation) else 0.0)
                digest = item.get("content_sha256")
                if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
                    clean["content_sha256"] = digest
                restored[key] = clean
                if len(restored) >= MAX_SOURCES:
                    break
        self.state["sources"] = restored
        for name in ("last_discovery", "updated_at"):
            self.state[name] = self._integer(value.get(name), maximum=self.now)
        self.state["api_retry_at"] = self._integer(value.get("api_retry_at"), maximum=self.now + 86400)
        self.state["last_qualified"] = self._integer(value.get("last_qualified"), maximum=500)
        self.state["discovery_round"] = self._integer(value.get("discovery_round"), maximum=1_000_000_000)
        repositories = value.get("repositories", {})
        if isinstance(repositories, dict):
            repositories = {name: self._integer(seen, maximum=self.now) for name, seen in repositories.items()
                            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", name)}
            self.state["repositories"] = dict(sorted(repositories.items(), key=lambda pair: pair[1], reverse=True)[:200])
        retired = value.get("retired_sources", {})
        if isinstance(retired, dict):
            retired = {key: self._integer(until, maximum=self.now + RETIREMENT_COOLDOWN)
                       for key, until in retired.items()
                       if isinstance(key, str) and re.fullmatch(r"[0-9a-f]{24}", key)}
            self.state["retired_sources"] = dict(sorted(
                ((key, until) for key, until in retired.items() if until > self.now),
                key=lambda pair: pair[1], reverse=True,
            )[:MAX_RETIRED_SOURCES])
        dormant = value.get("dormant_sources", {})
        if isinstance(dormant, dict):
            restored_dormant = {}
            for key, record in dormant.items():
                try:
                    if (not isinstance(record, dict)
                            or set(record) != {"url", "origin", "retired_at", "retry_at"}):
                        continue
                    url = canonical_url(record["url"])
                    expected = hashlib.sha256(url.encode()).hexdigest()[:24]
                    retired_at, retry_at = record["retired_at"], record["retry_at"]
                    if (key != expected or key in restored
                            or record["origin"] not in {"github-search", "public-feed-link", "grok-research"}
                            or type(retired_at) not in (int, float) or type(retry_at) not in (int, float)
                            or not math.isfinite(retired_at) or not math.isfinite(retry_at)
                            or not 0 < retired_at <= self.now
                            or retry_at != retired_at + RETIREMENT_COOLDOWN):
                        continue
                    # A newer surviving hash ledger always keeps its cooldown,
                    # including caches written by an earlier implementation.
                    retry_at = max(retry_at, self.state["retired_sources"].get(key, 0))
                    restored_dormant[key] = {"url": url, "origin": record["origin"],
                                            "retired_at": retry_at - RETIREMENT_COOLDOWN,
                                            "retry_at": retry_at}
                except (ValueError, KeyError, TypeError, OverflowError):
                    continue
            self.state["dormant_sources"] = dict(sorted(
                restored_dormant.items(), key=lambda pair: (-pair[1]["retired_at"], pair[0]),
            )[:MAX_DORMANT_SOURCES])

    def _remember_dormant(self, item: dict) -> None:
        """Keep bounded public URLs so retirement does not depend on rediscovery."""
        try:
            url = canonical_url(item["url"])
        except (KeyError, ValueError, TypeError):
            return
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        origin = item.get("origin")
        if not isinstance(origin, str) or origin not in {"github-search", "public-feed-link", "grok-research"}:
            origin = "public-feed-link"
        self.state["dormant_sources"][key] = {"url": url, "origin": origin,
                                               "retired_at": self.now,
                                               "retry_at": self.now + RETIREMENT_COOLDOWN}
        self.state["dormant_sources"] = dict(sorted(
            self.state["dormant_sources"].items(), key=lambda pair: (-pair[1]["retired_at"], pair[0]),
        )[:MAX_DORMANT_SOURCES])

    def _reprobe_dormant(self) -> None:
        due = sorted(((key, item) for key, item in self.state["dormant_sources"].items()
                      if self.now >= item["retry_at"]), key=lambda pair: (pair[1]["retry_at"], pair[0]))
        for key, item in due[:MAX_DORMANT_REPROBES]:
            if key in self.sources:
                self.state["dormant_sources"].pop(key, None)
            elif self.add(item["url"], item["origin"]):
                self.stats["dormant_reprobes"] = self.stats.get("dormant_reprobes", 0) + 1

    def add(self, url: str, origin: str) -> bool:
        try:
            url = canonical_url(url)
        except (ValueError, TypeError):
            return False
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        if origin != "seed" and self.state["retired_sources"].get(key, 0) > self.now:
            return False
        if key in self.sources:
            return False
        if len(self.sources) >= MAX_SOURCES:
            if origin == "seed" or getattr(self, "_exploration_replacements", 0) >= 4:
                return False
            # Keep the best 80% of established non-seeds and all configured
            # seeds. Four bounded trials prevent a full, healthy-but-locally
            # unhelpful registry from permanently blocking new discoveries.
            nonseeds = [(existing, item) for existing, item in self.sources.items() if item["origin"] != "seed"]
            nonseeds.sort(key=lambda pair: (
                pair[1].get("functional_ema", 0),
                min(1.0, pair[1].get("last_functional_count", 0) / max(1, pair[1].get("last_tested_count", 0))),
                -pair[1].get("failures", 0), pair[1]["first_seen"], pair[0],
            ))
            eligible = [(existing, item) for existing, item in nonseeds[:max(1, len(nonseeds) // 5)]
                        if self.now - item["first_seen"] >= 86400]
            if not eligible:
                return False
            victim = eligible[0][0]
            self._remember_dormant(self.sources[victim])
            self.state["retired_sources"][victim] = self.now + RETIREMENT_COOLDOWN
            self.state["retired_sources"] = dict(sorted(self.state["retired_sources"].items(),
                                                        key=lambda pair: pair[1], reverse=True)[:MAX_RETIRED_SOURCES])
            del self.sources[victim]
            self._exploration_replacements = getattr(self, "_exploration_replacements", 0) + 1
            if hasattr(self, "stats"):
                self.stats["exploration_replacements"] = self._exploration_replacements
        self.sources[key] = {"url": url, "origin": origin, "first_seen": self.now, "last_fetch": 0, "last_changed": 0, "failures": 0, "functional_ema": 0.0, "next_fetch": 0}
        self.state["dormant_sources"].pop(key, None)
        return True

    def _before_request(self, url: str) -> None:
        if self.requests >= 110 or time.monotonic() - self.started > 180:
            raise SourceBudgetExhausted()
        origin = "https://" + urlsplit(url).netloc
        policy = self.robots.get(origin)
        delay = 0.25
        if isinstance(policy, urllib.robotparser.RobotFileParser):
            delay = max(delay, float(policy.crawl_delay(USER_AGENT) or 0))
            rate = policy.request_rate(USER_AGENT)
            if rate and rate.requests:
                delay = max(delay, rate.seconds / rate.requests)
        remaining = delay - (time.monotonic() - self.origin_last_request.get(origin, 0))
        if remaining > 0:
            if remaining > 15 or time.monotonic() - self.started + remaining > 180:
                raise SourceBudgetExhausted(stop_collection=time.monotonic() - self.started + remaining > 180)
            time.sleep(remaining)
        self.requests += 1
        self.origin_last_request[origin] = time.monotonic()

    def get(self, url: str, max_bytes: int = MAX_SOURCE_BYTES, robots_fetch: bool = False) -> tuple[bytes, dict]:
        self._before_request(url)
        def redirect_allowed(target):
            # Never recursively fetch a new site's policy while fetching robots.
            # Unknown robot redirects fail closed. Normal source redirects check
            # the new site's policy and count/delay its actual request as well.
            if robots_fetch or not self.allowed(target):
                return False
            self._before_request(target)
            return True
        return safe_get(url, max_bytes=max_bytes, redirect_policy=redirect_allowed)

    def allowed(self, url: str) -> bool:
        origin = "https://" + urlsplit(url).netloc
        # API and raw content are explicitly public download interfaces rather
        # than web page scraping. Every other site's robots policy is checked.
        if urlsplit(url).hostname in {"api.github.com", "raw.githubusercontent.com"}:
            return True
        if origin not in self.robots:
            parser = urllib.robotparser.RobotFileParser()
            try:
                raw, _ = self.get(origin + "/robots.txt", max_bytes=128000, robots_fetch=True)
                parser.parse(raw.decode("utf-8", "replace").splitlines())
                self.robots[origin] = parser
            except SourceBudgetExhausted:
                raise
            except RateLimited as exc:
                self.robots[origin] = SourcePolicyUnavailable(exc.retry_at, now=self.now)
            except RuntimeError as exc:
                # Explicit 404 means no robots policy; all other uncertainty
                # fails closed for automatic crawling.
                if str(exc) == "source HTTP 404":
                    self.robots[origin] = True
                else:
                    self.robots[origin] = SourcePolicyUnavailable(now=self.now)
            except Exception:
                self.robots[origin] = SourcePolicyUnavailable(now=self.now)
        policy = self.robots[origin]
        if isinstance(policy, SourcePolicyUnavailable):
            raise policy
        return policy if isinstance(policy, bool) else policy.can_fetch(USER_AGENT, url)

    def discover(self) -> None:
        interval = 7200 if int(self.state.get("last_qualified", 0)) < 20 else 21600
        if self.now < int(self.state.get("api_retry_at", 0)) or self.now - int(self.state.get("last_discovery", 0)) < interval:
            return
        queries = ["proxy subscription", "v2ray configs", "sing-box subscription", "hysteria2 proxy", "shadowsocks subscription"]
        query = queries[int(self.state.get("discovery_round", 0)) % len(queries)]
        since = (datetime.fromtimestamp(self.now, timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")
        url = "https://api.github.com/search/repositories?" + urlencode({"q": f"{query} pushed:>{since} archived:false fork:false", "sort": "updated", "order": "desc", "per_page": 20})
        try:
            raw, _ = self.get(url)
            repositories = json.loads(raw).get("items", [])
            if not isinstance(repositories, list):
                raise ValueError("invalid repository search result")
            # Recently seen repos move to the back; long-lived feeds get new peers.
            repositories.sort(key=lambda repo: int(self.state.get("repositories", {}).get(repo.get("full_name", ""), 0)))
            for repo in repositories[:8]:
                name = repo.get("full_name", "")
                branch = repo.get("default_branch", "")
                if repo.get("private") or repo.get("disabled") or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name) or not branch or len(branch) > 200:
                    continue
                try:
                    raw, _ = self.get(f"https://api.github.com/repos/{name}/git/trees/{quote(branch, safe='')}?recursive=1", max_bytes=4_000_000)
                    tree = json.loads(raw).get("tree", [])
                    candidates = []
                    for item in tree[:10000]:
                        path = item.get("path", "")
                        if item.get("type") != "blob" or not isinstance(path, str) or len(path) > 500 or int(item.get("size", 0)) > MAX_SOURCE_BYTES:
                            continue
                        lower = path.lower()
                        if lower.endswith((".txt", ".sub", ".list")) and re.search(r"vless|vmess|trojan|hysteria|socks|shadowsocks|all.config|subscription|verified|best|config\.txt|list\.txt|sub/", lower):
                            candidates.append((0 if re.search(r"vless|vmess|trojan|hysteria|socks|shadowsocks|verified|best", lower) else 1, path))
                        elif lower in {"readme.md", "readme.txt"}:
                            candidates.append((2, path))
                    for _, path in sorted(candidates)[:5]:
                        if self.add(f"https://raw.githubusercontent.com/{name}/{quote(branch, safe='')}/{quote(path, safe='/')}", origin="github-search"):
                            self.stats["discovered_sources"] += 1
                    self.state.setdefault("repositories", {})[name] = self.now
                except (RateLimited, SourcePolicyUnavailable):
                    raise
                except Exception:
                    continue
            self.state["last_discovery"] = self.now
            self.state["discovery_round"] = int(self.state.get("discovery_round", 0)) + 1
        except (RateLimited, SourcePolicyUnavailable) as exc:
            self.state["api_retry_at"] = min(self.now + 86400, max(self.now + 60, exc.retry_at))
            self.stats["rate_limited"] = True
        except SourceBudgetExhausted:
            self.stats["budget_exhausted"] = True
        except Exception as exc:
            self.stats["discovery_error"] = type(exc).__name__
            # Retry on the next scheduled run; existing feeds still operate.

    def collect(self) -> tuple[list[str], dict]:
        self.save()  # Retire unusable feeds before admitting new discoveries.
        # Revisit a bounded dormant tranche before fresh discovery. At a full
        # registry it shares, rather than expands, the four-replacement budget.
        self._reprobe_dormant()
        self.discover()
        # Successful feeds are inputs to every explicit build, including an
        # expedited replenishment immediately after the previous run. Only real
        # source failures/rate limits carry a persistent retry cooldown.
        due = [(key, item) for key, item in self.sources.items()
               if int(item.get("failures", 0)) == 0 or self.now >= int(item.get("next_fetch", 0))]
        # Favor proven useful feeds, retaining one quarter of slots for exploration.
        due.sort(key=lambda pair: (-float(pair[1].get("functional_ema", 0)), int(pair[1].get("last_fetch", 0)), pair[0]))
        explore = sorted(due, key=lambda pair: (int(pair[1].get("last_fetch", 0)), pair[0]))[:MAX_FETCH_SOURCES // 4]
        selected = list({key: item for key, item in explore + due}.items())[:MAX_FETCH_SOURCES]
        batches = []
        source_stats = {}
        for selected_index, (key, item) in enumerate(selected):
            if key not in self.sources:  # Replaced while an earlier feed was discovering new sources.
                continue
            try:
                if not self.allowed(item["url"]):
                    raise ValueError("source policy disallows discovery")
                raw, _ = self.get(item["url"])
                text = decode_subscription(raw)
                links = extract_links(text)
                if links:
                    stride = max(1, MAX_CANDIDATES // max(1, len(selected)))
                    offset = ((self.now // 7200) * stride) % len(links)
                    links = links[offset:] + links[:offset]
                digest = hashlib.sha256(raw).hexdigest()
                if digest != item.get("content_sha256"):
                    item["last_changed"] = self.now
                item.update({"last_fetch": self.now, "last_success": self.now, "content_sha256": digest, "candidate_count": len(links), "empty_runs": 0 if links else int(item.get("empty_runs", 0)) + 1, "failures": 0, "next_fetch": self.now})
                batches.append(links)
                for link in links:
                    self.link_sources.setdefault(link, set()).add(key)
                source_stats[key] = {"candidates": len(links), "origin": item["origin"], "last_changed": item["last_changed"]}
                for url in feed_urls(text)[:12]:
                    if self.add(url, origin="public-feed-link"):
                        self.stats["discovered_sources"] += 1
                self.stats["fetched_sources"] += 1
                print(f"Source {key}: {len(links)} candidates ({item['origin']})")
            except SourceBudgetExhausted as exc:
                source_stats[key] = {"deferred": "discovery-budget"}
                self.stats["deferred_sources"] = self.stats.get("deferred_sources", 0) + 1
                if exc.stop_collection:
                    self.stats["budget_exhausted"] = True
                    self.stats["deferred_sources"] += len(selected) - selected_index - 1
                    break
            except Exception as exc:
                failures = min(int(item.get("failures", 0)) + 1, 16)
                delay = min(86400, 1800 * 2 ** min(failures - 1, 6))
                item.update({"last_fetch": self.now, "failures": failures, "next_fetch": self.now + delay})
                if isinstance(exc, (RateLimited, SourcePolicyUnavailable)):
                    item["next_fetch"] = max(item["next_fetch"], min(self.now + 86400, max(self.now + 60, exc.retry_at)))
                    self.stats["rate_limited"] = True
                source_stats[key] = {"error": type(exc).__name__, "retry_at": item["next_fetch"]}
                self.stats["source_failures"] += 1
                print(f"Source {key}: {type(exc).__name__}; retry in {item['next_fetch'] - self.now}s")
        # Round-robin candidates prevents one large feed exhausting the pool.
        all_links = []
        seen_links = set()
        for index in range(max((len(batch) for batch in batches), default=0)):
            for batch in batches:
                if index < len(batch):
                    link = batch[index]
                    if link in seen_links:
                        continue
                    seen_links.add(link)
                    all_links.append(link)
                    if len(all_links) >= MAX_CANDIDATES:
                        self.save()
                        return all_links, source_stats
        self.save()
        return all_links, source_stats

    def feedback(self, tested: list[str], functional: set[str], qualified_count: int) -> None:
        counts = {}
        for link in tested:
            for key in self.link_sources.get(link, ()):
                total, passed = counts.get(key, (0, 0))
                counts[key] = (total + 1, passed + int(link in functional))
        for key, (total, passed) in counts.items():
            item = self.sources.get(key)
            if item is None:  # Exploration may replace a source after its candidates were collected.
                continue
            ratio = passed / total
            item["functional_ema"] = round(0.65 * float(item.get("functional_ema", 0)) + 0.35 * ratio, 6)
            item.update({"last_tested": self.now, "last_tested_count": total, "last_functional_count": passed, "validation_runs": int(item.get("validation_runs", 0)) + 1})
        self.state["last_qualified"] = int(qualified_count)
        self.save()

    def save(self) -> None:
        # Retire failed, unused discovered feeds so the pool continually replenishes.
        retired = {key: until for key, until in self.state["retired_sources"].items() if until > self.now}
        for key, item in list(self.sources.items()):
            age = self.now - int(item.get("first_seen", self.now))
            last_success = int(item.get("last_success", 0) or item.get("first_seen", self.now))
            failed = int(item.get("failures", 0)) >= 5 and self.now - last_success > 7 * 86400
            empty = int(item.get("empty_runs", 0)) >= 3 and age > 3 * 86400
            unproductive = int(item.get("validation_runs", 0)) >= 6 and float(item.get("functional_ema", 0)) == 0 and age > 7 * 86400
            if item.get("origin") != "seed" and (failed or empty or unproductive):
                self._remember_dormant(item)
                retired[key] = self.now + RETIREMENT_COOLDOWN
                del self.sources[key]
        self.state["retired_sources"] = dict(sorted(retired.items(), key=lambda pair: pair[1], reverse=True)[:MAX_RETIRED_SOURCES])
        self.state["repositories"] = dict(sorted(self.state.get("repositories", {}).items(), key=lambda pair: pair[1], reverse=True)[:200])
        self.state["updated_at"] = self.now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.state, sort_keys=True, indent=2) + "\n")
        temp.replace(self.path)
