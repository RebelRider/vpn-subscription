"""Bounded read-only public discovery tools; model output is never executable.

Only deterministic extraction can create a candidate. Public audit metadata has
hashes, not URI credentials; the existing validator remains authoritative.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from source_discovery import (SourcePool, SourceBudgetExhausted, RateLimited,
                              SourcePolicyUnavailable, canonical_url, decode_subscription,
                              extract_links, feed_urls)
from regional_scheduler import atomic_json, redact

MAX_REQUESTS = 32
MAX_CANDIDATES = 256
MAX_CACHE_BYTES = 1024 * 1024
MAX_HISTORY = 512
MAX_TEXT_CHARS = 7000
MAX_CONTEXT_CHARS = 24000
MAX_FETCH_BYTES = 512 * 1024
MAX_PUBLIC_BYTES = 200 * 1024
PRIVATE_CACHE = "qwen-candidates-private.json"
LAST_PUBLISHED = "qwen-discovery-last-published.json"
MODEL_ID = "mlx-community/Qwen3.8-27B-4bit"
SEED_QUERIES = (
    "Serbia public proxy subscription hysteria2 vless",
    "Serbia sing-box shadowsocks public configurations",
    "Сербия публичные прокси подписки vless hysteria2",
    "Srbija besplatni proxy konfiguracije pretplata",
    "Србија јавни прокси конфигурације",
    "Serbia Trojan VMess public subscription",
    "Serbia proxy liste abonnement public",
    "public proxy subscription updated sing-box",
)
_ID = re.compile(r"[a-f0-9]{64}")
_UUID = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def validate_query(query):
    if (not isinstance(query, str) or not 1 <= len(query) <= 160 or any(ord(c) < 32 for c in query)
            or "://" in query or _UUID.search(query)):
        raise ValueError("invalid-search-query")
    return query


def privacy_url(value: str) -> str:
    """A stricter public-audit boundary than ordinary subscription fetching."""
    url = canonical_url(value)
    parts = urlsplit(url)
    path = unquote(parts.path)
    segments = path.strip("/").split("/")
    sensitive = segments
    if parts.hostname in {"github.com", "raw.githubusercontent.com"} and len(segments) >= 2:
        # Public owner/repository names are identities, not URL credentials.
        sensitive = segments[2:]
        if parts.hostname == "raw.githubusercontent.com" and sensitive and re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", sensitive[0]):
            sensitive = sensitive[1:]
    elif parts.hostname == "api.github.com" and len(segments) >= 3 and segments[0] == "repos":
        sensitive = segments[3:]
    sensitive_path = "/" + "/".join(sensitive)
    if (_UUID.search(sensitive_path) or re.search(r"(?i)(?:^|/)(?:token|secret|private|password|auth|api[_-]?key)(?:[./_-]|$)", sensitive_path)
            or any(len(item) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+", item) and any(c.isdigit() for c in item)
                   for item in sensitive)):
        raise ValueError("credential-like-source-url")
    for key, values in parse_qs(parts.query, max_num_fields=24).items():
        if key.lower() not in {"format", "type", "raw", "plain", "q", "query", "sort", "order", "per_page", "recursive"}:
            raise ValueError("nonpublic-query-parameter")
        if any(_UUID.search(item) or len(item) > 512 or re.search(r"(?i)(?:token|password|secret|auth)\s*=", item) for item in values):
            raise ValueError("credential-like-source-url")
    return url


def _clean_text(text):
    text = re.sub(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", text)
    text = re.sub(r"<[^>]{0,1000}>", " ", text)
    text = redact(text)
    text = _UUID.sub("[redacted]", text)
    return " ".join(text.split())


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []
    def handle_starttag(self, tag, attributes):
        if tag != "a":
            return
        value = dict(attributes).get("href", "")
        if "uddg=" in value:
            value = parse_qs(urlsplit(value).query).get("uddg", [""])[0]
        if value.startswith("https://"):
            self.links.append(value)


class _BoundedPool(SourcePool):
    def __init__(self, owner, path, now):
        self.owner = owner
        super().__init__([], path, now=int(now))
    def _before_request(self, url):
        self.owner._take_request()
        return super()._before_request(url)


class DiscoveryTools:
    def __init__(self, repo: Path, state_dir: Path, state=None, *, now=None,
                 max_requests=MAX_REQUESTS, max_candidates=MAX_CANDIDATES,
                 pool=None, search_provider=None, deadline=None, known_sources=None, known_candidate_ids=None):
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_REQUESTS:
            raise ValueError("invalid-request-budget")
        if type(max_candidates) is not int or not 1 <= max_candidates <= MAX_CANDIDATES:
            raise ValueError("invalid-candidate-budget")
        self.repo, self.state_dir = Path(repo), Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.clock = time.time if now is None else lambda: now
        self.deadline = time.monotonic() + 20 * 60 if deadline is None else deadline
        self.max_requests, self.max_candidates = max_requests, max_candidates
        self.requests = 0; self.successful_requests = 0; self.context_chars = 0
        self.gate = threading.BoundedSemaphore(2); self.lock = threading.RLock()
        self.state = self._state(state)
        self.candidates, self.sources, self.repo_index = {}, {}, {}
        self.errors = Counter(); self.search_provider = search_provider
        self.pool = pool or _BoundedPool(self, self.state_dir / "qwen-public-source-state.json", self.clock())
        self._pool_counts_requests = isinstance(self.pool, _BoundedPool)
        self.known_source_urls, self.known_candidate_ids = self._load_known()
        self.known_source_urls.update(privacy_url(value) for value in known_sources or [])
        self.known_candidate_ids.update(value for value in known_candidate_ids or [] if isinstance(value, str) and _ID.fullmatch(value))
        self._load_cache()

    def _load_known(self):
        """Read existing production input identities; never expose private URIs."""
        from source_catalog import load_regional_sources
        urls, _ = load_regional_sources(self.repo, now=self.clock())
        known_urls, known_ids = set(urls), set()
        import build
        for name in ("best50.txt", "qualified-all.txt"):
            path = self.repo / "output" / name
            try:
                if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
                    continue
                for link in extract_links(decode_subscription(path.read_bytes())):
                    try:
                        known_ids.add(build.normalized_fingerprint(build.parse_vless(link)))
                    except (ValueError, TypeError, KeyError, OverflowError):
                        continue
            except (OSError, ValueError):
                continue
        # Hash-only reads avoid sending managed/private configurations to the
        # model. Current regional input manifests can also identify old inputs.
        paths = {self.state_dir / LAST_PUBLISHED}
        for directory in (self.state_dir, self.state_dir.parent):
            paths.update(directory / name for name in ("regional-candidate-cache.json", "regional-input-manifest.json", "local-reliability.json"))
        for path in paths:
            try:
                if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
                    continue
                data = json.loads(path.read_text())
                if not isinstance(data, dict):
                    continue
                if path.name == LAST_PUBLISHED:
                    for row in data.get("sources", [])[:64]:
                        known_urls.add(privacy_url(row["url"]))
                    records = data.get("candidates", [])
                elif path.name == "local-reliability.json":
                    records = [{"id": key} for key in list(data)[:8000]]
                else:
                    records = data.get("entries", data.get("nodes", []))
                for row in records[:8000] if isinstance(records, list) else []:
                    value = row.get("id") if isinstance(row, dict) else None
                    if isinstance(value, str) and _ID.fullmatch(value):
                        known_ids.add(value)
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                continue
        return known_urls, known_ids

    def _state(self, state):
        clean = {"schema": 1, "queries": {}, "urls": {}, "events": []}
        if not isinstance(state, dict):
            return clean
        for field in ("queries", "urls"):
            records = state.get(field, {})
            if not isinstance(records, dict):
                continue
            for key, item in list(records.items())[-MAX_HISTORY:]:
                if (isinstance(key, str) and _ID.fullmatch(key) and isinstance(item, dict)
                        and _number(item.get("at")) and 0 <= self.clock() - item["at"] <= 30 * 86400
                        and type(item.get("count")) is int and 0 <= item["count"] <= MAX_CANDIDATES):
                    clean[field][key] = {"at": item["at"], "count": item["count"]}
        events = state.get("events", [])
        for item in events[-128:] if isinstance(events, list) else []:
            if (isinstance(item, dict) and set(item) == {"at", "action", "reason", "count"}
                    and _number(item.get("at")) and 0 <= self.clock() - item["at"] <= 30 * 86400
                    and item.get("action") in {"search", "fetch"}
                    and item.get("reason") in {"ok", "no-results-or-unavailable", "compatible-public-inputs", "no-compatible-configurations",
                                               "request-budget", "rate-limit", "source-policy-unavailable", "source-unavailable"}
                    and type(item.get("count")) is int and 0 <= item["count"] <= MAX_CANDIDATES):
                clean["events"].append(dict(item))
        return clean

    def _take_request(self):
        with self.lock:
            if self.requests >= self.max_requests or time.monotonic() >= self.deadline:
                raise SourceBudgetExhausted()
            self.requests += 1

    def _fetch(self, url):
        url = privacy_url(url)
        with self.gate:
            if not self._pool_counts_requests:
                self._take_request()
            # SourcePool's 180-second budget applies to this bounded tool call;
            # model inference time is not charged as public-network activity.
            self.pool.started = time.monotonic()
            if not self.pool.allowed(url):
                raise ValueError("source-policy")
            raw, headers = self.pool.get(url, max_bytes=MAX_FETCH_BYTES)
            if not isinstance(raw, bytes) or len(raw) > MAX_FETCH_BYTES:
                raise ValueError("source-size")
            with self.lock:
                self.successful_requests += 1
            return raw, headers

    def seed_queries(self):
        offset = int(self.clock() // 86400) % (len(SEED_QUERIES) - 1)
        return [SEED_QUERIES[offset], SEED_QUERIES[(offset + 1) % (len(SEED_QUERIES) - 1)], SEED_QUERIES[-1]]

    def _event(self, action, reason, count=0):
        self.state["events"].append({"at": self.clock(), "action": action, "reason": reason, "count": count})
        self.state["events"] = self.state["events"][-128:]

    def _search(self, query):
        key = hashlib.sha256(("qwen-search-v2:" + query).encode()).hexdigest()
        previous = self.state["queries"].get(key)
        if previous and self.clock() - previous["at"] < (86400 if previous["count"] == 0 else 12 * 3600):
            return {"status": "cooldown", "results": []}
        rows = []
        if self.search_provider is not None:
            rows = self.search_provider(query)
        else:
            since = datetime.fromtimestamp(self.clock() - 60 * 86400, timezone.utc).strftime("%Y-%m-%d")
            # GitHub otherwise searches names/descriptions/topics only. Public
            # subscription aggregators often mention Serbia only in their README.
            # A natural-language web query becomes an AND query in repository
            # search. Long country/protocol sentences returned zero useful
            # results in live runs. Broaden only after a successful empty result;
            # broad aggregators can contain RS entries outside their README.
            variants = [query]
            if re.search(r"(?i)serbia|srbija|серби|срби|belgrade|beograd", query):
                variants.append("Serbia vless")
            variants.append("hysteria2" if "hysteria" in query.lower() else "vless subscription")
            for terms in list(dict.fromkeys(variants))[:3]:
                url = "https://api.github.com/search/repositories?" + urlencode({"q": terms + " in:name,description,readme pushed:>" + since + " archived:false fork:false", "sort": "updated", "order": "desc", "per_page": "8"})
                try:
                    raw, _ = self._fetch(url)
                    payload = json.loads(raw)
                    for item in payload.get("items", [])[:8]:
                        name = item.get("full_name", "")
                        if item.get("private") is not False or item.get("disabled") or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
                            continue
                        rows.append({"url": "https://github.com/" + name,
                                     "description": _clean_text(str(item.get("description") or ""))[:300], "channel": "github"})
                    if rows:
                        break
                except (ValueError, KeyError, TypeError, OSError, RuntimeError):
                    self.errors["github-search-unavailable"] += 1
                    break  # Never evade an outage/rate limit with another query.
            # Legitimate public web search is optional: policy denial, challenge
            # or provider outage is explicit; GitHub and public links still work.
            try:
                raw, _ = self._fetch("https://html.duckduckgo.com/html/?" + urlencode({"q": query}))
                parser = _Links(); parser.feed(raw.decode("utf-8", "replace")); parser.close()
                for url in parser.links[:30]:
                    if urlsplit(url).hostname not in {"duckduckgo.com", "html.duckduckgo.com"}:
                        rows.append({"url": url, "channel": "web"})
            except (ValueError, OSError, RuntimeError):
                self.errors["web-search-unavailable"] += 1
        results = []
        for row in rows[:64] if isinstance(rows, list) else []:
            try:
                url = privacy_url(row["url"])
                if any(value["url"] == url for value in results):
                    continue
                results.append({"url": url, "description": _clean_text(str(row.get("description", "")))[:300],
                                "channel": "github" if row.get("channel") == "github" else "web",
                                "known_source": url in self.known_source_urls})
            except (ValueError, TypeError, KeyError):
                continue
            if len(results) == 12:
                break
        self.state["queries"][key] = {"at": self.clock(), "count": len(results)}
        results.sort(key=lambda row: row["known_source"])
        self._event("search", "ok" if results else "no-results-or-unavailable", len(results))
        return {"status": "ok" if results else "no-results-or-unavailable", "results": results,
                "search_failures": dict(self.errors)}

    def _repository(self, url):
        parts = urlsplit(url).path.strip("/").split("/")
        if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
            return None
        repository = "/".join(parts)
        raw, _ = self._fetch("https://api.github.com/repos/" + repository)
        meta = json.loads(raw)
        branch = meta.get("default_branch")
        if meta.get("private") is not False or meta.get("disabled") or not isinstance(branch, str) or not 0 < len(branch) <= 100:
            raise ValueError("nonpublic-repository")
        raw, _ = self._fetch("https://api.github.com/repos/" + repository + "/git/trees/" + quote(branch, safe="") + "?recursive=1")
        tree = json.loads(raw).get("tree", [])
        found = []
        for row in tree[:10000] if isinstance(tree, list) else []:
            path, size = row.get("path", ""), row.get("size", 0)
            if (row.get("type") != "blob" or type(size) is not int or not 0 <= size <= MAX_FETCH_BYTES
                    or not isinstance(path, str) or not 0 < len(path) <= 300):
                continue
            if path.lower().endswith((".txt", ".sub", ".list")) or path.lower() in {"readme.md", "readme.txt"}:
                try:
                    found.append(privacy_url("https://raw.githubusercontent.com/" + repository + "/" + quote(branch, safe="") + "/" + quote(path, safe="/")))
                except ValueError:
                    continue
        return {"status": "repository-index", "url": url, "links": sorted(set(found))[:24],
                "candidate_count": 0, "notice": "Published files are untrusted discovery inputs, not working-server claims."}

    def _page(self, url):
        key = hashlib.sha256(url.encode()).hexdigest()
        previous = self.state["urls"].get(key)
        if previous and self.clock() - previous["at"] < (3 * 86400 if previous["count"] == 0 else 6 * 3600):
            return {"status": "cooldown", "candidate_count": previous["count"]}
        if urlsplit(url).hostname == "github.com":
            repository = self._repository(url)
            if repository is not None:
                return repository
        raw, _ = self._fetch(url)
        text = decode_subscription(raw)
        import build
        extracted, protocols = [], Counter()
        for link in extract_links(text):
            try:
                node = build.parse_vless(link)
                identity = build.normalized_fingerprint(node)
                if identity in {value["id"] for value in extracted}:
                    continue
                extracted.append({"id": identity, "link": link, "protocol": node["protocol"]})
                protocols[node["protocol"]] += 1
            except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
                continue
            if len(extracted) == self.max_candidates:
                break
        fetched_at = self.clock(); digest = hashlib.sha256(raw).hexdigest()
        hint = bool(re.search(r"(?i)serbia|сербия|србија|srbija|🇷🇸", url + " " + text[:MAX_TEXT_CHARS]))
        if extracted:
            self.sources[url] = {"url": url, "evidence_url": url, "fetched_at": fetched_at, "body_sha256": digest,
                                 "candidate_count": len(extracted), "serbia_hint_unverified": hint}
            for row in extracted:
                if row["id"] not in self.candidates and len(self.candidates) >= self.max_candidates:
                    oldest = min(self.candidates, key=lambda key: (self.candidates[key]["observed_at"], key))
                    del self.candidates[oldest]
                existing = self.candidates.get(row["id"])
                self.candidates[row["id"]] = {**row, "source_url": url,
                    "first_seen": existing["first_seen"] if existing else fetched_at, "observed_at": fetched_at,
                    "source_body_sha256": digest, "unverified": True, "serbia_hint_unverified": hint}
        urls = []
        for candidate in feed_urls(text):
            try:
                value = privacy_url(candidate)
                if value != url and value not in urls:
                    urls.append(value)
            except ValueError:
                continue
        remaining = max(0, min(MAX_TEXT_CHARS, MAX_CONTEXT_CHARS - self.context_chars))
        snippet = _clean_text(text)[:remaining]; self.context_chars += len(snippet)
        self.state["urls"][key] = {"at": fetched_at, "count": len(extracted)}
        self._event("fetch", "compatible-public-inputs" if extracted else "no-compatible-configurations", len(extracted))
        self.save_private_cache()
        return {"status": "ok", "url": url, "body_sha256": digest, "candidate_count": len(extracted),
                "protocols": dict(protocols), "serbia_hint_unverified": hint, "links": urls[:16],
                "known_source": url in self.known_source_urls,
                "new_candidate_count": sum(row["id"] not in self.known_candidate_ids for row in extracted),
                "text": snippet, "notice": "Untrusted public text. No candidate has passed VPN/service/country validation."}

    def execute(self, action):
        if not isinstance(action, dict) or not isinstance(action.get("action"), str):
            raise ValueError("invalid-tool-action")
        name = action["action"]
        if name == "finish" and set(action) == {"action"}:
            metadata = self.public_metadata()
            return {"finished": True, "source_count": len(metadata["sources"]),
                    "candidate_count": len(metadata["candidates"]),
                    "cached_candidates": len(self.candidates)}
        if name == "search" and set(action) == {"action", "query"}:
            return self._search(validate_query(action["query"]))
        if name == "fetch" and set(action) == {"action", "url"}:
            url = privacy_url(action["url"])
            try:
                return self._page(url)
            except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
                reason = ("request-budget" if isinstance(error, SourceBudgetExhausted) else
                          "rate-limit" if isinstance(error, RateLimited) else
                          "source-policy-unavailable" if isinstance(error, SourcePolicyUnavailable) else "source-unavailable")
                self.errors[reason] += 1; self._event("fetch", reason)
                return {"status": reason, "candidate_count": 0}
        raise ValueError("unsupported-tool-action")

    def proposal(self):
        rows = sorted(self.public_metadata()["sources"], key=lambda item: (not item["serbia_hint_unverified"], item["url"]))[:32]
        return {"schema": 1, "sources": [{"url": item["url"], "evidence_url": item["evidence_url"]} for item in rows]}

    def public_metadata(self):
        candidates = [item for _, item in sorted(self.candidates.items())
                      if item["source_url"] in self.sources and item["id"] not in self.known_candidate_ids
                      and item["source_body_sha256"] == self.sources[item["source_url"]]["body_sha256"]]
        candidate_sources = {item["source_url"] for item in candidates}
        result = {"schema": 1, "worker": "qwen", "model": MODEL_ID, "generated_at": self.clock(),
                  "unverified_inputs": True, "sources": sorted([item for item in self.sources.values()
                      if item["url"] not in self.known_source_urls or item["url"] in candidate_sources], key=lambda item: item["url"]),
                  "candidates": [{key: item[key] for key in ("id", "protocol", "source_url", "observed_at", "source_body_sha256", "serbia_hint_unverified")}
                                 for item in candidates]}
        if len(json.dumps(result).encode()) > MAX_PUBLIC_BYTES:
            raise ValueError("public-metadata-size")
        return result

    def snapshot(self):
        result = self._state(self.state)
        result["events"] = self.state["events"][-128:]
        for key in ("queries", "urls"):
            result[key] = dict(sorted(result[key].items(), key=lambda pair: pair[1]["at"], reverse=True)[:MAX_HISTORY])
        return result

    def coverage(self):
        return {"requests": self.requests, "successful_requests": self.successful_requests,
                "fetched_source_count": len(self.sources), "cached_candidate_count": len(self.candidates),
                "search_failures": dict(self.errors)}

    def _load_cache(self):
        path = self.state_dir / PRIVATE_CACHE
        try:
            if path.is_symlink() or path.stat().st_size > MAX_CACHE_BYTES or path.stat().st_mode & 0o077:
                return
            data = json.loads(path.read_text())
            if not isinstance(data, dict) or data.get("schema") != 1:
                return
            import build
            for row in data.get("candidates", [])[:self.max_candidates]:
                if not isinstance(row, dict) or not _number(row.get("observed_at")) or not 0 <= self.clock() - row["observed_at"] <= 7 * 86400:
                    continue
                node = build.parse_vless(row["link"])
                if build.normalized_fingerprint(node) != row["id"] or not _ID.fullmatch(row.get("source_body_sha256", "")):
                    continue
                first = row.get("first_seen")
                if not _number(first) or not 0 < first <= row["observed_at"]:
                    first = row["observed_at"]
                self.candidates[row["id"]] = {"id": row["id"], "link": row["link"], "protocol": node["protocol"],
                    "source_url": privacy_url(row["source_url"]), "first_seen": first, "observed_at": row["observed_at"],
                    "source_body_sha256": row["source_body_sha256"], "unverified": True,
                    "serbia_hint_unverified": row.get("serbia_hint_unverified") is True}
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return

    def save_private_cache(self):
        path = self.state_dir / PRIVATE_CACHE
        if path.is_symlink():
            raise ValueError("private-cache-symlink")
        records = sorted(self.candidates.values(), key=lambda item: (-item["observed_at"], item["id"]))[:self.max_candidates]
        value = {"schema": 1, "unverified_inputs": True, "candidates": records}
        if len(json.dumps(value).encode()) > MAX_CACHE_BYTES:
            raise ValueError("private-cache-size")
        atomic_json(path, value)
        os.chmod(path, 0o600)
