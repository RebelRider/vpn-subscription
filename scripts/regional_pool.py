"""Independent, private regional exploration inputs for the strict local validator.

These inputs are UNVERIFIED. Neither discovery nor a manifest grants publication:
the caller must still require current, complete service and latency evidence.
Managed credentials never enter source discovery state or public diagnostics.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from urllib.parse import unquote
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

try:
    from .source_discovery import SourcePool
    from .source_catalog import load_regional_sources
    from .protocols import connection_identity
except ImportError:
    from source_discovery import SourcePool
    from source_catalog import load_regional_sources
    from protocols import connection_identity


MAX_BYTES = 4 * 1024 * 1024
MAX_MANAGED = 50
MAX_EXPLORATION = 50
MAX_MANIFEST_NODES = 150
MAX_PROVENANCE = 8000
MAX_SOURCE_IDS = 8
MAX_AGE = 6 * 3600
MAX_HISTORY_AGE = 28 * 86400
MAX_BROWSER_RETRIES = 128
BROWSER_RETRY_QUOTA = 8
BROWSER_RETRY_LIFETIME = 24 * 3600
BROWSER_RETRY_BASE = 15 * 60
BROWSER_RETRY_MAX = 2 * 3600
BROWSER_DEFERRED_REASONS = frozenset({"browser-queue-deferred-inconclusive", "browser-busy-inconclusive",
                                     "browser-queue-or-runtime-deadline-inconclusive", "browser-deadline"})
ID = re.compile(r"[0-9a-f]{64}")
SOURCE_ID = re.compile(r"[0-9a-f]{24}")
MANIFEST_NAME = "regional-input-manifest.json"
HISTORY_NAME = "regional-pool-state.json"
DISCOVERY_NAME = "regional-discovery-state.json"
CANDIDATE_CACHE_NAME = "regional-candidate-cache.json"
MAX_CACHED_CANDIDATES = 2000
MAX_CANDIDATE_CACHE_BYTES = 2 * 1024 * 1024
MAX_CANDIDATE_CACHE_AGE = 24 * 3600


def _number(value, maximum=10 ** 12):
    return ((type(value) is int and 0 <= value <= maximum)
            or (type(value) is float and math.isfinite(value) and 0 <= value <= maximum))


def _source_ids(values):
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return sorted({value for value in values if isinstance(value, str) and SOURCE_ID.fullmatch(value)})[:MAX_SOURCE_IDS]


def _browser_retry(value, now):
    if not isinstance(value, dict) or set(value) != {"first_at", "after", "attempts"}:
        return None
    first, after, attempts = value["first_at"], value["after"], value["attempts"]
    if (not _number(first) or not now - BROWSER_RETRY_LIFETIME <= first <= now + 300
            or not _number(after) or not first <= after <= now + BROWSER_RETRY_MAX + 300
            or type(attempts) is not int or not 1 <= attempts <= 8):
        return None
    return {"first_at": first, "after": after, "attempts": attempts}


def _bound_browser_retries(candidates):
    pending = sorted((key for key, value in candidates.items() if "browser_retry" in value),
                     key=lambda key: (candidates[key]["browser_retry"]["first_at"],
                                      candidates[key].get("last_tested", 0), key))
    for key in pending[MAX_BROWSER_RETRIES:]:
        candidates[key].pop("browser_retry", None)


def _deferred_browser_result(result):
    browser = result.get("browser_check", {})
    if (not isinstance(browser, dict) or not isinstance(browser.get("reason"), str)
            or browser["reason"] not in BROWSER_DEFERRED_REASONS
            or any(type(browser.get(field)) is int and 100 <= browser[field] <= 599
                   for field in ("http_status", "first_failed_http_status"))):
        return False
    services = result.get("services", {})
    if not isinstance(services, dict):
        return False
    for name in ("youtube", "instagram"):
        service = services.get(name, {})
        if (not isinstance(service, dict) or type(service.get("attempts")) is not int
                or not 1 <= service["attempts"] <= 5 or type(service.get("passed")) is not int
                or service["passed"] != service["attempts"]):
            return False
    samples = result.get("latency_samples_ms", [])
    return isinstance(samples, list) and 1 <= len(samples) <= 5 and all(_number(value) for value in samples)


def _state_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("Regional state directory must be owned by this user")
    os.chmod(path, 0o700)
    return path


def _private_bytes(path: Path, *, required=False, maximum=MAX_BYTES) -> bytes | None:
    """Open without following symlinks; verify the actual open file's ownership."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        if required:
            raise ValueError("Required private input is missing") from None
        return None
    except OSError:
        raise ValueError("Private input cannot be safely opened") from None
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise ValueError("Private input must be a bounded user-owned mode-600 file")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Private input exceeds size limit")
    return raw


def _write_private(path: Path, value) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("Regional state exceeds size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".regional-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return raw


class PrivateSourcePool(SourcePool):
    def __init__(self, seeds, state_path, now=None):
        _private_bytes(Path(state_path))
        super().__init__(seeds, state_path, now=now)

    def save(self):
        # SourcePool's atomic writer uses a predictable .tmp sibling. Reserve it
        # privately before each write; it contains source metadata, never URIs.
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix(".tmp")
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except FileExistsError:
            _private_bytes(temporary, required=True)
        if self.path.exists():
            _private_bytes(self.path, required=True)
        super().save()
        os.chmod(self.path, 0o600)


def _load_history(state_dir: Path, now):
    try:
        raw = _private_bytes(state_dir / HISTORY_NAME)
        data = json.loads(raw) if raw else {}
    except (ValueError, UnicodeError, RecursionError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    clean = {"schema": 1, "cursor": 0, "candidates": {}, "sources": {}}
    if type(data.get("cursor")) is int and 0 <= data["cursor"] <= 10 ** 12:
        clean["cursor"] = data["cursor"]
    for kind, expression, maximum in (("candidates", ID, MAX_PROVENANCE), ("sources", SOURCE_ID, 160)):
        records = data.get(kind, {})
        if not isinstance(records, dict):
            continue
        for key, value in list(records.items())[:maximum]:
            if not isinstance(key, str) or not expression.fullmatch(key) or not isinstance(value, dict):
                continue
            stamp = value.get("last_seen", 0)
            if not _number(stamp) or stamp > now + 300 or stamp < now - MAX_HISTORY_AGE:
                continue
            item = {"last_seen": stamp}
            if kind == "candidates":
                source_ids = value.get("source_ids", [])
                item["source_ids"] = _source_ids(source_ids)
                outcome = value.get("last_outcome")
                item["last_outcome"] = outcome if isinstance(outcome, str) and outcome in {"qualified", "definitive-failure", "inconclusive"} else "inconclusive"
                tested = value.get("last_tested", 0)
                item["last_tested"] = tested if _number(tested) and tested <= now + 300 else 0
                country = value.get("last_exit_country")
                if isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country):
                    item["last_exit_country"] = country
                retry = _browser_retry(value.get("browser_retry"), now)
                if retry is not None:
                    item["browser_retry"] = retry
            else:
                for name in ("qualified", "definitive_failure", "inconclusive"):
                    count = value.get(name, 0)
                    item[name] = count if type(count) is int and 0 <= count <= 1_000_000 else 0
                ema = value.get("local_ema", 0)
                item["local_ema"] = float(ema) if _number(ema, 1) else 0.0
            clean[kind][key] = item
    _bound_browser_retries(clean["candidates"])
    return clean


def _candidate(build, link, source_ids=(), origin="regional-exploration", public=True):
    try:
        if not isinstance(link, str) or len(link) > 16384:
            return None
        node = build.parse_vless(link)
        identifier = build.normalized_fingerprint(node)
        if not isinstance(identifier, str) or not ID.fullmatch(identifier):
            return None
        return {"id": identifier, "link": link, "protocol": node["protocol"],
                "source_ids": _source_ids(source_ids),
                "origin": origin, "public_publish_allowed": bool(public), "_node": node}
    except (ValueError, KeyError, TypeError, OverflowError, UnicodeError, RecursionError):
        return None


def _serbia_hint(candidate, history):
    """A bounded exploration preference, never country or functional proof."""
    if history["candidates"].get(candidate["id"], {}).get("last_exit_country") == "RS":
        return True
    remark = unquote(candidate["link"].rsplit("#", 1)[-1]) if "#" in candidate["link"] else ""
    return "🇷🇸" in remark or bool(re.search(
        r"(?i)(?<![A-Za-z])(?:RS|Serbia|Srbija|Belgrade|Beograd|Сербия|Србија)(?![A-Za-z])", remark))


def _load_candidate_cache(build, state_dir, now, private_connections):
    """Recover only discovery inputs; no cached service result is accepted."""
    try:
        raw = _private_bytes(state_dir / CANDIDATE_CACHE_NAME, maximum=MAX_CANDIDATE_CACHE_BYTES)
        if raw is None:
            return {}, "missing"
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"schema", "unverified_inputs", "entries"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or data["unverified_inputs"] is not True or not isinstance(data["entries"], list)
                or len(data["entries"]) > MAX_CACHED_CANDIDATES):
            raise ValueError
        result = {}
        for entry in data["entries"]:
            if (not isinstance(entry, dict) or set(entry) != {
                    "id", "link", "protocol", "source_ids", "observed_at", "public_publish_allowed"}
                    or entry["public_publish_allowed"] is not True or not _number(entry["observed_at"])
                    or not now - MAX_CANDIDATE_CACHE_AGE <= entry["observed_at"] <= now + 60
                    or not isinstance(entry["source_ids"], list)
                    or _source_ids(entry["source_ids"]) != entry["source_ids"]):
                continue
            candidate = _candidate(build, entry["link"], entry["source_ids"])
            if (candidate is None or candidate["id"] != entry["id"] or candidate["protocol"] != entry["protocol"]
                    or connection_identity(build, candidate["link"]) in private_connections):
                continue
            candidate["_observed_at"] = entry["observed_at"]
            old = result.get(candidate["id"])
            if old is None or old["_observed_at"] < candidate["_observed_at"]:
                result[candidate["id"]] = candidate
        return result, "available" if result else "empty-or-expired"
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {}, "invalid-or-unavailable"


def _main_manifest_candidates(build, state_dir, now, private_connections):
    """Seed a new RS pool from fresh PUBLIC main inputs, never its PASS results."""
    path = state_dir.parent / MANIFEST_NAME
    try:
        raw = _private_bytes(path)
        if raw is None:
            return {}
        manifest = json.loads(raw)
        stamp = manifest.get("generated_at") if isinstance(manifest, dict) else None
        entries = manifest.get("nodes") if isinstance(manifest, dict) else None
        if (not _number(stamp) or not now - MAX_AGE <= stamp <= now + 60
                or not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MANIFEST_NODES):
            return {}
        eligible = [entry for entry in entries if isinstance(entry, dict)
                    and entry.get("public_publish_allowed") is True and entry.get("origin") != "managed"]
        # This verifies the original frozen manifest and its live managed-policy
        # digest, including equivalent private aliases, before copying inputs.
        validate_manifest_membership(build, eligible, path, expected_digest=hashlib.sha256(raw).hexdigest(), now=now)
        result = {}
        for entry in eligible:
            candidate = _candidate(build, entry.get("link"), entry.get("source_ids", []))
            if candidate is None or connection_identity(build, candidate["link"]) in private_connections:
                continue
            observed = entry.get("input_observed_at", stamp)
            if not _number(observed) or not now - MAX_CANDIDATE_CACHE_AGE <= observed <= stamp + 60:
                continue
            # A new manifest around replayed inputs must not renew discovery age.
            candidate["_observed_at"] = observed
            result[candidate["id"]] = candidate
        return result
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {}


def _cache_order(candidates, history):
    """Reserve RS hints, then rotate protocols and endpoint networks in O(n log n)."""
    def diverse(values):
        buckets = defaultdict(lambda: defaultdict(list))
        for candidate in sorted(values, key=lambda value: (
                -value["_observed_at"],
                -max((history["sources"].get(key, {}).get("local_ema", 0)
                      for key in value["source_ids"]), default=0), value["id"])):
            buckets[candidate["protocol"]][_endpoint(candidate["_node"])].append(candidate)
        protocols = deque(deque(deque(group) for group in endpoints.values())
                          for _, endpoints in sorted(buckets.items()))
        while protocols:
            endpoints = protocols.popleft()
            group = endpoints.popleft()
            yield group.popleft()
            if group:
                endpoints.append(group)
            if endpoints:
                protocols.append(endpoints)
    preferred = list(diverse([value for value in candidates.values() if _serbia_hint(value, history)]))[:MAX_CACHED_CANDIDATES // 4]
    ids = {value["id"] for value in preferred}
    yield from preferred
    yield from diverse([value for key, value in candidates.items() if key not in ids])


def _save_candidate_cache(state_dir, candidates, history):
    records, size = [], 128
    for candidate in _cache_order(candidates, history):
        record = {key: candidate[key] for key in ("id", "link", "protocol", "source_ids")}
        record.update(observed_at=candidate["_observed_at"], public_publish_allowed=True)
        record_size = len(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) + 1
        if size + record_size > MAX_CANDIDATE_CACHE_BYTES:
            continue
        records.append(record)
        size += record_size
        if len(records) >= MAX_CACHED_CANDIDATES:
            break
    # The existing atomic writer creates a private mode-600 file and never
    # follows a destination symlink. The serialized cache has its tighter cap.
    raw = _write_private(state_dir / CANDIDATE_CACHE_NAME,
                         {"schema": 1, "unverified_inputs": True, "entries": records})
    if len(raw) > MAX_CANDIDATE_CACHE_BYTES:
        raise ValueError("Regional candidate cache exceeds its size limit")
    return len(records)


def _managed(build, state_dir):
    raw = _private_bytes(state_dir / "managed-pool.json")
    if raw is None:
        return [], None
    try:
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"schema", "servers"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or not isinstance(data["servers"], list) or len(data["servers"]) > MAX_MANAGED):
            raise ValueError
        result = []
        for value in data["servers"]:
            if (not isinstance(value, dict) or set(value) - {"uri", "publish_public"}
                    or "uri" not in value or type(value.get("publish_public", False)) is not bool):
                raise ValueError
            candidate = _candidate(build, value["uri"], origin="managed", public=value.get("publish_public", False))
            if candidate is None:
                raise ValueError
            result.append(candidate)
        return result, hashlib.sha256(raw).hexdigest()
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        # Do not include parser errors: they can contain private connection data.
        raise ValueError("Managed pool contains an invalid or incompatible entry") from None


def _endpoint(node):
    try:
        address = ipaddress.ip_address(node["server"])
        return str(ipaddress.ip_network(f"{address}/{'24' if address.version == 4 else '48'}", strict=False))
    except ValueError:
        return ".".join(node["server"].lower().split(".")[-2:])


def _published_rechecks(build, preferred_country=None):
    """Read only public previously published strict inputs, never cached passes."""
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=build.ROOT,
            stderr=subprocess.DEVNULL, timeout=5)
    def blob(commit, path):
        oid = git("rev-parse", "--verify", f"{commit}:{path}").strip().decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise ValueError
        size = int(git("cat-file", "-s", oid))
        if not 0 <= size <= MAX_BYTES:
            raise ValueError
        raw = git("cat-file", "blob", oid)
        if len(raw) != size:
            raise ValueError
        return raw
    try:
        commit = git("rev-parse", "--verify", "refs/remotes/origin/regional").strip().decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            return []
        status_path = "output/local-status-Serbia.json" if preferred_country == "RS" else "output/local-status.json"
        subscription_path = "output/best-local-Serbia.txt" if preferred_country == "RS" else "output/best-local.txt"
        algorithm = "serbia-strict-services-v1" if preferred_country == "RS" else "bestlocal-strict-services-v6"
        status = json.loads(blob(commit, status_path))
        nodes = status.get("nodes") if isinstance(status, dict) else None
        retained = status.get("retained_nodes", []) if isinstance(status, dict) else None
        if (not isinstance(status, dict) or status.get("algorithm") != algorithm
                or not isinstance(nodes, list) or not 1 <= len(nodes) <= 12
                or not isinstance(retained, list) or len(retained) > 2):
            return []
        nodes = nodes + retained
        published = {}
        for line in blob(commit, subscription_path).decode().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            candidate = _candidate(build, line.strip(), origin="local-recheck")
            if candidate is not None:
                published[candidate["id"]] = candidate
        result = []
        for value in nodes:
            candidate = _candidate(build, value.get("link"), origin="local-recheck") if isinstance(value, dict) else None
            if candidate is None:
                continue
            published_id = candidate["id"]
            if value.get("tested_server_ip"):
                try:
                    from protocols import pin_transport_address
                    pinned = pin_transport_address(build, value["link"], value["tested_server_ip"])
                    published_id = build.normalized_fingerprint(build.parse_vless(pinned))
                except (ValueError, TypeError, KeyError):
                    continue
            if published_id in published:
                # Retest the original source identity, while matching the exact
                # pinned transport that was rendered in the published artifact.
                result.append(candidate)
        return result
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, subprocess.SubprocessError):
        return []


def _select(candidates, history, count):
    ordered = sorted(candidates, key=lambda value: value["id"])
    if not ordered or not count:
        return []
    offset = history["cursor"] % len(ordered)
    ordered = ordered[offset:] + ordered[:offset]
    order = {value["id"]: index for index, value in enumerate(ordered)}
    protocols, sources, endpoints = Counter(), Counter(), Counter()
    selected = []
    while ordered and len(selected) < count:
        def priority(value):
            past = history["candidates"].get(value["id"], {})
            source_ids = value["source_ids"]
            reputation = max((history["sources"].get(key, {}).get("local_ema", 0) for key in source_ids), default=0)
            return (past.get("last_tested", 0),
                    protocols[value["protocol"]] + endpoints[_endpoint(value["_node"])],
                    min((sources[key] for key in source_ids), default=0),
                    -reputation, order[value["id"]])
        chosen = min(ordered, key=priority)
        ordered.remove(chosen)
        selected.append(chosen)
        protocols[chosen["protocol"]] += 1
        endpoints[_endpoint(chosen["_node"])] += 1
        sources.update(chosen["source_ids"])
    history["cursor"] = (history["cursor"] + len(selected)) % max(1, len(candidates))
    return selected


def collect_regional(build, best50_links, state_dir, now=None, limit=50, *, best50_sha=None, preferred_country=None):
    """Return Best50, managed entries and a rotating independent public tranche.

    Synchronous bounded collection belongs in asyncio.to_thread at the caller.
    `manifest_digest` must be captured in the completed validation status and
    supplied to validate_manifest_membership before public publication.
    """
    if preferred_country not in (None, "RS"):
        raise ValueError("Unsupported regional exploration preference")
    now = time.time() if now is None else now
    if not _number(now) or type(limit) is not int or not 0 <= limit <= MAX_EXPLORATION:
        raise ValueError("Invalid regional collection limits")
    if not isinstance(best50_links, list) or not 1 <= len(best50_links) <= 50:
        raise ValueError("Best50 input must contain 1..50 entries")
    state_dir = _state_directory(state_dir)
    history = _load_history(state_dir, now)
    selected, by_id = [], {}
    for link in best50_links:
        candidate = _candidate(build, link, origin="best50")
        if candidate is None:
            raise ValueError("Best50 input contains an invalid configuration")
        if candidate["id"] not in by_id:
            selected.append(candidate)
            by_id[candidate["id"]] = candidate
    managed, managed_digest = _managed(build, state_dir)
    private_connections = {connection_identity(build, node["link"]) for node in managed if not node["public_publish_allowed"]}
    for candidate in managed:
        if candidate["id"] not in by_id:
            selected.append(candidate)
            by_id[candidate["id"]] = candidate
        elif not candidate["public_publish_allowed"]:
            # An explicit private designation wins even when the same endpoint
            # credentials happen to exist in a public feed or another entry.
            by_id[candidate["id"]]["public_publish_allowed"] = False
    recheck_count = 0
    recheck_order = {}
    for candidate in (_published_rechecks(build) if preferred_country is None else _published_rechecks(build, preferred_country)):
        recheck_order.setdefault(candidate["id"], len(recheck_order))
        if recheck_count >= min(14, limit):
            break
        if candidate["id"] not in by_id:
            selected.append(candidate)
            by_id[candidate["id"]] = candidate
            recheck_count += 1
    pool = None
    catalog_status = {"status": "unavailable"}
    try:
        pool = PrivateSourcePool(build.CFG.get("sources", []), state_dir / DISCOVERY_NAME, now=now)
        if preferred_country == "RS":
            pool.discovery_queries = ["Serbia proxy subscription", "Serbia hysteria2", "Serbia shadowsocks",
                                      "RS sing-box", "Serbia v2ray", "proxy subscription"]
        catalog_urls, catalog_status = load_regional_sources(build.ROOT, now=now)
        for url in catalog_urls:
            pool.add(url, origin="source-catalog")
        for key, record in history["sources"].items():
            if key in pool.sources:
                pool.sources[key]["functional_ema"] = record.get("local_ema", 0)
        links, source_stats = pool.collect()
        discovery_stats = dict(pool.stats)
    except (OSError, ValueError, RuntimeError, TimeoutError):
        # Discovery is supplemental: a temporary source failure cannot prevent
        # testing the preserved Best50 or explicitly configured managed pool.
        links, source_stats = [], {}
        discovery_stats = {**(pool.stats if pool is not None else {}),
                           "collection_error": "regional-discovery-unavailable"}
    candidates = {}
    fresh_cache = {}
    invalid = 0
    for link in links:
        candidate = _candidate(build, link, pool.link_sources.get(link, ()))
        if candidate is None:
            invalid += 1
            continue
        identifier = candidate["id"]
        candidate["_observed_at"] = now
        if connection_identity(build, candidate["link"]) not in private_connections:
            cached = {**candidate, "_observed_at": now}
            if identifier in fresh_cache:
                cached["source_ids"] = _source_ids(set(cached["source_ids"]) | set(fresh_cache[identifier]["source_ids"]))
            fresh_cache[identifier] = cached
        previous = history["candidates"].get(identifier, {})
        source_ids = _source_ids(set(candidate["source_ids"]) | set(previous.get("source_ids", [])))
        history["candidates"][identifier] = {**previous, "last_seen": now, "source_ids": source_ids,
                                               "last_tested": previous.get("last_tested", 0)}
        if identifier in by_id:
            by_id[identifier]["source_ids"] = _source_ids(set(by_id[identifier]["source_ids"]) | set(source_ids))
            by_id[identifier]["_observed_at"] = now
            continue
        if identifier in candidates:
            candidates[identifier]["source_ids"] = _source_ids(set(candidates[identifier]["source_ids"]) | set(source_ids))
        else:
            candidate["source_ids"] = source_ids
            candidates[identifier] = candidate
    cached, cache_status = _load_candidate_cache(build, state_dir, now, private_connections)
    partial_discovery = (not fresh_cache or bool(discovery_stats.get("collection_error"))
                         or bool(discovery_stats.get("budget_exhausted"))
                         or bool(discovery_stats.get("source_failures"))
                         or bool(discovery_stats.get("deferred_sources")))
    fallback_count = 0
    if preferred_country == "RS" and not cached and partial_discovery:
        cached = _main_manifest_candidates(build, state_dir, now, private_connections)
        fallback_count = len(cached)
    replayed = {}
    if partial_discovery:
        for identifier, candidate in cached.items():
            if identifier in candidates or identifier in by_id:
                continue
            candidates[identifier] = candidate
            replayed[identifier] = candidate["_observed_at"]
            previous = history["candidates"].get(identifier, {})
            source_ids = _source_ids(set(candidate["source_ids"]) | set(previous.get("source_ids", [])))
            candidate["source_ids"] = source_ids
            history["candidates"][identifier] = {**previous, "last_seen": max(previous.get("last_seen", 0), candidate["_observed_at"]),
                                                   "source_ids": source_ids, "last_tested": previous.get("last_tested", 0)}
    merged_cache = dict(cached)
    for identifier, candidate in fresh_cache.items():
        previous = merged_cache.get(identifier)
        if previous is not None:
            candidate["source_ids"] = _source_ids(set(candidate["source_ids"]) | set(previous["source_ids"]))
        merged_cache[identifier] = candidate
    try:
        stored_cache_count = _save_candidate_cache(state_dir, merged_cache, history)
        cache_persistence = "saved"
    except (OSError, ValueError):
        stored_cache_count, cache_persistence = 0, "unavailable"
    # Queue contention is validator uncertainty, not evidence of a dead server.
    # Give due promising candidates a small tranche without displacing normal
    # exploration. A retry hint never supplies cached functional proof.
    pending = {key: value["browser_retry"] for key, value in history["candidates"].items() if "browser_retry" in value}
    def retry_order(candidate):
        past = history["candidates"].get(candidate["id"], {})
        return (past.get("last_tested", 0), past["browser_retry"]["first_at"], candidate["id"])
    due = sorted((value for key, value in candidates.items() if key in pending and pending[key]["after"] <= now), key=retry_order)
    normal_reserve = max(0, limit - BROWSER_RETRY_QUOTA - 2)
    quota = min(BROWSER_RETRY_QUOTA, max(0, limit - recheck_count - normal_reserve))
    retry_selected = due[:quota]
    selected.extend(retry_selected)
    normal = [value for key, value in candidates.items() if key not in pending]
    remaining = max(0, limit - recheck_count - len(retry_selected))
    if preferred_country == "RS" and remaining:
        # Source labels are search hints only. Reserve at least one quarter for
        # broad rotating exploration to find unlabeled/mislabelled Serbian exits.
        def hinted(value):
            return _serbia_hint(value, history)
        preferred = _select([value for value in normal if hinted(value)], history, remaining - max(1, remaining // 4))
        selected.extend(preferred)
        broad = _select([value for value in normal if not hinted(value)], history, remaining - len(preferred))
        selected.extend(broad)
        picked_ids = {value["id"] for value in preferred + broad}
        selected.extend(_select([value for value in normal if value["id"] not in picked_ids], history,
                                remaining - len(preferred) - len(broad)))
    else:
        selected.extend(_select(normal, history, remaining))
    due_selected = sorted((value for value in selected if value["id"] in pending and pending[value["id"]]["after"] <= now), key=retry_order)
    retry_positions = {value["id"]: index for index, value in enumerate(due_selected)}
    # Admission uses this list's actual order; merely recording a priority in
    # the manifest would still leave retained nodes behind all fifty cloud nodes.
    selected.sort(key=lambda value: (0, recheck_order[value["id"]]) if value["id"] in recheck_order else
                  (1, retry_positions[value["id"]]) if value["id"] in retry_positions else (2, 0))
    for candidate in selected:
        if connection_identity(build, candidate["link"]) in private_connections:
            candidate["public_publish_allowed"] = False
    history["candidates"] = dict(sorted(history["candidates"].items(), key=lambda pair: pair[1]["last_seen"], reverse=True)[:MAX_PROVENANCE])
    try:
        _write_private(state_dir / HISTORY_NAME, history)
        provenance_persistence = "saved"
    except (OSError, ValueError):
        # Reputation and rotation are optional hints. Preserve useful current
        # inputs even if their cache cannot be written; the frozen manifest
        # below remains mandatory for publication authorization.
        provenance_persistence = "unavailable"
    nodes = [{**{key: value for key, value in candidate.items() if not key.startswith("_")},
              **({"input_observed_at": candidate["_observed_at"]} if "_observed_at" in candidate else {})}
             for candidate in selected]
    used_cache_ages = [max(0, now - replayed[node["id"]]) for node in nodes if node["id"] in replayed]
    fetched_sources = discovery_stats.get("fetched_sources", 0)
    failed_sources = discovery_stats.get("source_failures", 0)
    fetched_sources = fetched_sources if type(fetched_sources) is int and 0 <= fetched_sources <= 160 else 0
    failed_sources = failed_sources if type(failed_sources) is int and 0 <= failed_sources <= 160 else 0
    registered_sources = min(160, max(len(pool.sources) if pool is not None else 0, len(source_stats), fetched_sources + failed_sources))
    attempted_sources = min(registered_sources, fetched_sources + failed_sources)
    manifest = {"schema": 1, "generated_at": now, "unverified_inputs": True,
                "best50_digest": hashlib.sha256("\n".join(best50_links).encode()).hexdigest(),
                "managed_pool_digest": managed_digest,
                "nodes": nodes,
                "summary": {"best50": sum(node["origin"] == "best50" for node in nodes),
                            "managed": sum(node["origin"] == "managed" for node in nodes),
                            "exploration": sum(node["origin"] in {"regional-exploration", "local-recheck"} for node in nodes),
                            "local_recheck": recheck_count,
                            "browser_retry": len(due_selected),
                            "collected": len(links), "invalid": invalid,
                            "discovery": discovery_stats, "source_catalog": catalog_status,
                            "provenance_persistence": provenance_persistence,
                            "candidate_cache": {"status": cache_status, "fresh": len(fresh_cache),
                                                "available": len(cached), "offered": len(replayed),
                                                "used": len(used_cache_ages), "stored": stored_cache_count,
                                                "oldest_used_age_seconds": max(used_cache_ages, default=None),
                                                "youngest_used_age_seconds": min(used_cache_ages, default=None),
                                                "fallback_main_manifest": fallback_count,
                                                "persistence": cache_persistence},
                            "source_counts": {"registered": registered_sources, "attempted": attempted_sources,
                                              "fetched": fetched_sources, "failed": failed_sources,
                                              "deferred": max(0, registered_sources - attempted_sources)},
                            "source_count": len(source_stats)}}
    if best50_sha is not None:
        if not isinstance(best50_sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", best50_sha):
            raise ValueError("Invalid Best50 commit identity")
        manifest["best50_sha"] = best50_sha
    path = state_dir / MANIFEST_NAME
    raw = _write_private(path, manifest)
    return [node["link"] for node in nodes], {**manifest, "manifest_path": str(path), "manifest_digest": hashlib.sha256(raw).hexdigest()}


def validate_manifest_membership(build, nodes, manifest_path, *, expected_digest=None, now=None, require_public=True,
                                 expected_best50_sha=None, expected_best50_digest=None):
    now = time.time() if now is None else now
    raw = _private_bytes(Path(manifest_path), required=True)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and (not isinstance(expected_digest, str) or not ID.fullmatch(expected_digest) or expected_digest != digest):
        raise ValueError("Regional input manifest changed after validation")
    try:
        manifest = json.loads(raw)
        stamp = manifest.get("generated_at") if isinstance(manifest, dict) else None
        entries = manifest.get("nodes") if isinstance(manifest, dict) else None
        if (not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or manifest["schema"] != 1
                or manifest.get("unverified_inputs") is not True or not _number(stamp)
                or stamp > now + 60 or now - stamp > MAX_AGE
                or not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MANIFEST_NODES
                or not isinstance(nodes, list) or len(nodes) > MAX_MANIFEST_NODES):
            raise ValueError
        if expected_best50_sha is not None and (
                not isinstance(expected_best50_sha, str)
                or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_best50_sha)
                or expected_best50_sha != manifest.get("best50_sha")):
            raise ValueError
        if expected_best50_digest is not None and (
                not isinstance(expected_best50_digest, str) or not ID.fullmatch(expected_best50_digest)
                or expected_best50_digest != manifest.get("best50_digest")):
            raise ValueError
        # Re-read the live managed opt-in policy immediately before export.
        # Revocation, deletion, replacement or creation after testing invalidates
        # the frozen authorization, including private/public canonical collisions.
        if "managed_pool_digest" not in manifest:
            raise ValueError
        managed_digest = manifest["managed_pool_digest"]
        if managed_digest is not None and (not isinstance(managed_digest, str) or not ID.fullmatch(managed_digest)):
            raise ValueError
        managed_raw = _private_bytes(Path(manifest_path).parent / "managed-pool.json")
        current_managed_digest = hashlib.sha256(managed_raw).hexdigest() if managed_raw is not None else None
        if managed_digest != current_managed_digest:
            raise ValueError
        managed, _ = _managed(build, Path(manifest_path).parent)
        private_connections = {connection_identity(build, entry["link"]) for entry in managed if not entry["public_publish_allowed"]}
        allowed = {}
        for entry in entries:
            if not isinstance(entry, dict) or type(entry.get("public_publish_allowed")) is not bool:
                raise ValueError
            candidate = _candidate(build, entry.get("link"), origin=entry.get("origin"), public=entry["public_publish_allowed"])
            if candidate is None or candidate["id"] != entry.get("id") or candidate["protocol"] != entry.get("protocol") or candidate["id"] in allowed:
                raise ValueError
            allowed[candidate["id"]] = candidate
        for node in nodes:
            link = node.get("link") if isinstance(node, dict) else node
            candidate = _candidate(build, link)
            if candidate is None or candidate["id"] not in allowed:
                raise ValueError
            if require_public and not allowed[candidate["id"]]["public_publish_allowed"]:
                raise ValueError
            if require_public and connection_identity(build, candidate["link"]) in private_connections:
                raise ValueError
        return True
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError("Node is absent from a current publication-authorized regional manifest") from None


def _outcome(diagnostic):
    try:
        from .local_feedback import classify_diagnostic
    except ImportError:
        from local_feedback import classify_diagnostic
    return {"pass": "qualified", "fail": "definitive-failure", "inconclusive": "inconclusive"}[classify_diagnostic(diagnostic)]


def apply_local_feedback(state_dir, diagnostics, now=None):
    """Update source reputation only from conclusive authoritative local results."""
    now = time.time() if now is None else now
    if not _number(now) or not isinstance(diagnostics, list) or len(diagnostics) > MAX_MANIFEST_NODES:
        raise ValueError("Invalid regional diagnostic batch")
    state_dir = _state_directory(state_dir)
    history = _load_history(state_dir, now)
    totals = Counter()
    sources = {}
    seen = set()
    for result in diagnostics:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str) or not ID.fullmatch(result["id"]) or result["id"] in seen:
            continue
        identifier = result["id"]
        seen.add(identifier)
        outcome = _outcome(result)
        totals[outcome] += 1
        candidate = history["candidates"].get(identifier)
        if candidate is None:
            continue  # Best50-only and private candidates have no invented source attribution.
        candidate.update(last_tested=now, last_seen=now, last_outcome=outcome)
        # Store only a validated same-proxy observation as a future search hint.
        # This field never authorizes selection/publication without a fresh test.
        country_evidence = result.get("exit_country_evidence")
        if isinstance(country_evidence, dict):
            from service_probe import valid_exit_country_evidence
            country = country_evidence.get("country")
            if (isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country)
                    and valid_exit_country_evidence(country_evidence, country)):
                candidate["last_exit_country"] = country
        if outcome == "inconclusive" and _deferred_browser_result(result):
            previous = candidate.get("browser_retry", {})
            attempts = min(8, previous.get("attempts", 0) + 1)
            candidate["browser_retry"] = {"first_at": previous.get("first_at", now), "attempts": attempts,
                                          "after": now + min(BROWSER_RETRY_MAX, BROWSER_RETRY_BASE * 2 ** min(attempts - 1, 3))}
        else:
            # A real admitted browser response, definitive rejection or strict
            # success completes the deferred task; no historical pass is reused.
            candidate.pop("browser_retry", None)
        for source in candidate["source_ids"]:
            sources.setdefault(source, Counter())[outcome] += 1
    for source, counts in sources.items():
        record = history["sources"].setdefault(source, {"qualified": 0, "definitive_failure": 0, "inconclusive": 0, "local_ema": 0.0})
        for outcome, count in counts.items():
            key = outcome.replace("-", "_")
            record[key] = min(1_000_000, record.get(key, 0) + count)
        definite = counts["qualified"] + counts["definitive-failure"]
        if definite:
            record["local_ema"] = round(0.65 * record.get("local_ema", 0) + 0.35 * counts["qualified"] / definite, 6)
        record["last_seen"] = now
    _bound_browser_retries(history["candidates"])
    persisted = True
    try:
        _write_private(state_dir / HISTORY_NAME, history)
    except (OSError, ValueError):
        persisted = False
    # This separate registry is regional-only, so functional_ema now describes
    # Mac evidence. SourcePool will prioritize it in the next collection cycle.
    path = state_dir / DISCOVERY_NAME
    if path.exists():
        try:
            pool = PrivateSourcePool([], path, now=now)
            for source, record in history["sources"].items():
                if source in pool.sources:
                    pool.sources[source]["functional_ema"] = record["local_ema"]
                    counts = sources.get(source, {})
                    definite = counts.get("qualified", 0) + counts.get("definitive-failure", 0)
                    if definite:
                        item = pool.sources[source]
                        item.update(last_tested=now, last_tested_count=definite,
                                    last_functional_count=counts.get("qualified", 0),
                                    validation_runs=min(1_000_000, int(item.get("validation_runs", 0)) + 1))
            pool.save()
        except (OSError, ValueError, RuntimeError):
            persisted = False
    return {"qualified": totals["qualified"], "definitive_failure": totals["definitive-failure"],
            "inconclusive": totals["inconclusive"], "sources_updated": len(sources), "persisted": persisted}
