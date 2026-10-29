"""Independent, private regional exploration inputs for the strict local validator.

These inputs are UNVERIFIED. Neither discovery nor a manifest grants publication:
the caller must still require current, complete service and latency evidence.
Managed credentials never enter source discovery state or public diagnostics.
"""
from __future__ import annotations

from collections import Counter
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
ID = re.compile(r"[0-9a-f]{64}")
SOURCE_ID = re.compile(r"[0-9a-f]{24}")
MANIFEST_NAME = "regional-input-manifest.json"
HISTORY_NAME = "regional-pool-state.json"
DISCOVERY_NAME = "regional-discovery-state.json"


def _number(value, maximum=10 ** 12):
    return ((type(value) is int and 0 <= value <= maximum)
            or (type(value) is float and math.isfinite(value) and 0 <= value <= maximum))


def _source_ids(values):
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return sorted({value for value in values if isinstance(value, str) and SOURCE_ID.fullmatch(value)})[:MAX_SOURCE_IDS]


def _state_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("Regional state directory must be owned by this user")
    os.chmod(path, 0o700)
    return path


def _private_bytes(path: Path, *, required=False) -> bytes | None:
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
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_BYTES):
            raise ValueError("Private input must be a bounded user-owned mode-600 file")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
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
            else:
                for name in ("qualified", "definitive_failure", "inconclusive"):
                    count = value.get(name, 0)
                    item[name] = count if type(count) is int and 0 <= count <= 1_000_000 else 0
                ema = value.get("local_ema", 0)
                item["local_ema"] = float(ema) if _number(ema, 1) else 0.0
            clean[kind][key] = item
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


def _published_rechecks(build):
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
        status = json.loads(blob(commit, "output/local-status.json"))
        nodes = status.get("nodes") if isinstance(status, dict) else None
        retained = status.get("retained_nodes", []) if isinstance(status, dict) else None
        if (not isinstance(status, dict) or status.get("algorithm") != "bestlocal-strict-services-v6"
                or not isinstance(nodes, list) or not 1 <= len(nodes) <= 12
                or not isinstance(retained, list) or len(retained) > 2):
            return []
        nodes = nodes + retained
        published = {}
        for line in blob(commit, "output/best-local.txt").decode().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            candidate = _candidate(build, line.strip(), origin="local-recheck")
            if candidate is not None:
                published[candidate["id"]] = candidate
        result = []
        for value in nodes:
            candidate = _candidate(build, value.get("link"), origin="local-recheck") if isinstance(value, dict) else None
            if candidate is not None and candidate["id"] in published:
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


def collect_regional(build, best50_links, state_dir, now=None, limit=50, *, best50_sha=None):
    """Return Best50, managed entries and a rotating independent public tranche.

    Synchronous bounded collection belongs in asyncio.to_thread at the caller.
    `manifest_digest` must be captured in the completed validation status and
    supplied to validate_manifest_membership before public publication.
    """
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
    for candidate in _published_rechecks(build):
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
        catalog_urls, catalog_status = load_regional_sources(build.ROOT, now=now)
        for url in catalog_urls:
            pool.add(url, origin="grok-research")
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
    invalid = 0
    for link in links:
        candidate = _candidate(build, link, pool.link_sources.get(link, ()))
        if candidate is None:
            invalid += 1
            continue
        identifier = candidate["id"]
        previous = history["candidates"].get(identifier, {})
        source_ids = _source_ids(set(candidate["source_ids"]) | set(previous.get("source_ids", [])))
        history["candidates"][identifier] = {**previous, "last_seen": now, "source_ids": source_ids,
                                               "last_tested": previous.get("last_tested", 0)}
        if identifier in by_id:
            by_id[identifier]["source_ids"] = _source_ids(set(by_id[identifier]["source_ids"]) | set(source_ids))
            continue
        if identifier in candidates:
            candidates[identifier]["source_ids"] = _source_ids(set(candidates[identifier]["source_ids"]) | set(source_ids))
        else:
            candidate["source_ids"] = source_ids
            candidates[identifier] = candidate
    selected.extend(_select(list(candidates.values()), history, limit - recheck_count))
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
    nodes = [{key: value for key, value in candidate.items() if key != "_node"} for candidate in selected]
    manifest = {"schema": 1, "generated_at": now, "unverified_inputs": True,
                "best50_digest": hashlib.sha256("\n".join(best50_links).encode()).hexdigest(),
                "managed_pool_digest": managed_digest,
                "nodes": nodes,
                "summary": {"best50": sum(node["origin"] == "best50" for node in nodes),
                            "managed": sum(node["origin"] == "managed" for node in nodes),
                            "exploration": sum(node["origin"] in {"regional-exploration", "local-recheck"} for node in nodes),
                            "local_recheck": recheck_count,
                            "collected": len(links), "invalid": invalid,
                            "discovery": discovery_stats, "source_catalog": catalog_status,
                            "provenance_persistence": provenance_persistence,
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
