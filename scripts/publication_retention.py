"""Keep explicitly protected public connections without claiming fresh proof.

Only immutable, already published strict results can supply a retained entry.
Fresh qualification remains the responsibility of local_probe's unchanged gates.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import subprocess
import time

MAX_RETAINED = 2
MAX_BYTES = 1024 * 1024
OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ID = re.compile(r"[0-9a-f]{64}")
STATUS_PATH = "output/local-status.json"
SUBSCRIPTION_PATH = "output/best-local.txt"


def protected_ids(build) -> list[str]:
    policy = getattr(build, "CFG", {}).get("regional_publication", {})
    values = policy.get("protected_ids", []) if isinstance(policy, dict) else None
    if (not isinstance(values, list) or len(values) > MAX_RETAINED
            or any(not isinstance(value, str) or not ID.fullmatch(value) for value in values)
            or len(set(values)) != len(values)):
        raise RuntimeError("Invalid protected publication identities")
    return values


def all_nodes(status: dict) -> list[dict]:
    fresh, retained = status.get("nodes", []), status.get("retained_nodes", [])
    if not isinstance(fresh, list) or not isinstance(retained, list) or len(retained) > MAX_RETAINED:
        raise RuntimeError("Invalid retained publication node collection")
    return fresh + retained


def rendered_links(local, status: dict) -> list[str]:
    return [local.published_link(node["link"], index, node.get("exit_country"),
                                 node.get("exit_city"), node.get("exit_ip"))
            for index, node in enumerate(all_nodes(status), 1)]


def _git(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(["git", *arguments], cwd=repo, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Retained publication Git evidence unavailable") from None
    if result.returncode:
        raise RuntimeError("Retained publication Git evidence invalid")
    return result.stdout


def _oid(value: object) -> str:
    if not isinstance(value, str) or not OID.fullmatch(value):
        raise RuntimeError("Invalid retained publication object identity")
    return value


def _blob(repo: Path, commit: str, path: str) -> tuple[str, bytes]:
    oid = _oid(_git(repo, "rev-parse", "--verify", f"{commit}:{path}").strip().decode("ascii"))
    size = int(_git(repo, "cat-file", "-s", oid))
    if not 0 < size <= MAX_BYTES:
        raise RuntimeError("Retained publication evidence exceeds size limit")
    raw = _git(repo, "cat-file", "blob", oid)
    if len(raw) != size:
        raise RuntimeError("Incomplete retained publication evidence")
    return oid, raw


def snapshot(repo: Path, commit: str) -> dict:
    commit = _oid(commit)
    actual = _git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").strip().decode("ascii")
    if actual != commit:
        raise RuntimeError("Retained publication does not reference a commit")
    committed_at = int(_git(repo, "show", "-s", "--format=%ct", commit))
    if not 0 < committed_at <= time.time() + 300:
        raise RuntimeError("Future or invalid retained publication commit")
    status_oid, status_raw = _blob(repo, commit, STATUS_PATH)
    subscription_oid, subscription_raw = _blob(repo, commit, SUBSCRIPTION_PATH)
    try:
        status = json.loads(status_raw)
        lines = [line.strip() for line in subscription_raw.decode("utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
    except (ValueError, UnicodeError, RecursionError):
        raise RuntimeError("Malformed retained publication evidence") from None
    if (not isinstance(status, dict) or status.get("algorithm") != "bestlocal-strict-services-v6"
            or not isinstance(status.get("nodes"), list)):
        raise RuntimeError("Retained publication lacks strict original metadata")
    return {"commit": commit, "status_blob": status_oid, "subscription_blob": subscription_oid,
            "status": status, "lines": lines}


def _entry(local, snap: dict, identifier: str) -> dict | None:
    entries = all_nodes(snap["status"])
    if not 1 <= len(entries) <= local.MAX_LOCAL_PUBLISHED_NODES + MAX_RETAINED:
        raise RuntimeError("Invalid original publication inventory")
    if snap["lines"] != rendered_links(local, snap["status"]):
        raise RuntimeError("Original publication content does not match its metadata")
    matches = [node for node in entries if isinstance(node, dict) and node.get("id") == identifier]
    if len(matches) > 1:
        raise RuntimeError("Duplicate protected publication identity")
    return matches[0] if matches else None


def _same_payload(left, right) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False, separators=(",", ":")) == json.dumps(
        right, sort_keys=True, allow_nan=False, separators=(",", ":"))


def _historical_proof(local, source: dict, node: dict) -> None:
    """Validate original proof at its original epoch, never as a current pass."""
    status = source["status"]
    try:
        stamp = datetime.fromisoformat(status["generated_at"].replace("Z", "+00:00"))
        epoch = stamp.timestamp()
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        raise RuntimeError("Invalid original validation timestamp") from None
    if stamp.tzinfo is None or not math.isfinite(epoch) or not 0 < epoch <= time.time() + 300:
        raise RuntimeError("Future or invalid original validation timestamp")
    stability = status.get("stability", {})
    nodes = status["nodes"]
    rounds = stability.get("rounds") if isinstance(stability, dict) else None
    if (not isinstance(stability, dict) or not 1 <= len(nodes) <= local.MAX_LOCAL_PUBLISHED_NODES
            or not all(isinstance(value, dict) for value in nodes)
            or type(stability.get("qualified")) is not int or stability["qualified"] != len(nodes)
            or type(rounds) is not int or rounds not in (3, 4, 5)
            or stability.get("minimum_successes") != rounds
            or any(type(value.get("rank")) is not int for value in nodes)
            or [value.get("rank") for value in nodes] != list(range(1, len(nodes) + 1))):
        raise RuntimeError("Incomplete original strict validation")
    local.require_fresh_timestamp(status.get("upstream_generated_at"), 18, "original input", reference_time=stamp)
    for value in nodes:
        local.require_fresh_timestamp(value.get("validated_at"), 6, "original candidate", reference_time=stamp)
        if not local.valid_node_evidence(value, rounds, require_round_evidence=True, reference_time=stamp):
            raise RuntimeError("Original candidate lacks historical functional proof")
    original = [value for value in nodes if value.get("id") == node.get("id")]
    if len(original) != 1 or not _same_payload(original[0], node):
        raise RuntimeError("Retained payload differs from original strict candidate")


def validate(local, build, status: dict, *, base_ref: str | None = None) -> None:
    entries = all_nodes(status)
    retained = status.get("retained_nodes", [])
    provenance = status.get("retained_provenance", {})
    if not retained:
        total = status.get("published_total", len(entries))
        if not isinstance(provenance, dict) or provenance or type(total) is not int or total != len(entries):
            raise RuntimeError("Inconsistent retained publication totals")
        return
    allowed = set(protected_ids(build))
    if (not isinstance(retained, list) or not 1 <= len(retained) <= MAX_RETAINED
            or not isinstance(provenance, dict)
            or set(provenance) != {node.get("id") for node in retained if isinstance(node, dict)}
            or not set(provenance) <= allowed
            or type(status.get("published_total")) is not int
            or status["published_total"] != len(entries)):
        raise RuntimeError("Invalid retained publication provenance or totals")
    local.validate_publication_nodes(build, entries, maximum=local.MAX_LOCAL_PUBLISHED_NODES + MAX_RETAINED)
    base = _oid(base_ref or _git(local.ROOT, "rev-parse", "--verify", "refs/remotes/origin/regional").strip().decode("ascii"))
    current = snapshot(local.ROOT, base)
    for node in retained:
        if _entry(local, current, node["id"]) is None:
            raise RuntimeError("Protected entry is absent from current public subscription")
        item = provenance[node["id"]]
        if not isinstance(item, dict) or set(item) != {"commit", "status_blob", "subscription_blob"}:
            raise RuntimeError("Invalid retained source reference")
        commit = _oid(item["commit"])
        _git(local.ROOT, "merge-base", "--is-ancestor", commit, base)
        source = snapshot(local.ROOT, commit)
        if any(item[key] != source[key] for key in ("status_blob", "subscription_blob")):
            raise RuntimeError("Retained source blob identity mismatch")
        original = _entry(local, source, node["id"])
        if original is None or not _same_payload(original, node):
            raise RuntimeError("Retained candidate does not match its published source")
        _historical_proof(local, source, node)


def prepare(local, build, status: dict, base_ref: str) -> None:
    """Rebuild retention from the exact publication base on every safe retry."""
    for name in ("retained_nodes", "retained_provenance", "published_total"):
        status.pop(name, None)
    allowed = protected_ids(build)
    if not allowed:
        return
    # Corrupt unrelated legacy metadata must not prevent a fresh publication.
    # Retention is required only for configured identities actually present in
    # this immutable base's public connection inventory.
    _, published_raw = _blob(local.ROOT, _oid(base_ref), SUBSCRIPTION_PATH)
    published_ids = set()
    for line in published_raw.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            published_ids.add(build.normalized_fingerprint(build.parse_vless(line.strip())))
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
            continue
    if not set(allowed) & published_ids:
        return
    current = snapshot(local.ROOT, base_ref)
    fresh_connections = {local.connection_identity(build, node["link"]) for node in status["nodes"]}
    fresh_ids = {node["id"] for node in status["nodes"]}
    retained, provenance = [], {}
    for identifier in allowed:
        if identifier in fresh_ids:
            continue
        node = _entry(local, current, identifier)
        if node is None:
            continue
        connection = local.connection_identity(build, node["link"])
        if connection in fresh_connections:
            continue
        if any(value.get("id") == identifier for value in current["status"]["nodes"]):
            original = {key: current[key] for key in ("commit", "status_blob", "subscription_blob")}
        else:
            original = current["status"].get("retained_provenance", {}).get(identifier)
            if not isinstance(original, dict):
                raise RuntimeError("Missing original protected publication provenance")
        retained.append(copy.deepcopy(node))
        provenance[identifier] = copy.deepcopy(original)
        fresh_connections.add(connection)
    if retained:
        status.update(retained_nodes=retained, retained_provenance=provenance,
                      published_total=len(status["nodes"]) + len(retained))
        validate(local, build, status, base_ref=base_ref)
