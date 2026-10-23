"""Use recent authoritative Mac evidence to replenish primary publications.

Feedback only orders candidates that the primary builder has already validated.
It cannot introduce a configuration, bypass a gate, or label a node as working.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import re
import subprocess
import time


POLICY = "bestlocal-strict-services-v6"
MAX_BYTES = 1024 * 1024
MAX_IDS = 5000
MAX_HEALTH_AGE = 18 * 3600
REJECT_COOLDOWN = 12 * 3600
PASS_FRESHNESS = 6 * 3600
PASS_SCORE_BONUS = 0.05
HEALTH_REF = "refs/remotes/origin/regional:output/local-health.json"
_ID = re.compile(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})")


def _epoch(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def parse_health(raw: bytes, now: float | None = None) -> tuple[dict, dict]:
    now = time.time() if now is None else now
    summary = {"status": "invalid", "records": 0, "invalid_records": 0}
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        return {}, summary
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return {}, summary
    if not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1 or data.get("policy") != POLICY:
        return {}, summary
    generated = data.get("generated_at")
    if not _epoch(generated) or generated > now:
        return {}, summary
    if now - generated > MAX_HEALTH_AGE:
        summary["status"] = "stale"
        return {}, summary
    recent = data.get("recent_results", {})
    diagnostics = data.get("diagnostics", [])
    if not isinstance(recent, dict) or not isinstance(diagnostics, list) or len(recent) > MAX_IDS or len(diagnostics) > MAX_IDS:
        return {}, summary
    records = {}
    def add(identifier, value, seen):
        if (not isinstance(identifier, str) or not _ID.fullmatch(identifier)
                or type(value) is not bool or not _epoch(seen) or seen > generated):
            summary["invalid_records"] += 1
            return
        identifier = identifier.lower()
        if len(records) >= MAX_IDS and identifier not in records:
            raise ValueError("feedback ID budget exceeded")
        if seen >= records.get(identifier, {}).get("last_seen", 0):
            records[identifier] = {"last_seen": seen, "qualified": value}
    try:
        for identifier, result in recent.items():
            if not isinstance(result, dict):
                summary["invalid_records"] += 1
                continue
            add(identifier, result.get("qualified"), result.get("last_seen"))
        for result in diagnostics:
            if not isinstance(result, dict):
                summary["invalid_records"] += 1
                continue
            # Diagnostics describe the latest completed attempt. Historical
            # entries retain their own last_seen timestamp in recent_results.
            add(result.get("id"), result.get("qualified"), generated)
    except ValueError:
        return {}, summary
    summary.update(status="fresh", records=len(records), generated_at=generated)
    return records, summary


def read_regional_health(repo: Path) -> bytes:
    """Read one immutable, size-checked Git blob; never invoke a shell/network."""
    def git(*arguments):
        result = subprocess.run(
            ["git", *arguments], cwd=repo, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=True,
        )
        return result.stdout
    oid = git("rev-parse", "--verify", HEALTH_REF).strip().decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
        raise ValueError("invalid feedback blob")
    size = int(git("cat-file", "-s", oid).strip())
    if not 0 <= size <= MAX_BYTES:
        raise ValueError("feedback blob exceeds budget")
    raw = git("cat-file", "blob", oid)
    if len(raw) != size:
        raise ValueError("feedback blob size mismatch")
    return raw


def load_regional_feedback(repo: Path, now: float | None = None) -> tuple[dict, dict]:
    try:
        return parse_health(read_regional_health(repo), now=now)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return {}, {"status": "unavailable", "records": 0, "invalid_records": 0}


def apply_feedback(ranked: list[dict], records: dict, now: float | None = None) -> tuple[list[dict], dict]:
    """Demote recent rejects and apply a bounded recent-local-pass score bonus.

    Recent passes share the eligible group with untested/expired nodes, allowing
    the existing diversity policy to choose across providers. Recent local
    rejects are considered only after eligible alternatives are exhausted.
    """
    now = time.time() if now is None else now
    summary = {"applied": 0, "passed": 0, "rejected": 0, "expired": 0, "unmatched": 0}
    matched = set()
    ordered = []
    for item in ranked:
        candidate = dict(item)
        group = 1
        # Keep the bonus bounded even if the helper is accidentally applied twice.
        base_score = candidate.get("_local_feedback_base_score", candidate["score"])
        candidate["_local_feedback_base_score"] = base_score
        candidate["score"] = base_score
        identifier = candidate.get("normalized", "")
        # The primary builder supplies canonical full SHA256 IDs. Legacy short
        # IDs may be parsed for compatibility but can never match a candidate.
        result = records.get(identifier) if isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{64}", identifier) else None
        if result:
            matched.add(identifier)
            age = now - result["last_seen"]
            if 0 <= age < (PASS_FRESHNESS if result["qualified"] else REJECT_COOLDOWN):
                group = 1 if result["qualified"] else 2
                if result["qualified"]:
                    candidate["score"] = float(base_score) * (1 + PASS_SCORE_BONUS)
                summary["applied"] += 1
                summary["passed" if result["qualified"] else "rejected"] += 1
            else:
                summary["expired"] += 1
        candidate["_local_feedback_group"] = group
        ordered.append(candidate)
    summary["unmatched"] = len(records.keys() - matched)
    ordered.sort(key=lambda item: (item["_local_feedback_group"], -float(item["score"])))
    return ordered, summary
