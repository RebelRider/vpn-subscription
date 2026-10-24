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
    return ((type(value) is int and 0 < value <= 10 ** 12)
            or (type(value) is float and math.isfinite(value) and 0 < value <= 10 ** 12))


def classify_diagnostic(diagnostic) -> str:
    """Reduce bounded, credential-free local evidence to a ranking outcome.

    A failed qualification is not by itself proof that a candidate is dead.
    Challenges, HTTP policy responses and unavailable controls take precedence
    over transport errors elsewhere in the same inconclusive attempt.
    """
    if not isinstance(diagnostic, dict):
        return "inconclusive"
    if diagnostic.get("qualified") is True:
        return "pass"
    strings = []
    codes = []
    curl_codes = []
    uncertain = False
    pending = [diagnostic]
    visited = 0
    while pending and visited < 300:
        value = pending.pop()
        visited += 1
        if isinstance(value, dict):
            browser_resolved = value.get("outcome") == "pass" and value.get("reason") == "browser-functional-access"
            for key, item in list(value.items())[:40]:
                if browser_resolved and key in {"cf_challenge", "challenge", "http_status", "status", "http_reason", "http_outcome"}:
                    # A current browser proof resolved this particular HTTP
                    # challenge. Another service's transport failure still
                    # needs its own classification.
                    continue
                if key in {"cf_challenge", "challenge"} and item is True:
                    uncertain = True
                if key == "outcome" and item == "inconclusive":
                    uncertain = True
                if key in {"http_status", "status"} and type(item) is int:
                    codes.append(item)
                if key == "curl_exit" and type(item) is int:
                    curl_codes.append(item)
                if key in {"reason", "http_reason", "error", "rejection_reasons", "reasons"}:
                    pending.append(item)
                elif key in {"services", "evidence", "latency_checks", "engine_errors", "transport_errors", "browser_check", "control", "transport_attempts"}:
                    pending.append(item)
                elif key in {"dns-failed", "routing-no-route", "tls-certificate-invalid", "protocol-authentication-failed", "configuration-invalid", "connection-refused", "timeout", "tls-handshake-failed", "protocol-handshake-failed", "connection-reset", "connection-eof", "socks-connection-failed"}:
                    if type(item) is int and item > 0:
                        strings.append(key)
                # Service names and other evidence containers need no hardcoded
                # naming convention; only nested bounded objects are visited.
                elif isinstance(item, (dict, list)):
                    pending.append(item)
        elif isinstance(value, list):
            pending.extend(value[:40])
        elif isinstance(value, str):
            strings.append(value[:160].lower())
    text = " ".join(strings)
    if (uncertain or any(code in {401, 403, 408, 429} or 500 <= code <= 599 for code in codes)
            or any(marker in text for marker in (
                "inconclusive", "challenge", "captcha", "rate-limit", "rate_limit",
                "access-denied", "authentication-required", "http-401", "http-403", "http-429",
                "browser-check-unavailable", "browser-runtime-unavailable", "browser-dependency",
                "browser-network-isolation-unavailable", "browser-isolation-test-failed",
                "browser-proof-missing", "browser-proof-unavailable", "control-unavailable",
                "control-failed", "positive-control", "engine-unavailable", "request-process-failed",
            ))):
        return "inconclusive"
    if (any(code in {5, 6, 7, 28, 35, 51, 56, 60, 97} for code in curl_codes)
            or any(marker in text for marker in (
                "invalid-or-unsafe-config", "invalid-config", "configuration-invalid",
                "protocol-authentication-failed", "protocol-handshake-failed", "protocol-error",
                "dns-failed", "dns-timeout", "name-resolution-failed", "server-dns",
                "routing-no-route", "connection-refused", "connection-reset", "connection-eof",
                "tls-handshake-failed", "tls-certificate-invalid", "destination-tls-failed",
                "destination-certificate-invalid", "socks-connection-failed", "proxy-receive-failed",
                "proxy-start-or-network-failure", "proxy-exited", "loopback-proxy-unavailable",
                "socket-failed", "socket-error", "timeout", "latency-not-below-500ms",
                "curl-5", "curl-6", "curl-7", "curl-28", "curl-35", "curl-51", "curl-56", "curl-60", "curl-97",
            ))):
        return "fail"
    return "inconclusive"


def _valid_outcome(value, qualified):
    if not isinstance(value, str) or value not in {"pass", "fail", "inconclusive"}:
        return None
    # An optional label cannot invent a strict pass or contradict qualification.
    return value if (value == "pass") == qualified else None


def _rich_diagnostic(result):
    if any(key in result and isinstance(result[key], (dict, list)) for key in (
            "engine_errors", "browser_check", "latency_checks", "transport_attempts")):
        return True
    services = result.get("services")
    return (isinstance(services, dict) and any(isinstance(service, dict)
            and isinstance(service.get("evidence"), list) for service in list(services.values())[:3]))


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
    def add(identifier, value, seen, outcome=None):
        if (not isinstance(identifier, str) or not _ID.fullmatch(identifier)
                or type(value) is not bool or not _epoch(seen) or seen > generated):
            summary["invalid_records"] += 1
            return
        identifier = identifier.lower()
        if len(records) >= MAX_IDS and identifier not in records:
            raise ValueError("feedback ID budget exceeded")
        if seen >= records.get(identifier, {}).get("last_seen", 0):
            record = {"last_seen": seen, "qualified": value}
            outcome = _valid_outcome(outcome, value)
            if outcome is None and not value:
                # Old qualification booleans cannot distinguish a dead server
                # from a Cloudflare challenge or a validator infrastructure issue.
                outcome = "inconclusive"
            if outcome is not None:
                record["outcome"] = outcome
            records[identifier] = record
    try:
        for identifier, result in recent.items():
            if not isinstance(result, dict):
                summary["invalid_records"] += 1
                continue
            add(identifier, result.get("qualified"), result.get("last_seen"), result.get("outcome"))
        for result in diagnostics:
            if not isinstance(result, dict):
                summary["invalid_records"] += 1
                continue
            # Diagnostics describe the latest completed attempt. Historical
            # entries retain their own last_seen timestamp in recent_results.
            outcome = (classify_diagnostic(result) if _rich_diagnostic(result)
                       else _valid_outcome(result.get("outcome"), result.get("qualified")))
            add(result.get("id"), result.get("qualified"), generated, outcome)
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
    summary = {"applied": 0, "passed": 0, "rejected": 0, "inconclusive": 0, "expired": 0, "unmatched": 0}
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
            if not result["qualified"] and result.get("outcome") != "fail":
                # Keep uncertainty eligible: it must neither boost the score nor
                # poison the twelve-hour hard-failure group.
                summary["inconclusive" if 0 <= age < MAX_HEALTH_AGE else "expired"] += 1
            elif 0 <= age < (PASS_FRESHNESS if result["qualified"] else REJECT_COOLDOWN):
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
