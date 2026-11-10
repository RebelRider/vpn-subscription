#!/usr/bin/env python3
"""Validate untrusted research suggestions and maintain the public source catalog.

This module never accepts proxy credentials/configurations as research output.
A catalog entry is only a discovery input; every server still needs primary and
strict local functional validation before it can appear in BestLocal.
"""
from __future__ import annotations

import argparse
from collections import Counter
import fcntl
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

from source_discovery import SourcePool, canonical_url, decode_subscription, extract_links, RateLimited, SourcePolicyUnavailable
from owned_temporary import temporary_directory

CATALOG_PATH = "sources/primary-sources.json"
CATALOG_REF = "refs/remotes/origin/regional:" + CATALOG_PATH
MAX_BYTES = 512 * 1024
MAX_SOURCES = 64
MAX_PROPOSALS = 32
MAX_AGE = 30 * 86400
REFRESH_SECONDS = 24 * 3600
QWEN_MODEL = "mlx-community/Qwen3.8-27B-4bit"


class ResearchSourcesUnavailable(RuntimeError):
    """A retry may succeed; preserve the model's pending proposal."""
    def __init__(self, message: str, retry_at: float = 0, *, summary: dict | None = None, reason: str = "publication"):
        self.retry_at = retry_at
        self.summary = summary or {}
        self.reason = reason if reason in {"publication", "network"} else "publication"
        super().__init__(message)


def _number(value) -> bool:
    return ((type(value) is int and -(10 ** 15) <= value <= 10 ** 15)
            or (type(value) is float and math.isfinite(value)))


def parse_catalog(raw: bytes, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    empty = {"schema": 1, "generated_at": 0, "sources": []}
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        return empty
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return empty
    if (not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1
            or not isinstance(data.get("sources"), list) or len(data["sources"]) > MAX_SOURCES):
        return empty
    records = {}
    for record in data["sources"]:
        try:
            if not isinstance(record, dict) or type(record.get("enabled", True)) is not bool:
                continue
            url = canonical_url(record["url"])
            evidence = canonical_url(record["evidence_url"])
            verified = record["last_verified_at"]
            first = record.get("first_seen", verified)
            if not _number(verified) or not 0 < verified <= now + 300:
                continue
            if not _number(first) or not 0 < first <= verified:
                first = verified
            clean = {"url": url, "evidence_url": evidence, "first_seen": first,
                     "last_verified_at": verified, "enabled": record.get("enabled", True)}
            discoverer = record.get("discovered_by")
            if discoverer in ("independent", "grok", "qwen"):
                clean["discovered_by"] = discoverer
                model = record.get("discovery_model")
                if discoverer == "grok" and isinstance(model, str) and re.fullmatch(r"(?:cursor-)?grok-\d+(?:\.\d+)*-xhigh", model):
                    clean["discovery_model"] = model
                elif discoverer == "qwen" and model == QWEN_MODEL:
                    clean["discovery_model"] = model
            if url not in records or records[url]["last_verified_at"] < verified:
                records[url] = clean
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
    generated = data.get("generated_at", 0)
    if not _number(generated) or not 0 <= generated <= now + 300:
        generated = 0
    return {"schema": 1, "generated_at": generated, "sources": sorted(records.values(), key=lambda item: item["url"])}


def _git_blob(repo: Path, ref: str) -> bytes:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL, timeout=5)
    oid = git("rev-parse", "--verify", ref).strip().decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
        raise ValueError("invalid catalog object")
    length = int(git("cat-file", "-s", oid).strip())
    if not 0 <= length <= MAX_BYTES:
        raise ValueError("source catalog exceeds byte limit")
    raw = git("cat-file", "blob", oid)
    if len(raw) != length:
        raise ValueError("source catalog size mismatch")
    return raw


def load_regional_sources(repo: Path, now: float | None = None) -> tuple[list[str], dict]:
    now = time.time() if now is None else now
    try:
        catalog = parse_catalog(_git_blob(repo, CATALOG_REF), now=now)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return [], {"status": "unavailable", "active": 0}
    active = [item["url"] for item in catalog["sources"]
              if item["enabled"] and 0 <= now - item["last_verified_at"] <= MAX_AGE]
    return active, {"status": "available" if active else "empty-or-expired", "active": len(active)}


def parse_proposal(text: str) -> tuple[list[dict], int]:
    if not isinstance(text, str) or len(text.encode()) > MAX_BYTES:
        raise ValueError("research proposal exceeds byte limit")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise ValueError("research result must be JSON") from None
    if (not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] != 1
            or set(data) - {"schema", "sources"} or not isinstance(data.get("sources"), list)
            or len(data["sources"]) > MAX_PROPOSALS):
        raise ValueError("research result has an unsupported schema")
    found, rejected = {}, 0
    for item in data["sources"]:
        try:
            if not isinstance(item, dict) or set(item) - {"url", "evidence_url", "name", "protocols"}:
                raise ValueError("unsupported source metadata")
            url, evidence = canonical_url(item["url"]), canonical_url(item["evidence_url"])
            # Model-provided names and protocol claims are never authoritative.
            found[url] = {"url": url, "evidence_url": evidence}
        except (ValueError, TypeError, KeyError, OverflowError):
            rejected += 1
    return list(found.values()), rejected


def _has_compatible_configuration(text: str) -> bool:
    # Import lazily: the builder imports the catalog loader during initialization.
    import build
    for link in extract_links(text):
        try:
            build.parse_vless(link)
            return True
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
    return False


def _merge_catalog(current: dict, updates: list[dict], now: float) -> dict:
    records = {item["url"]: item for item in current["sources"]
               if now - item["last_verified_at"] <= MAX_AGE}
    for update in updates:
        previous = records.get(update["url"])
        if previous and previous["last_verified_at"] > update["last_verified_at"]:
            continue
        record = dict(update)
        if previous:
            record["first_seen"] = previous["first_seen"]
            # Refreshing a legacy entry cannot establish its original finder.
            for key in ("discovered_by", "discovery_model"):
                record.pop(key, None)
                if key in previous:
                    record[key] = previous[key]
        records[record["url"]] = record
    ranked = sorted(records.values(), key=lambda item: (-item["last_verified_at"], item["url"]))[:MAX_SOURCES]
    sources = sorted(ranked, key=lambda item: item["url"])
    if sources == current["sources"]:
        return current
    return {"schema": 1, "generated_at": now, "sources": sources}


def publish_catalog(repo: Path, state_dir: Path, updates: list[dict], now: float) -> bool:
    """Publish only the catalog, using the existing regional branch and auth."""
    from regional_scheduler import Runner, CommandFailure
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # This writer has its own detached worktree and immutable branch snapshot;
    # it need not wait behind the much longer local validation scheduler. Git's
    # non-forced transaction retry protects concurrent regional branch writers.
    with (state_dir / "source-catalog-publication.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ResearchSourcesUnavailable("another catalog publication is active; publication deferred") from None
        runner = Runner(repo, time.monotonic() + 300)
        for attempt in range(3):
            try:
                runner.git("fetch", "--quiet", "origin", "regional")
                base = runner.git("rev-parse", "--verify", "refs/remotes/origin/regional")
                if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base):
                    raise RuntimeError("invalid regional catalog base")
                try:
                    current = parse_catalog(_git_blob(repo, base + ":" + CATALOG_PATH), now)
                except (OSError, ValueError, subprocess.SubprocessError):
                    current = {"schema": 1, "generated_at": 0, "sources": []}
                merged = _merge_catalog(current, updates, now)
                if merged == current:
                    return False
                with temporary_directory(prefix="bestlocal-source-publish-", parent=state_dir / "temporary", repo=repo) as directory:
                    worktree = Path(directory) / "checkout"
                    try:
                        # Read and commit against the same immutable snapshot.
                        # A concurrent ref update must reject this push rather
                        # than silently replacing a newer catalog with old data.
                        runner.git("worktree", "add", "--detach", str(worktree), base)
                        target = worktree / CATALOG_PATH
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(json.dumps(merged, sort_keys=True, indent=2) + "\n")
                        work = Runner(worktree, runner.deadline)
                        # Transport helper lives in this same revision's scripts.
                        work.git("add", "-f", CATALOG_PATH)
                        code, _ = work.run(["git", "diff", "--cached", "--quiet"], "source catalog diff", check=False)
                        if code == 0:
                            return False
                        if code != 1:
                            raise RuntimeError("cannot inspect source catalog transaction")
                        work.git("-c", "user.name=best50-bot", "-c",
                                 "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                                 "commit", "-m", "chore: update public primary source catalog")
                        runner.git("-C", str(worktree), "push", "origin", "HEAD:refs/heads/regional")
                        runner.git("fetch", "--quiet", "origin", "regional")
                        verified = parse_catalog(_git_blob(repo, CATALOG_REF), now)
                        verified_urls = {item["url"]: item for item in verified["sources"]}
                        if any(url not in verified_urls or verified_urls[url]["last_verified_at"] < item["last_verified_at"]
                               for url, item in ((entry["url"], entry) for entry in merged["sources"])):
                            raise RuntimeError("source catalog publication verification failed")
                        return True
                    finally:
                        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            except (CommandFailure, RuntimeError, OSError, subprocess.SubprocessError):
                if attempt == 2:
                    raise ResearchSourcesUnavailable("source catalog publication failed; pending research retained") from None
                time.sleep(2 ** (attempt + 1))
            finally:
                runner.stop()
    return False


def process_research_result(result_text: str, repo: Path, state_dir: Path, now: float, *,
                            discovered_by: str | None = None, model_id: str | None = None) -> dict:
    if discovered_by not in (None, "independent", "grok", "qwen"):
        raise ValueError("invalid source discoverer")
    if model_id is not None and not (
            discovered_by == "grok" and isinstance(model_id, str) and re.fullmatch(r"(?:cursor-)?grok-\d+(?:\.\d+)*-xhigh", model_id)
            or discovered_by == "qwen" and model_id == QWEN_MODEL):
        raise ValueError("invalid source discovery model")
    proposals, rejected = parse_proposal(result_text)
    reasons = Counter({"invalid-proposal": rejected} if rejected else {})
    try:
        current = parse_catalog(_git_blob(repo, CATALOG_REF), now)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        current = {"schema": 1, "generated_at": 0, "sources": []}
    known = {entry["url"]: entry for entry in current["sources"]}
    updates, accepted, transient, retry_at = [], 0, 0, 0
    with temporary_directory(prefix="bestlocal-feed-check-", parent=state_dir / "temporary") as temporary:
        pool = SourcePool([], Path(temporary) / "state.json", now=int(now))
        for item in proposals:
            previous = known.get(item["url"])
            if previous and previous["enabled"] and 0 <= now - previous["last_verified_at"] < REFRESH_SECONDS:
                accepted += 1
                continue
            try:
                if not pool.allowed(item["url"]):
                    rejected += 1
                    reasons["source-policy"] += 1
                    continue
                raw, _ = pool.get(item["url"])
                if not _has_compatible_configuration(decode_subscription(raw)):
                    rejected += 1
                    reasons["no-compatible-configuration"] += 1
                    continue
                update = {**item, "enabled": True, "first_seen": previous["first_seen"] if previous else now,
                          "last_verified_at": now}
                if previous:
                    update.update({key: previous[key] for key in ("discovered_by", "discovery_model") if key in previous})
                elif discovered_by is not None:
                    update["discovered_by"] = discovered_by
                    if model_id is not None:
                        update["discovery_model"] = model_id
                updates.append(update)
                accepted += 1
            except (RateLimited, SourcePolicyUnavailable) as exc:
                transient += 1
                reasons["rate-limit" if isinstance(exc, RateLimited) else "source-policy-unavailable"] += 1
                retry_at = max(retry_at, min(now + 86400, max(now + 60, exc.retry_at)))
            except (TimeoutError, OSError):
                transient += 1
                reasons["network"] += 1
            except RuntimeError as error:
                if str(error).startswith("source HTTP 4"):
                    rejected += 1
                    reasons["source-http-client-error"] += 1
                else:
                    transient += 1
                    reasons["source-unavailable"] += 1
            except (ValueError, TypeError, OverflowError):
                rejected += 1
                reasons["invalid-source"] += 1
    summary = {"accepted": accepted, "added": sum(entry["url"] not in known for entry in updates),
               "refreshed": sum(entry["url"] in known for entry in updates), "rejected": rejected,
               "rejection_reasons": dict(reasons)}
    try:
        published = publish_catalog(repo, state_dir, updates, now) if updates else False
    except ResearchSourcesUnavailable as exc:
        # Preserve validation observations even when the Git transaction fails.
        exc.summary = {**summary, "published": False}
        raise
    summary.update(published=published, already_current=not published)
    if transient:
        raise ResearchSourcesUnavailable("source validation is temporarily unavailable; pending suggestions retained", retry_at=retry_at, summary=summary, reason="network")
    return summary


def independent_proposal(state_dir: Path, now: float, repo: Path | None = None) -> str:
    """Propose recent productive feeds; all are independently fetched again.

    The regional registry is read only. A separate discovery registry is used
    when no productive regional registry exists, so this job never races the
    local candidate collector's state writer.
    """
    from regional_pool import PrivateSourcePool
    from regional_scheduler import atomic_json
    productive_by_url = {}
    for regional in (state_dir / "regional-discovery-state.json", state_dir / "serbia/regional-discovery-state.json"):
        try:
            pool = PrivateSourcePool([], regional, now=int(now))
            for item in pool.sources.values():
                if (item.get("candidate_count", 0) <= 0 or item.get("failures", 0) != 0
                        or not 0 <= now - item.get("last_success", 0) <= 2 * REFRESH_SECONDS):
                    continue
                url = canonical_url(item["url"])
                previous = productive_by_url.get(url)
                priority = lambda value: (value.get("last_success", 0), value.get("functional_ema", 0),
                                          value.get("last_functional_count", 0), value.get("candidate_count", 0))
                if previous is None or priority(item) > priority(previous):
                    productive_by_url[url] = item
        except (OSError, ValueError, RuntimeError):
            continue
    productive = list(productive_by_url.values())
    if not productive:
        fallback = state_dir / "source-fallback-discovery-state.json"
        pool = PrivateSourcePool([], fallback, now=int(now))
        pool.collect()
        productive = [item for item in pool.sources.values()
                      if item.get("candidate_count", 0) > 0 and item.get("failures", 0) == 0
                      and 0 <= now - item.get("last_success", 0) <= 2 * REFRESH_SECONDS]
        # PrivateSourcePool already persists collection; keep an atomic durable
        # snapshot with fsync for the standalone fallback registry as well.
        atomic_json(fallback, pool.state)
    try:
        known = {item["url"]: item for item in parse_catalog(_git_blob(repo, CATALOG_REF), now)["sources"]} if repo else {}
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        known = {}
    # Unknown feeds lead; stable useful ones still retain priority within each
    # group. Rotate equal-quality unknown feeds by day so a bounded proposal
    # does not permanently repeat the same lexicographic prefix.
    productive.sort(key=lambda item: (item["url"] in known,
                                     -item.get("functional_ema", 0),
                                     -item.get("last_functional_count", 0),
                                     known.get(item["url"], {}).get("last_verified_at", 0),
                                     hashlib.sha256(f"{int(now // REFRESH_SECONDS)}:{item['url']}".encode()).hexdigest()))
    sources, providers = [], Counter()
    for item in productive:
        url = canonical_url(item["url"])
        parsed = urlsplit(url)
        path = unquote(parsed.path)
        # Do not promote opaque credentials encountered inside public text.
        # Discovery may consume public format parameters; registry publication
        # deliberately requires a clearly credential-free URL.
        if (parsed.query or re.search(r"(?i)(?:^|/)(?:token|secret|private|password|auth|api[_-]?key)(?:[./_-]|$)", path)
                or re.search(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path)
                or any(len(part) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+", part) and any(char.isdigit() for char in part)
                       for part in path.split("/"))):
            continue
        provider = (parsed.hostname, tuple(parsed.path.split("/")[1:3])
                    if parsed.hostname == "raw.githubusercontent.com" else ())
        if providers[provider] >= 2:
            continue
        providers[provider] += 1
        sources.append({"url": url, "evidence_url": url})
        if len(sources) == 16:
            break
    return json.dumps({"schema": 1, "sources": sources}, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.result.stat().st_size > MAX_BYTES:
            raise ValueError("research result exceeds limit")
        result = process_research_result(args.result.read_text(), args.repo.resolve(), args.state_dir.resolve(), time.time())
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
        print("Source research validation/publication deferred; previous catalog retained", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
