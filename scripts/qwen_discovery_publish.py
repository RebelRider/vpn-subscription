"""Allowlisted Qwen discovery audit publication and deterministic source admission.

The PR is an audit trail, not a manual approval gate. Source admission independently
refetches public originals; neither this module nor the model publishes VPN nodes.
"""
from __future__ import annotations

from datetime import datetime
import fcntl
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))

import source_catalog
from qwen_discovery_tools import privacy_url, MODEL_ID, MAX_PUBLIC_BYTES, LAST_PUBLISHED
from regional_scheduler import Runner, atomic_json
from owned_temporary import temporary_directory

BRANCH = "discovery/qwen"
DATA_PATH = "discovery/qwen/candidates.json"
REPOSITORY = "RebelRider/vpn-subscription"
MAX_NEW_SOURCES = 8
PENDING = "qwen-discovery-publish-pending.json"
PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "socks"})
HASH = re.compile(r"[a-f0-9]{64}")


class DiscoveryPublishFailure(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in {"authentication", "git-transport", "data-invalid", "branch-not-data-only",
                                          "pr-unavailable", "busy", "admission-busy", "admission-unavailable"} else "git-transport"
        super().__init__(self.reason)


def _number(value, now):
    return type(value) in (int, float) and math.isfinite(value) and 0 < value <= now + 300


def validate_metadata(value, *, now=None):
    now = time.time() if now is None else now
    if (not isinstance(value, dict) or set(value) != {"schema", "worker", "model", "generated_at", "unverified_inputs", "sources", "candidates"}
            or type(value["schema"]) is not int or value["schema"] != 1 or value["worker"] != "qwen"
            or value["model"] != MODEL_ID or value["unverified_inputs"] is not True or not _number(value["generated_at"], now)
            or not isinstance(value["sources"], list) or len(value["sources"]) > 64
            or not isinstance(value["candidates"], list) or len(value["candidates"]) > 256):
        raise DiscoveryPublishFailure("data-invalid")
    sources, candidates = {}, {}
    try:
        for row in value["sources"]:
            if (not isinstance(row, dict) or set(row) != {"url", "evidence_url", "fetched_at", "body_sha256", "candidate_count", "serbia_hint_unverified"}
                    or not _number(row["fetched_at"], now) or not isinstance(row["body_sha256"], str) or not HASH.fullmatch(row["body_sha256"])
                    or type(row["candidate_count"]) is not int or not 1 <= row["candidate_count"] <= 256
                    or type(row["serbia_hint_unverified"]) is not bool):
                raise ValueError()
            url, evidence = privacy_url(row["url"]), privacy_url(row["evidence_url"])
            if url in sources:
                raise ValueError()
            sources[url] = {**row, "url": url, "evidence_url": evidence}
        for row in value["candidates"]:
            if (not isinstance(row, dict) or set(row) != {"id", "protocol", "source_url", "observed_at", "source_body_sha256", "serbia_hint_unverified"}
                    or not isinstance(row["id"], str) or not HASH.fullmatch(row["id"])
                    or row["protocol"] not in PROTOCOLS or not _number(row["observed_at"], now)
                    or type(row["serbia_hint_unverified"]) is not bool):
                raise ValueError()
            url = privacy_url(row["source_url"])
            if url not in sources or row["source_body_sha256"] != sources[url]["body_sha256"] or row["id"] in candidates:
                raise ValueError()
            candidates[row["id"]] = {**row, "source_url": url}
    except (ValueError, TypeError, KeyError, OverflowError):
        raise DiscoveryPublishFailure("data-invalid") from None
    result = {"schema": 1, "worker": "qwen", "model": MODEL_ID, "generated_at": value["generated_at"],
              "unverified_inputs": True, "sources": [sources[key] for key in sorted(sources)],
              "candidates": [candidates[key] for key in sorted(candidates)]}
    if len(json.dumps(result).encode()) > MAX_PUBLIC_BYTES:
        raise DiscoveryPublishFailure("data-invalid")
    return result


def _new_data(previous, current):
    if previous is None:
        return bool(current["sources"] or current["candidates"])
    old_urls = {row["url"] for row in previous["sources"]}
    old_ids = {row["id"] for row in previous["candidates"]}
    return any(row["url"] not in old_urls for row in current["sources"]) or any(row["id"] not in old_ids for row in current["candidates"])


def _merge_metadata(previous, current, now):
    """Retain bounded recent observations; never resurrect mismatched body proof."""
    if previous is None:
        return current
    sources = {row["url"]: row for row in previous["sources"] if row["fetched_at"] >= now - 7 * 86400}
    for row in current["sources"]:
        if row["url"] not in sources or sources[row["url"]]["fetched_at"] <= row["fetched_at"]:
            sources[row["url"]] = row
    chosen = sorted(sources.values(), key=lambda row: (-row["fetched_at"], row["url"]))[:64]
    sources = {row["url"]: row for row in chosen}
    candidates = {}
    for row in previous["candidates"] + current["candidates"]:
        source = sources.get(row["source_url"])
        if (source is None or row["observed_at"] < now - 7 * 86400
                or row["source_body_sha256"] != source["body_sha256"]):
            continue
        old = candidates.get(row["id"])
        if old is None or old["observed_at"] <= row["observed_at"]:
            candidates[row["id"]] = row
    kept = sorted(candidates.values(), key=lambda row: (-row["observed_at"], row["id"]))[:256]
    return validate_metadata({**current, "sources": list(sources.values()), "candidates": kept}, now=now)


def _read_git_data(runner, ref):
    try:
        oid = runner.git("rev-parse", "--verify", ref + ":" + DATA_PATH)
        if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", oid):
            raise ValueError()
        length = int(runner.git("cat-file", "-s", oid))
        if not 0 < length <= MAX_PUBLIC_BYTES:
            raise ValueError()
        return json.loads(runner.git("cat-file", "blob", oid))
    except (RuntimeError, ValueError, TypeError, subprocess.SubprocessError):
        return None


def _pr(runner, directory):
    try:
        _, output = runner.run(["gh", "pr", "list", "--repo", REPOSITORY, "--head", BRANCH,
                                "--base", "main", "--state", "open", "--json", "url", "--limit", "1"],
                               "Qwen discovery PR lookup", 45)
        rows = json.loads(output)
        url = rows[0]["url"] if isinstance(rows, list) and rows else None
        if url is None:
            body = Path(directory) / "pull-request-body.md"
            body.write_text("Public source observations and candidate fingerprints from the local discovery worker.\n\n"
                            "All entries are unverified data. Candidate credentials and local paths are omitted. "
                            "Source admission independently refetches public originals; production nodes still require "
                            "the existing functional, local-service, latency and exit-country validation. "
                            "This PR is an audit trail and is not a manual prerequisite for source discovery.\n", encoding="utf-8")
            body.chmod(0o600)
            _, output = runner.run(["gh", "pr", "create", "--repo", REPOSITORY, "--head", BRANCH,
                                    "--base", "main", "--title", "chore: review public VPN discovery observations",
                                    "--body-file", str(body)], "Qwen discovery PR creation", 60)
            url = output.strip()
        if not isinstance(url, str) or not re.fullmatch(r"https://github\.com/RebelRider/vpn-subscription/pull/[0-9]+", url):
            raise ValueError()
        return url
    except (RuntimeError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise DiscoveryPublishFailure("pr-unavailable") from None


def publish_discovery(repo: Path, state_dir: Path, metadata, *, now=None, runner_factory=None, create_pr=True):
    now = time.time() if now is None else now
    metadata = validate_metadata(metadata, now=now)
    state_dir = Path(state_dir); state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not metadata["sources"] and not metadata["candidates"]:
        return {"published": False, "branch": BRANCH, "pr_url": None, "reason": "empty"}
    factory = Runner if runner_factory is None else runner_factory
    with (state_dir / "qwen-discovery-publication.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DiscoveryPublishFailure("busy") from None
        atomic_json(state_dir / PENDING, metadata)
        runner = factory(Path(repo), time.monotonic() + 300)
        try:
            if create_pr:
                code, output = runner.run(["gh", "api", "repos/" + REPOSITORY, "--jq", ".permissions.push"],
                                          "Qwen discovery GitHub authorization", 30, check=False)
                if code or output.strip() != "true":
                    raise DiscoveryPublishFailure("authentication")
            for attempt in range(3):
                try:
                    runner.git("fetch", "--quiet", "--no-tags", "origin", "main")
                    remote = runner.git("ls-remote", "--heads", "origin", "refs/heads/" + BRANCH)
                    if remote:
                        runner.git("fetch", "--quiet", "--no-tags", "origin", BRANCH)
                        base = runner.git("rev-parse", "refs/remotes/origin/" + BRANCH)
                        paths = runner.git("diff", "--name-only", "origin/main..." + base).splitlines()
                        if set(paths) - {DATA_PATH}:
                            raise DiscoveryPublishFailure("branch-not-data-only")
                        raw = _read_git_data(runner, base)
                        previous = validate_metadata(raw, now=now) if raw is not None else None
                    else:
                        base = runner.git("rev-parse", "refs/remotes/origin/main")
                        previous = None
                        paths = []
                    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", base):
                        raise DiscoveryPublishFailure("git-transport")
                    changed = _new_data(previous, metadata)
                    updated = _merge_metadata(previous, metadata, now) if changed else previous
                    with temporary_directory(prefix="bestlocal-source-publish-", parent=state_dir / "temporary", repo=Path(repo)) as directory:
                        worktree = Path(directory) / "checkout"
                        try:
                            if changed:
                                runner.git("worktree", "add", "--detach", str(worktree), base)
                                target = worktree / DATA_PATH
                                target.parent.mkdir(parents=True, exist_ok=True)
                                owned_parts = [worktree.joinpath(*Path(DATA_PATH).parts[:index]) for index in range(1, len(Path(DATA_PATH).parts) + 1)]
                                if any(path.is_symlink() for path in owned_parts):
                                    raise DiscoveryPublishFailure("branch-not-data-only")
                                target.write_text(json.dumps(updated, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                                runner.git("-C", str(worktree), "add", "--", DATA_PATH)
                                staged = runner.git("-C", str(worktree), "diff", "--cached", "--name-only").splitlines()
                                if set(staged) != {DATA_PATH}:
                                    raise DiscoveryPublishFailure("branch-not-data-only")
                                runner.git("-C", str(worktree), "-c", "commit.gpgsign=false", "-c", "user.name=best50-bot", "-c",
                                           "user.email=41898282+github-actions[bot]@users.noreply.github.com", "commit", "-m",
                                           "chore: record public VPN discovery observations")
                                runner.git("-C", str(worktree), "push", "origin", "HEAD:refs/heads/" + BRANCH)
                                runner.git("fetch", "--quiet", "--no-tags", "origin", BRANCH)
                                verified = validate_metadata(_read_git_data(runner, "refs/remotes/origin/" + BRANCH), now=now)
                                if verified != updated:
                                    raise DiscoveryPublishFailure("git-transport")
                            pr_url = _pr(runner, directory) if create_pr and (changed or paths) else None
                            if updated is not None:
                                atomic_json(state_dir / LAST_PUBLISHED, updated)
                            (state_dir / PENDING).unlink(missing_ok=True)
                            return {"published": changed, "branch": BRANCH, "pr_url": pr_url,
                                    "reason": "published" if changed else "already-current"}
                        finally:
                            if worktree.exists():
                                subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
                except DiscoveryPublishFailure:
                    raise
                except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                    if any(marker in str(error).lower() for marker in ("authentication failed", "permission denied", "bad credentials", "could not read username")):
                        raise DiscoveryPublishFailure("authentication") from None
                    if attempt == 2:
                        raise DiscoveryPublishFailure("git-transport") from None
                    time.sleep(2 ** (attempt + 1))
        finally:
            runner.stop()


def promote_sources(proposal, repo: Path, state_dir: Path, *, now=None, model_id=MODEL_ID):
    """Reserve at most eight new URLs per Moscow day, replaying failed admissions.

    Reservations precede network publication. An interruption can defer admission,
    but cannot accidentally exceed the daily limit; the same proposal can retry.
    """
    now = time.time() if now is None else now
    if model_id != MODEL_ID:
        raise DiscoveryPublishFailure("data-invalid")
    if isinstance(proposal, str):
        text = proposal
    else:
        text = json.dumps(proposal, allow_nan=False)
    rows, invalid = source_catalog.parse_proposal(text)
    public_rows = []
    for row in rows:
        try:
            public_rows.append({"url": privacy_url(row["url"]), "evidence_url": privacy_url(row["evidence_url"])})
        except ValueError:
            invalid += 1
    state_dir = Path(state_dir); state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state_dir / "qwen-source-admission.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DiscoveryPublishFailure("admission-busy") from None
        today = datetime.fromtimestamp(now, ZoneInfo("Europe/Moscow")).date().isoformat()
        path = state_dir / "qwen-source-admissions.json"
        ledger = {"schema": 1, "day": today, "urls": [], "used": 0}
        try:
            if path.exists():
                if path.is_symlink() or path.stat().st_size > 32768:
                    raise ValueError()
                previous = json.loads(path.read_text())
                if (not isinstance(previous, dict) or set(previous) != {"schema", "day", "urls", "used"}
                        or previous["schema"] != 1 or not isinstance(previous["day"], str)
                        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", previous["day"])
                        or type(previous["used"]) is not int or not 0 <= previous["used"] <= MAX_NEW_SOURCES
                        or not isinstance(previous["urls"], list) or len(previous["urls"]) > previous["used"]):
                    raise ValueError()
                if previous["day"] == today:
                    previous["urls"] = list({privacy_url(url) for url in previous["urls"]})
                    ledger = previous
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            ledger["used"] = MAX_NEW_SOURCES
        try:
            catalog = source_catalog.parse_catalog(source_catalog._git_blob(Path(repo), source_catalog.CATALOG_REF), now)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            catalog = {"sources": []}
        known = {row["url"] for row in catalog["sources"]}
        allowed, deferred = [], []
        for row in public_rows:
            if row["url"] in known or row["url"] in ledger["urls"]:
                allowed.append(row)
            elif ledger["used"] < MAX_NEW_SOURCES:
                ledger["urls"].append(row["url"]); ledger["used"] += 1
                allowed.append(row)
            else:
                deferred.append(dict(row))
        atomic_json(path, ledger)
        if not allowed:
            return {"accepted": 0, "added": 0, "refreshed": 0, "rejected": invalid,
                    "published": False, "already_current": True, "budget_deferred": len(deferred),
                    "deferred_sources": deferred}
        result = source_catalog.process_research_result(json.dumps({"schema": 1, "sources": allowed}),
            Path(repo), state_dir, now, discovered_by="qwen", model_id=MODEL_ID)
        result["budget_deferred"] = len(deferred)
        result["deferred_sources"] = deferred
        result["rejected"] += invalid
        return result
