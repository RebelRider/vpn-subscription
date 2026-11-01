#!/usr/bin/env python3
"""Expose retained BestLocal staleness without changing any connection URI."""
from __future__ import annotations

import argparse
from datetime import datetime
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_temporary import temporary_directory
from subscription_presentation import title as presentation_title

MAX_BYTES = 1024 * 1024
MAX_AGE_SECONDS = 6 * 3600
HEALTH_URL = "https://raw.githubusercontent.com/RebelRider/vpn-subscription/regional/output/local-health.json"
STALE_TITLE = "#profile-title: Best Local VPN [STALE - no verified servers]"
STALE_HEADERS = (STALE_TITLE, "#bestlocal-status: stale; retained configurations are not currently verified",
                 "#bestlocal-health-url: " + HEALTH_URL)


def read_text(path: Path) -> str:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Retained subscription/state exceeds size limit")
    return raw.decode("utf-8")


def connection_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def mark_stale_text(text: str) -> str:
    """Change owned comments only, preserving URIs and original generated time."""
    if not connection_lines(text):
        raise ValueError("Cannot annotate an empty subscription")
    owned = ("#profile-title:", "#bestlocal-status:", "#bestlocal-health-url:")
    retained = "".join(line for line in text.splitlines(keepends=True)
                       if not line.lstrip().lower().startswith(owned))
    return "\n".join(STALE_HEADERS) + "\n" + retained


def apply_presentation(text: str, status: dict, now: float | None = None) -> str:
    """Annotate the existing publication's age, never the failed attempt's time.

    This is deliberately separate from the six-hour newer-writer guard. Missing
    or corrupt metadata fails closed to an undated STALE title, preserving the
    original generated comment and every connection byte.
    """
    if not connection_lines(text):
        raise ValueError("Cannot annotate an empty subscription")
    try:
        if not isinstance(status, dict) or status.get("algorithm") != "bestlocal-strict-services-v6":
            raise RuntimeError("Invalid publication policy")
        nodes, stability = status.get("nodes"), status.get("stability")
        if (not isinstance(nodes, list) or not nodes or not all(isinstance(node, dict) for node in nodes)
                or not isinstance(stability, dict) or type(stability.get("qualified")) is not int
                or stability["qualified"] != len(nodes)):
            raise RuntimeError("Invalid publication inventory")
        title = presentation_title(status, now=now)
    except (RuntimeError, ValueError, TypeError, OverflowError):
        return mark_stale_text(text)
    if status.get("retained_nodes"):
        headers = (title, "#bestlocal-status: mixed; retained entries are not currently verified", STALE_HEADERS[2])
    elif "[STALE - " in title:
        headers = (title, STALE_HEADERS[1], STALE_HEADERS[2])
    else:
        headers = (title,)
    owned = ("#profile-title:", "#bestlocal-status:", "#bestlocal-health-url:")
    existing = [line for line in text.splitlines() if line.lstrip().lower().startswith(owned)]
    if existing == list(headers):
        return text
    retained = "".join(line for line in text.splitlines(keepends=True)
                       if not line.lstrip().lower().startswith(owned))
    return "\n".join(headers) + "\n" + retained


def has_fresh_validation(status, now: float | None = None) -> bool:
    """Fresh subset timestamp, also used to protect newer mixed writers."""
    now = time.time() if now is None else now
    try:
        if not isinstance(status, dict) or status.get("algorithm") != "bestlocal-strict-services-v6":
            return False
        raw = status.get("generated_at")
        if not isinstance(raw, str):
            return False
        generated = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if generated.tzinfo is None:
            return False
        epoch = generated.timestamp()
        if not math.isfinite(epoch) or not 0 < epoch <= now + 300 or not now - epoch < MAX_AGE_SECONDS:
            return False
        nodes, stability = status.get("nodes"), status.get("stability")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= 50 or not all(isinstance(node, dict) for node in nodes):
            return False
        count = stability.get("qualified") if isinstance(stability, dict) else None
        return isinstance(count, int) and not isinstance(count, bool) and count == len(nodes)
    except (ValueError, TypeError, OverflowError):
        return False


def is_fresh_strict_status(status, now: float | None = None) -> bool:
    """The complete artifact is fresh only when it contains no retained entries."""
    return has_fresh_validation(status, now) and not status.get("retained_nodes")


def read_status(path: Path) -> dict:
    try:
        value = json.loads(read_text(path))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}


def mark_regional(repo: Path, runner=None) -> bool:
    """Annotate stale retained regional output; ordinary push serializes writers."""
    if runner is None:
        spec = importlib.util.spec_from_file_location("subscription_scheduler", Path(__file__).with_name("regional_scheduler.py"))
        scheduler = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scheduler)
        runner = scheduler.Runner(repo.resolve(), time.monotonic() + 10 * 60)
    try:
        for attempt in range(3):
            try:
                runner.git("fetch", "--quiet", "--no-tags", "origin", "regional")
                with temporary_directory(prefix="bestlocal-stale-", repo=repo) as directory:
                    worktree = Path(directory) / "checkout"
                    try:
                        runner.git("worktree", "add", "--detach", str(worktree), "origin/regional")
                        published_status = read_status(worktree / "output/local-status.json")
                        if has_fresh_validation(published_status) and "presentation_version" not in published_status:
                            print("Regional strict validation is fresh; retained subscription unchanged")
                            return False
                        target = worktree / "output/best-local.txt"
                        original = read_text(target)
                        marked = apply_presentation(original, published_status)
                        if marked == original:
                            print("Regional subscription validation age is already displayed")
                            return False
                        target.write_text(marked, encoding="utf-8")
                        runner.git("-C", str(worktree), "add", "-f", "output/best-local.txt")
                        runner.git("-C", str(worktree), "-c", "user.name=best50-bot", "-c",
                                   "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                                   "commit", "-m", "chore: expose retained BestLocal staleness")
                        runner.git("-C", str(worktree), "push", "origin", "HEAD:refs/heads/regional")
                        print("Regional validation age published; connection configurations and generated time retained")
                        return True
                    finally:
                        if worktree.exists():
                            # Cleanup has its own budget, including when the
                            # publishing runner exhausted its deadline.
                            try:
                                subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
                            except (OSError, subprocess.SubprocessError):
                                print("Owned stale annotation worktree cleanup could not complete")
            except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
                if attempt == 2:
                    raise
                print("Stale annotation publication failed; retrying against current regional branch")
                time.sleep(2 ** (attempt + 1))
    finally:
        runner.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mark-regional", action="store_true", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        mark_regional(args.repo)
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        print("Unable to publish retained subscription status; existing configurations preserved")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
