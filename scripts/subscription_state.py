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
import tempfile
import time

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


def is_fresh_strict_status(status, now: float | None = None) -> bool:
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
                with tempfile.TemporaryDirectory(prefix="bestlocal-stale-") as directory:
                    worktree = Path(directory) / "checkout"
                    try:
                        runner.git("worktree", "add", "--detach", str(worktree), "origin/regional")
                        if is_fresh_strict_status(read_status(worktree / "output/local-status.json")):
                            print("Regional strict validation is fresh; retained subscription unchanged")
                            return False
                        target = worktree / "output/best-local.txt"
                        original = read_text(target)
                        marked = mark_stale_text(original)
                        if marked == original:
                            print("Regional retained subscription is already marked stale")
                            return False
                        target.write_text(marked, encoding="utf-8")
                        runner.git("-C", str(worktree), "add", "-f", "output/best-local.txt")
                        runner.git("-C", str(worktree), "-c", "user.name=best50-bot", "-c",
                                   "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                                   "commit", "-m", "chore: expose retained BestLocal staleness")
                        runner.git("-C", str(worktree), "push", "origin", "HEAD:refs/heads/regional")
                        print("Regional stale status published; connection configurations and generated time retained")
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
