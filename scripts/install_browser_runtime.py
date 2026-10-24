#!/usr/bin/env python3
"""Install an owned, pinned Playwright browser without touching user browsers."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

VERSION = "1.62.1"
RUNTIME = Path.home() / "Library/Application Support/best50-vpn/browser-runtime"
CACHE = Path.home() / "Library/Caches/best50-vpn/playwright"
BUNDLED_PACKAGES = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules"


def find_node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    paths = list((Path.home() / ".nvm/versions/node").glob("*/bin/node"))
    def version(path):
        try:
            return tuple(int(part) for part in path.parents[1].name.lstrip("v").split("."))
        except ValueError:
            return ()
    return str(max(paths, key=version)) if paths else None


def package_version(path: Path) -> str | None:
    try:
        return json.loads((path / "package.json").read_text())["version"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def install(packages: Path = BUNDLED_PACKAGES, runtime: Path = RUNTIME, cache: Path = CACHE) -> None:
    node = find_node()
    if not node:
        raise RuntimeError("Node.js is unavailable")
    for name in ("playwright", "playwright-core"):
        source = packages / name
        destination = runtime / "node_modules" / name
        if destination.exists() and package_version(destination) != VERSION:
            raise RuntimeError("Owned browser runtime contains a different version; refusing overwrite")
        if not destination.exists():
            if package_version(source) != VERSION:
                raise RuntimeError("Pinned official Playwright packages are unavailable")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)
    cache.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PLAYWRIGHT_BROWSERS_PATH"] = str(cache)
    # Use the pinned official installer's HTTPS download/archive extraction.
    # No global/npm installation or existing browser profile is used.
    subprocess.run([node, str(runtime / "node_modules/playwright/cli.js"), "install", "chromium", "--no-shell"],
                   env=environment, check=True, timeout=900)


def ready() -> bool:
    node = find_node()
    if not node or any(package_version(RUNTIME / "node_modules" / name) != VERSION for name in ("playwright", "playwright-core")):
        return False
    try:
        environment = {**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(CACHE)}
        result = subprocess.check_output([node, "-e", "process.stdout.write(require(process.argv[1]).chromium.executablePath())", str(RUNTIME / "node_modules/playwright")],
                                         env=environment, stderr=subprocess.DEVNULL, timeout=10, text=True)
        binary = Path(result)
        return binary.is_file() and os.access(binary, os.X_OK)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def ensure() -> bool:
    """Repair only owned browser assets, with bounded retry and no user profile."""
    if ready():
        return True
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    status = RUNTIME / "installation-status.json"
    with (RUNTIME / "installation.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        try:
            previous = json.loads(status.read_text()) if status.is_file() and status.stat().st_size <= 4096 else {}
            retry = previous.get("retry_at", 0) if isinstance(previous, dict) else 0
        except (OSError, ValueError, RecursionError):
            retry = 0
        now = time.time()
        if type(retry) in (int, float) and now < retry <= now + 6 * 3600:
            return False
        try:
            install()
            success = ready()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            success = False
        from regional_scheduler import atomic_json
        atomic_json(status, {"last_attempt": now, "ready": success, "retry_at": 0 if success else now + 3600})
        return success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, default=BUNDLED_PACKAGES)
    args = parser.parse_args()
    try:
        install(args.packages)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("Owned browser installation failed: " + type(error).__name__)
        return 1
    print("Installed owned Playwright " + VERSION + " Chromium runtime")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
