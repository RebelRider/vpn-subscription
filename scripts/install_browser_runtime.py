#!/usr/bin/env python3
"""Install an owned, pinned Playwright browser without touching user browsers."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

from owned_temporary import cleanup_owned_temporary, temporary_directory

VERSION = "1.62.1"
RUNTIME = Path.home() / "Library/Application Support/best50-vpn/browser-runtime"
CACHE = Path.home() / "Library/Caches/best50-vpn/playwright"
BUNDLED_PACKAGES = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules"
TRANSACTION = "installation-transaction.json"


class InstallationBusy(RuntimeError):
    pass


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
        with (path / "package.json").open("rb") as stream:
            raw = stream.read(65537)
        return json.loads(raw)["version"] if len(raw) <= 65536 else None
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def vendor_environment(cache: Path) -> dict:
    # Neither a temporary control proxy nor inherited npm/Git authentication is
    # required to retrieve public official assets. This changes child env only.
    allowed = {"HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "SYSTEMROOT"}
    return {**{key: value for key, value in os.environ.items() if key in allowed},
            "PLAYWRIGHT_BROWSERS_PATH": str(cache)}


def _owned_directory(path: Path, *, create=False) -> None:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("Browser asset directory is not user-owned")


@contextmanager
def installation_locks(runtime: Path):
    _owned_directory(runtime, create=True)
    with ExitStack() as stack:
        for name in ("installation.lock", "browser.lock"):
            descriptor = os.open(runtime / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            handle = stack.enter_context(os.fdopen(descriptor, "a+b"))
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallationBusy("Owned browser assets are in use") from None
        yield


def _npm_cli(node: str) -> Path:
    for binary in (Path(node).absolute(), Path(node).resolve()):
        candidate = binary.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("Pinned package repair requires the existing Node npm CLI")


def _browser_details(runtime: Path, cache: Path, node: str):
    _owned_directory(runtime)
    _owned_directory(runtime / "node_modules")
    for name in ("playwright", "playwright-core"):
        _owned_directory(runtime / "node_modules" / name)
    if any(package_version(runtime / "node_modules" / name) != VERSION for name in ("playwright", "playwright-core")):
        raise RuntimeError("Pinned browser packages are incomplete")
    with (runtime / "node_modules/playwright-core/browsers.json").open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise RuntimeError("Pinned Chromium metadata exceeds limit")
    data = json.loads(raw)
    expected = next(item["browserVersion"] for item in data["browsers"] if item["name"] == "chromium")
    if not isinstance(expected, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", expected):
        raise RuntimeError("Invalid pinned Chromium metadata")
    result = subprocess.check_output([node, "-e", "process.stdout.write(require(process.argv[1]).chromium.executablePath())",
                                      str(runtime / "node_modules/playwright")],
                                     env=vendor_environment(cache), stderr=subprocess.DEVNULL, timeout=10, text=True)
    binary = Path(result)
    # Public package code cannot redirect validation to a user application.
    binary.relative_to(cache)
    return binary, expected


def _runtime_ready(runtime: Path, cache: Path, node: str) -> bool:
    try:
        binary, expected = _browser_details(runtime, cache, node)
        _owned_directory(cache)
        binary.resolve().relative_to(cache.resolve())
        if not binary.is_file() or not os.access(binary, os.X_OK):
            return False
        result = subprocess.check_output([str(binary), "--version"], env=vendor_environment(cache),
                                         stderr=subprocess.DEVNULL, timeout=10, text=True)
        return bool(re.search(r"(?:Chromium|Google Chrome(?: for Testing)?)\s+" + re.escape(expected) + r"(?:\s|$)", result.strip()))
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RuntimeError, RecursionError, subprocess.SubprocessError):
        return False


def _stage_packages(packages: Path, stage: Path, cache: Path, node: str) -> None:
    destination = stage / "node_modules"
    try:
        for name in ("playwright", "playwright-core"):
            if package_version(packages / name) != VERSION:
                raise RuntimeError("Pinned bundled package is unavailable")
            shutil.copytree(packages / name, destination / name)
        _browser_details(stage, cache, node)
        return
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RuntimeError, RecursionError, subprocess.SubprocessError):
        if destination.exists():
            shutil.rmtree(destination)
    # npm rejects loading /dev/null twice as user and global config. Distinct
    # empty private files preserve the intended absence of ambient npm config.
    configs = []
    for name in ("user.npmrc", "global.npmrc"):
        path = stage / name
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        configs.append(path)
    # Explicit pin, official registry, scripts disabled, no user npmrc or global
    # install/cache. A changed Codex bundle cannot strand the owned runtime.
    subprocess.run([node, str(_npm_cli(node)), "install", "--prefix", str(stage),
                    "--ignore-scripts", "--no-audit", "--no-fund", "--userconfig=" + str(configs[0]),
                    "--globalconfig=" + str(configs[1]), "--registry=https://registry.npmjs.org/",
                    "--cache", str(stage / "npm-cache"), "--package-lock=false", "--save=false",
                    "playwright@" + VERSION, "playwright-core@" + VERSION],
                   env=vendor_environment(cache), check=True, timeout=240,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _browser_details(stage, cache, node)


def _recover_transaction(runtime: Path, cache: Path, node: str) -> bool:
    transaction = runtime / TRANSACTION
    if not transaction.exists():
        return True
    try:
        if transaction.is_symlink() or transaction.stat().st_size > 4096:
            raise ValueError
        info = transaction.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError
        value = json.loads(transaction.read_text())
        if not isinstance(value, dict) or set(value) != {"schema", "backups"} or value["schema"] != 1:
            raise ValueError
        backups = value["backups"]
        if not isinstance(backups, dict) or set(backups) - {"modules", "cache"}:
            raise ValueError
        targets = {"modules": runtime / "node_modules", "cache": cache}
        parents = {"modules": runtime.parent / "temporary", "cache": cache.parent / "temporary"}
        checked = []
        for name, raw in backups.items():
            backup = Path(raw)
            parent = parents[name]
            workspace = backup.parent
            if (workspace.parent.resolve() != parent.resolve() or backup.name != "previous"
                    or not re.fullmatch(r"bestlocal-browser-install-[A-Za-z0-9_-]{6,}", workspace.name)):
                raise ValueError
            if backup.exists():
                _owned_directory(parent)
                _owned_directory(workspace)
                _owned_directory(backup)
                checked.append((targets[name], backup))
        if not _runtime_ready(runtime, cache, node):
            for target, backup in reversed(checked):
                if target.exists():
                    _owned_directory(target)
                    shutil.rmtree(target)
                os.replace(backup, target)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, RecursionError, subprocess.SubprocessError):
        # Preserve failed transactions and their backups until a complete new
        # installation succeeds. Neither malformed metadata nor failed I/O may
        # authorize the janitor to discard the remaining rollback copy.
        return False
    transaction.unlink(missing_ok=True)
    return True


def _recover_and_clean(runtime: Path, cache: Path, node: str) -> None:
    # Both installation locks must already be held. Generic janitors exclude
    # this kind: an old workspace may still hold the only rollback copy.
    if not _recover_transaction(runtime, cache, node):
        return
    for parent in {runtime.parent / "temporary", cache.parent / "temporary"}:
        try:
            cleanup_owned_temporary(parent, kinds={"bestlocal-browser-install-"})
        except (OSError, ValueError, RuntimeError):
            pass


def _install_locked(packages: Path, runtime: Path, cache: Path) -> None:
    node = find_node()
    if not node:
        raise RuntimeError("Node.js is unavailable")
    _recover_and_clean(runtime, cache, node)
    with temporary_directory(prefix="bestlocal-browser-install-", parent=runtime.parent / "temporary") as directory:
        stage = Path(directory)
        _stage_packages(packages, stage, cache, node)
        with temporary_directory(prefix="bestlocal-browser-install-", parent=cache.parent / "temporary") as cache_directory:
            staged_cache = Path(cache_directory) / "browser-cache"
            moves = [(runtime / "node_modules", stage / "node_modules", stage / "previous", "modules")]
            if not _runtime_ready(stage, cache, node):
                subprocess.run([node, str(stage / "node_modules/playwright/cli.js"), "install", "chromium", "--no-shell"],
                               env=vendor_environment(staged_cache), check=True, timeout=900,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if not _runtime_ready(stage, staged_cache, node):
                    raise RuntimeError("Downloaded Chromium failed version validation")
                moves.insert(0, (cache, staged_cache, Path(cache_directory) / "previous", "cache"))
            from regional_scheduler import atomic_json
            transaction = runtime / TRANSACTION
            atomic_json(transaction, {"schema": 1, "backups": {name: str(backup) for target, _, backup, name in moves if target.exists()}})
            try:
                for target, candidate, backup, _ in moves:
                    if target.exists():
                        _owned_directory(target)
                        os.replace(target, backup)
                    os.replace(candidate, target)
                if not _runtime_ready(runtime, cache, node):
                    raise RuntimeError("Installed browser failed validation")
                transaction.unlink(missing_ok=True)
            except BaseException:
                _recover_transaction(runtime, cache, node)
                raise


def install(packages: Path = BUNDLED_PACKAGES, runtime: Path = RUNTIME, cache: Path = CACHE) -> None:
    with installation_locks(runtime):
        _install_locked(packages, runtime, cache)


def ready() -> bool:
    node = find_node()
    return bool(node and _runtime_ready(RUNTIME, CACHE, node))


def ensure() -> bool:
    """Repair only owned browser assets, with bounded retry and no user profile."""
    status = RUNTIME / "installation-status.json"
    try:
        with installation_locks(RUNTIME):
            node = find_node()
            if node:
                _recover_and_clean(RUNTIME, CACHE, node)
            if ready():
                return True
            try:
                previous = json.loads(status.read_text()) if status.is_file() and status.stat().st_size <= 4096 else {}
                retry = previous.get("retry_at", 0) if isinstance(previous, dict) else 0
            except (OSError, ValueError, RecursionError):
                retry = 0
            now = time.time()
            if type(retry) in (int, float) and now < retry <= now + 6 * 3600:
                return False
            try:
                _install_locked(BUNDLED_PACKAGES, RUNTIME, CACHE)
                success = ready()
            except (OSError, RuntimeError, subprocess.SubprocessError):
                success = False
            from regional_scheduler import atomic_json
            atomic_json(status, {"last_attempt": now, "ready": success, "retry_at": 0 if success else now + 3600})
            return success
    except InstallationBusy:
        return False


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
