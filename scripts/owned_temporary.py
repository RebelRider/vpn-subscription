"""Leased, private temporary directories with conservative crash recovery.

Only marked directories below this system's dedicated temporary root are ever
eligible. A kernel lease, rather than a PID or directory age, protects live work.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

DEFAULT_PARENT = Path.home() / "Library/Application Support/best50-vpn/temporary"
MARKER = ".bestlocal-temporary.json"
LEASE = ".bestlocal-temporary.lock"
KNOWN_PREFIXES = frozenset({
    "source-research-workspace-", "bestlocal-source-publish-",
    "bestlocal-feed-check-", "best50-regional-publish-", "bestlocal-health-",
    "bestlocal-stale-", "bestlocal-browser-", "bestlocal-service-",
    "bestlocal-browser-install-", "bestlocal-control-",
})


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("temporary root is not an owned directory")
    os.chmod(path, 0o700)


def _check_private_regular(info: os.stat_result, *, maximum: int = 4096) -> os.stat_result:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > maximum):
        raise ValueError("invalid temporary ownership metadata")
    return info


def _private_regular(path: Path, *, maximum: int = 4096) -> os.stat_result:
    return _check_private_regular(path.lstat(), maximum=maximum)


def _record(directory: Path, now: float) -> dict:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("invalid temporary directory")
    try:
        descriptor = os.open(directory / MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("temporary ownership metadata cannot be safely opened") from None
    with os.fdopen(descriptor, "rb") as handle:
        # Validate the opened inode, rather than lstat followed by an open
        # which could follow a replacement symlink or block on a FIFO.
        _check_private_regular(os.fstat(handle.fileno()))
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("oversized temporary ownership metadata")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"schema", "owner", "created_at", "kind", "repo"}:
        raise ValueError("invalid temporary ownership metadata")
    created = value["created_at"]
    if (type(value["schema"]) is not int or value["schema"] != 1
            or type(value["owner"]) is not int or value["owner"] != os.getuid()
            or value["kind"] not in KNOWN_PREFIXES
            or not re.fullmatch(re.escape(value["kind"]) + r"[A-Za-z0-9_-]{6,}", directory.name)
            or type(created) not in (int, float) or not math.isfinite(created)
            or not 0 < created <= now + 300
            or value["repo"] is not None and not isinstance(value["repo"], str)):
        raise ValueError("invalid temporary ownership metadata")
    return value


def _registered_worktrees(repo: Path) -> set[Path]:
    # Use an anonymous bounded output file; no Git networking or global pruning.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(["git", "worktree", "list", "--porcelain", "-z"], cwd=repo,
                                stdout=output, stderr=subprocess.DEVNULL, timeout=10, check=False)
        if result.returncode or output.tell() > 1024 * 1024:
            raise RuntimeError("cannot inspect owned temporary worktrees")
        output.seek(0)
        raw = output.read(1024 * 1024 + 1)
    return {Path(os.fsdecode(item[len(b"worktree "):])).resolve() for item in raw.split(b"\0")
            if item.startswith(b"worktree ")}


def _dispose(directory: Path, record: dict, repositories: set[str]) -> None:
    if directory.is_symlink():
        raise ValueError("owned temporary directory became a symlink")
    # Git canonicalizes macOS /var -> /private/var aliases in its registry.
    # Compare the same identities before authorizing a checkout removal.
    directory = directory.resolve()
    repository = record["repo"]
    authorized_checkout = None
    if repository is not None:
        if repository not in repositories:
            raise ValueError("temporary repository is not explicitly authorized")
        repo = Path(repository)
        checkout = directory / "checkout"
        if checkout.is_symlink():
            raise ValueError("owned temporary checkout became a symlink")
        registered = _registered_worktrees(repo)
        nested = {path for path in registered if path == directory or directory in path.parents}
        if nested - {checkout}:
            raise ValueError("unexpected worktree in temporary directory")
        if checkout in registered:
            def common_directory(path):
                raw = subprocess.check_output(["git", "rev-parse", "--git-common-dir"], cwd=path,
                                              stderr=subprocess.DEVNULL, timeout=10).strip()
                value = Path(os.fsdecode(raw))
                return (value if value.is_absolute() else path / value).resolve()
            if common_directory(checkout) != common_directory(repo):
                raise ValueError("temporary checkout metadata points to an unrelated repository")
            authorized_checkout = checkout
        elif (checkout / ".git").exists() or (checkout / ".git").is_symlink():
            raise ValueError("temporary checkout is not registered to the authorized repository")
    # Ownership of the outer scratch directory does not grant permission to
    # delete an unrelated repository later placed inside it. Do not follow
    # symlinks, and keep this defensive scan bounded even for corrupt state.
    pending, examined = [directory], 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                examined += 1
                if examined > 10000:
                    raise ValueError("temporary cleanup inspection budget exceeded")
                if entry.name == ".git":
                    if (authorized_checkout is not None
                            and Path(entry.path) == authorized_checkout / ".git"
                            and entry.is_file(follow_symlinks=False)):
                        continue
                    raise ValueError("unrelated Git data in temporary directory")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
    if repository is not None and authorized_checkout is not None:
        checkout = authorized_checkout
        repo = Path(repository)
        if checkout in registered:
            removed = subprocess.run(["git", "worktree", "remove", "--force", str(checkout)], cwd=repo,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=30, check=False)
            if removed.returncode or checkout in _registered_worktrees(repo):
                raise RuntimeError("owned temporary worktree cleanup deferred")
    shutil.rmtree(directory)


@contextmanager
def temporary_directory(*, prefix: str, parent: Path | str | None = None,
                        repo: Path | str | None = None):
    """Yield a private directory path, keeping its cleanup lease until exit.

    Git callers put their detached worktree in the returned directory's
    ``checkout`` child and pass the exact repository that registers it.
    """
    if prefix not in KNOWN_PREFIXES:
        raise ValueError("unknown owned temporary kind")
    root = Path(parent) if parent is not None else DEFAULT_PARENT
    _private_directory(root)
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    repository = str(Path(repo).resolve()) if repo is not None else None
    record = {"schema": 1, "owner": os.getuid(), "created_at": time.time(),
              "kind": prefix, "repo": repository}
    lease = None
    try:
        descriptor = os.open(directory / LEASE, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        lease = os.fdopen(descriptor, "a+b")
        fcntl.flock(lease, fcntl.LOCK_EX)
        descriptor = os.open(directory / MARKER, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            json.dump(record, handle, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield str(directory)
    finally:
        try:
            if lease is not None:
                _dispose(directory, record, {repository} if repository is not None else set())
            elif directory.exists():
                shutil.rmtree(directory)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            # Keep the marker for the next janitor instead of hiding the
            # caller's result or exception behind optional housekeeping.
            logging.warning("Owned temporary cleanup deferred; marked resources retained for recovery")
        finally:
            if lease is not None:
                lease.close()


def cleanup_owned_temporary(parent: Path | str | None = None, *, repos=(), now: float | None = None,
                            minimum_age: float = 2 * 3600, maximum_entries: int = 256, kinds=None) -> dict:
    """Reclaim only old, marked, unlocked directories in the dedicated root."""
    root = Path(parent) if parent is not None else DEFAULT_PARENT
    result = {"examined": 0, "removed": 0, "active": 0, "invalid": 0, "failed": 0, "limited": False}
    if not root.exists():
        return result
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("temporary root is not a private owned directory")
    if not 1 <= maximum_entries <= 4096 or not math.isfinite(minimum_age) or minimum_age < 2 * 3600:
        raise ValueError("invalid temporary cleanup budget")
    now = time.time() if now is None else now
    repositories = {str(Path(repo).resolve()) for repo in repos}
    eligible = KNOWN_PREFIXES - {"bestlocal-browser-install-"} if kinds is None else frozenset(kinds)
    if not eligible <= KNOWN_PREFIXES:
        raise ValueError("unknown temporary cleanup kind")
    with os.scandir(root) as entries:
        for entry in entries:
            if result["examined"] >= maximum_entries:
                result["limited"] = True
                break
            result["examined"] += 1
            directory = Path(entry.path)
            lease = None
            try:
                record = _record(directory, now)
                # Installation backups may be referenced by a durable swap
                # transaction. Only the installer, under its locks and after
                # rollback/recovery, explicitly opts into reclaiming them.
                if record["kind"] not in eligible:
                    continue
                if now - record["created_at"] <= minimum_age:
                    continue
                before = _private_regular(directory / LEASE)
                descriptor = os.open(directory / LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                lease = os.fdopen(descriptor, "rb")
                if (before.st_dev, before.st_ino) != (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino):
                    raise ValueError("temporary lease changed")
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    result["active"] += 1
                    continue
                # Re-read ownership after acquiring the lease. PID reuse and
                # forged process timestamps are irrelevant to this lock.
                record = _record(directory, now)
                _dispose(directory, record, repositories)
                result["removed"] += 1
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                result["invalid"] += 1
            except (OSError, RuntimeError, subprocess.SubprocessError):
                result["failed"] += 1
            finally:
                if lease is not None:
                    lease.close()
    return result
