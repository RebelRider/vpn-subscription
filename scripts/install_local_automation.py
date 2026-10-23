#!/usr/bin/env python3
"""Install the BestLocal launchd files; loading requires explicit --load."""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

LABEL = "com.rebelrider.best50-regional-refresh"


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def launchd_configuration(home: Path, repo: Path, python: Path) -> dict:
    state_dir = home / "Library/Application Support/best50-vpn"
    logs = home / "Library/Logs/best50-vpn"
    return {
        "Label": LABEL,
        "ProgramArguments": ["/bin/bash", str(state_dir / "regional-bootstrap.sh")],
        "EnvironmentVariables": {
            "BEST50_REPO": str(repo),
            "BEST50_PYTHON": str(python),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "StartInterval": 900,
        "ProcessType": "Background",
        "ThrottleInterval": 30,
        "ExitTimeOut": 15,
        "AbandonProcessGroup": False,
        "StandardOutPath": str(logs / "regional-refresh.log"),
        "StandardErrorPath": str(logs / "regional-refresh-error.log"),
    }


def install(home: Path, repo: Path, python: Path, *, load: bool = False) -> Path:
    scheduler = repo / "scripts/regional_scheduler.py"
    if not scheduler.is_file():
        raise RuntimeError(f"Runtime lacks scheduler: {scheduler}")
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError("Configured Python is not executable")
    state_dir = home / "Library/Application Support/best50-vpn"
    logs = home / "Library/Logs/best50-vpn"
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    template = Path(__file__).with_name("regional_bootstrap.sh").read_bytes()
    atomic_write(state_dir / "regional-bootstrap.sh", template, 0o700)
    plist_path = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    configuration = launchd_configuration(home, repo, python)
    if plist_path.exists():
        existing = plistlib.loads(plist_path.read_bytes())
        environment = dict(existing.get("EnvironmentVariables", {}))
        environment.update(configuration["EnvironmentVariables"])
        configuration["EnvironmentVariables"] = environment
    atomic_write(plist_path, plistlib.dumps(configuration), 0o600)
    if load:
        with (state_dir / "regional-scheduler.lock").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("BestLocal scheduler owns the lock; files installed but reload deferred") from exc
            domain = f"gui/{os.getuid()}"
            # Refuse to interrupt an active BestLocal runner. Never touches other jobs.
            active = subprocess.run(["launchctl", "print", f"{domain}/{LABEL}"], capture_output=True, text=True, timeout=10)
            if active.returncode == 0:
                if any(line.strip() == "state = running" for line in active.stdout.splitlines()):
                    raise RuntimeError("BestLocal scheduler is running; files installed but reload deferred")
                subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=True, timeout=15)
            subprocess.run(["launchctl", "bootstrap", domain, str(plist_path)], check=True, timeout=15)
    return plist_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "best50-vpn-regional-runtime")
    parser.add_argument("--python", type=Path, default=Path(shutil.which("python3") or sys.executable))
    parser.add_argument("--load", action="store_true", help="Reload only this BestLocal launchd job if idle")
    args = parser.parse_args()
    path = install(Path.home(), args.repo.resolve(), args.python.absolute(), load=args.load)
    print(f"Installed {path}; {'loaded' if args.load else 'reload not requested'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
