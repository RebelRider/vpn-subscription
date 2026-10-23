#!/usr/bin/env python3
"""Install only the BestLocal daily public-source research launchd job."""
from __future__ import annotations

import argparse
import fcntl
import math
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_research import seed_initial_state

LABEL = "com.rebelrider.best50-source-research"


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configuration(home: Path, repo: Path, python: Path) -> dict:
    logs = home / "Library/Logs/best50-vpn"
    return {
        "Label": LABEL,
        "ProgramArguments": [str(python), str(repo / "scripts/source_research.py"), "--repo", str(repo)],
        "EnvironmentVariables": {"HOME": str(home), "PATH": f"{home}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
        "RunAtLoad": True, "StartInterval": 3600, "ThrottleInterval": 30,
        "ProcessType": "Background", "ExitTimeOut": 15, "AbandonProcessGroup": False,
        "StandardOutPath": str(logs / "source-research.log"),
        "StandardErrorPath": str(logs / "source-research-error.log"),
    }


def install(home: Path, repo: Path, python: Path, *, load: bool = False, defer_hours: float = 1) -> Path:
    if not isinstance(defer_hours, (int, float)) or isinstance(defer_hours, bool) or not math.isfinite(defer_hours) or not 0 <= defer_hours <= 6:
        raise ValueError("defer hours must be finite and between zero and six")
    if not (repo / "scripts/source_research.py").is_file():
        raise RuntimeError("Runtime lacks the source-research runner")
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError("Configured Python is not executable")
    state = home / "Library/Application Support/best50-vpn"
    logs = home / "Library/Logs/best50-vpn"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    with (state / "source-research.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Source research is running; installation deferred") from exc
        domain = f"gui/{os.getuid()}"
        active = None
        if load:
            active = subprocess.run(["launchctl", "print", f"{domain}/{LABEL}"], capture_output=True, text=True, timeout=10)
            if active.returncode == 0 and any(line.strip() == "state = running" for line in active.stdout.splitlines()):
                raise RuntimeError("Source-research job is active; reload deferred")
        value = configuration(home, repo, python)
        if path.exists():
            existing = plistlib.loads(path.read_bytes())
            environment = dict(existing.get("EnvironmentVariables", {}))
            environment.update(value["EnvironmentVariables"])
            value["EnvironmentVariables"] = environment
        seed_initial_state(state, time.time(), defer_hours)
        atomic_write(path, plistlib.dumps(value))
        if load:
            if active.returncode == 0:
                subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=True, timeout=15)
            subprocess.run(["launchctl", "bootstrap", domain, str(path)], check=True, timeout=15)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "best50-vpn-regional-runtime")
    parser.add_argument("--python", type=Path, default=Path(shutil.which("python3") or sys.executable))
    parser.add_argument("--defer-hours", type=float, default=1, help="Initial quota wait; existing state is preserved")
    parser.add_argument("--load", action="store_true", help="Reload only the idle BestLocal source-research job")
    args = parser.parse_args()
    path = install(Path.home(), args.repo.resolve(), args.python.absolute(), load=args.load, defer_hours=args.defer_hours)
    print(f"Installed {path}; {'loaded' if args.load else 'reload not requested'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
