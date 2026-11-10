#!/usr/bin/env python3
"""Install or inspect only BestLocal's Moscow03:01 local Qwen discovery job."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, tzinfo as Timezone
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qwen_schedule import MOSCOW, calendar_for_local_timezone, latest_due_slot, next_scheduled_at


LABEL = "com.rebelrider.best50-qwen-discovery"
LOCK_NAME = "qwen-discovery.lock"


def machine_timezone() -> Timezone:
    # Reading the installed TZif preserves future DST transitions. astimezone's
    # default tzinfo may instead be a fixed offset valid only for today's date.
    try:
        with Path("/etc/localtime").open("rb") as source:
            return ZoneInfo.from_file(source)
    except (OSError, ValueError):
        return datetime.now().astimezone().tzinfo or timezone.utc


def configuration(home: Path, repo: Path, python: Path, *, now: float | None = None,
                  tzinfo: Timezone | None = None) -> dict:
    now = time.time() if now is None else now
    local_zone = machine_timezone() if tzinfo is None else tzinfo
    logs = home / "Library/Logs/best50-vpn"
    state = home / "Library/Application Support/best50-vpn/qwen"
    return {
        "Label": LABEL,
        "ProgramArguments": [str(python), str(repo / "scripts/qwen_discovery.py"), "--poll",
                             "--repo", str(repo), "--state-dir", str(state)],
        "EnvironmentVariables": {"HOME": str(home), "PATH": f"{home}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
        "RunAtLoad": True, "StartInterval": 60,
        "StartCalendarInterval": calendar_for_local_timezone(now, local_zone),
        "ProcessType": "Background", "Nice": 10, "LowPriorityIO": True,
        "ThrottleInterval": 30, "ExitTimeOut": 30, "AbandonProcessGroup": False,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "qwen-discovery.log"),
        "StandardErrorPath": str(logs / "qwen-discovery-error.log"),
    }


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _job() -> dict:
    domain = f"gui/{os.getuid()}"
    try:
        result = subprocess.run(["launchctl", "print", f"{domain}/{LABEL}"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {"loaded": None, "state": "unavailable", "running": None}
    if result.returncode:
        return {"loaded": False, "state": "not-loaded", "running": False}
    match = re.search(r"^\s*state = ([^\r\n]+)", result.stdout, re.MULTILINE)
    state = match.group(1).strip() if match else "unknown"
    # Unknown/transitioning jobs are conservatively active. Never bootout a
    # worker just because launchd omitted a familiar status line.
    running = state not in {"not running", "waiting", "exited"} or bool(
        re.search(r"^\s*pid = [1-9][0-9]*\s*$", result.stdout, re.MULTILINE))
    return {"loaded": True, "state": state if state in {"running", "not running", "waiting", "exited"} else "transitioning",
            "running": running}


def status(home: Path, *, now: float | None = None, tzinfo: Timezone | None = None) -> dict:
    now = time.time() if now is None else now
    local_zone = machine_timezone() if tzinfo is None else tzinfo
    next_at = next_scheduled_at(now)
    due_slot, due_at = latest_due_slot(now)
    path = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    return {"label": LABEL, "installed": path.is_file(), **_job(),
            "schedule": "03:01 Europe/Moscow", "poll_seconds": 60,
            "next_scheduled_at": next_at,
            "next_run_utc": datetime.fromtimestamp(next_at, timezone.utc).isoformat(),
            "next_run_moscow": datetime.fromtimestamp(next_at, MOSCOW).isoformat(),
            "latest_due_slot": due_slot, "latest_due_at": due_at,
            "local_calendar_hint": calendar_for_local_timezone(now, local_zone),
            "recovery": "latest missed Moscow slot once after wake/login; cannot run while powered off"}


def install(home: Path, repo: Path, python: Path, *, load: bool = False,
            now: float | None = None, tzinfo: Timezone | None = None) -> Path:
    # No repository creation or clone. Deployment must populate the existing
    # clean runtime before installing or enabling its executable entry point.
    if not (repo / "scripts/qwen_discovery.py").is_file() or not (repo / "scripts/qwen_schedule.py").is_file():
        raise RuntimeError("Existing runtime lacks Qwen discovery code; deploy it before installation")
    if not (repo / ".git").exists():
        raise RuntimeError("Qwen discovery requires the existing Git runtime")
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError("Configured Python is not executable")
    state = home / "Library/Application Support/best50-vpn/qwen"
    logs = home / "Library/Logs/best50-vpn"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = home / "Library/LaunchAgents" / f"{LABEL}.plist"
    descriptor = os.open(state / LOCK_NAME, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Qwen discovery owns its lock; installation deferred") from None
        active = _job() if load else None
        if active and (active["running"] is not False or active["loaded"] is None):
            raise RuntimeError("Qwen discovery job is active or unavailable; reload deferred")
        marker = state / "installation.json"
        if not marker.exists():
            _atomic_write(marker, json.dumps({"schema": 1, "installed_at": time.time() if now is None else now}).encode())
        content = plistlib.dumps(configuration(home, repo, python, now=now, tzinfo=tzinfo))
        unchanged = path.is_file() and path.read_bytes() == content
        if not unchanged:
            _atomic_write(path, content)
        if load:
            domain = f"gui/{os.getuid()}"
            try:
                reload_needed = not (unchanged and active["loaded"])
                if reload_needed and active["loaded"]:
                    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=True, timeout=15)
                subprocess.run(["launchctl", "enable", f"{domain}/{LABEL}"], check=True, timeout=15)
                if reload_needed:
                    subprocess.run(["launchctl", "bootstrap", domain, str(path)], check=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                raise RuntimeError("Qwen LaunchAgent loading failed; installed plist retained for retry") from None
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.home() / "best50-vpn-regional-runtime")
    parser.add_argument("--python", type=Path, default=Path(shutil.which("python3") or sys.executable))
    parser.add_argument("--load", action="store_true", help="Enable/reload only this idle Qwen discovery job")
    parser.add_argument("--status", action="store_true", help="Read job state and next Moscow execution time")
    args = parser.parse_args()
    try:
        if args.status:
            print(json.dumps(status(Path.home()), indent=2))
        else:
            path = install(Path.home(), args.repo.resolve(), args.python.absolute(), load=args.load)
            print(f"Installed {path}; {'enabled' if args.load else 'load not requested'}; schedule=03:01 Europe/Moscow")
        return 0
    except (ValueError, RuntimeError) as exc:
        print("Qwen discovery: " + str(exc), file=sys.stderr)
        return 1
    except OSError:
        print("Qwen discovery installation/status filesystem operation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
