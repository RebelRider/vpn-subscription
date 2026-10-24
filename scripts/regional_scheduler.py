#!/usr/bin/env python3
"""Locked, bounded launchd runner. Never changes macOS networking or VPN state."""
from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_temporary import cleanup_owned_temporary

POLL_SECONDS = 300
REVALIDATE_SECONDS = 6 * 3600
MAX_INPUT_AGE_SECONDS = 18 * 3600
JOB_DEADLINE_SECONDS = 90 * 60
REPLENISH_SECONDS = 6 * 3600
VALIDATION_DUE_SECONDS = REVALIDATE_SECONDS - JOB_DEADLINE_SECONDS - POLL_SECONDS - 5 * 60
LOW_POOL_SIZE = 10
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
MAX_RETRY_FUTURE_SECONDS = 3600 + 300
RECOVERABLE_GIT_LOCKS = (
    "index.lock", "shallow.lock", "FETCH_HEAD.lock", "packed-refs.lock",
    "refs/heads/main.lock", "refs/remotes/origin/main.lock", "refs/remotes/origin/regional.lock",
)


def redact(value: str) -> str:
    # Treat every URI scheme as potentially credential-bearing, including all
    # supported proxy protocols and any future additions.
    value = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s'\"]+", "<url>", value)
    value = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[^\s,;]+", "<redacted>", value)
    value = re.sub(
        r"(?i)((?:[\"']?)(?:token|password|authorization|secret|uuid|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token)(?:[\"']?)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,}]+)",
        r"\1<redacted>", value,
    )
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b", "<redacted>", value)
    return value


def parse_timestamp(value, description: str) -> float:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            timestamp = float(value)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("missing timezone")
            timestamp = parsed.timestamp()
        else:
            raise ValueError("missing timestamp")
        if not math.isfinite(timestamp) or timestamp <= 0 or timestamp > time.time() + 300:
            raise ValueError("nonfinite or future timestamp")
        return timestamp
    except (ValueError, TypeError, OverflowError):
        raise RuntimeError(f"{description} timestamp is missing, invalid, or future") from None


def log(message: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "[regional-scheduler]", redact(message), flush=True)


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, sort_keys=True, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rotate_logs(directory: Path, limit: int = 5 * 1024 * 1024, *, names=None) -> None:
    # launchd opens the new path next run; the current descriptor keeps writing
    # its rotated inode. Only these two BestLocal-owned files are eligible.
    selected = ("regional-refresh.log", "regional-refresh-error.log") if names is None else names
    allowed = {"regional-refresh.log", "regional-refresh-error.log", "source-research.log", "source-research-error.log"}
    if any(name not in allowed for name in selected):
        raise ValueError("Only BestLocal operational logs may be rotated")
    for name in selected:
        path = directory / name
        if path.is_file() and path.stat().st_size > limit:
            previous = directory / (name + ".1")
            os.replace(path, previous)


def _system_lsof() -> str | None:
    # Use the OS tool, never an executable supplied by a source or shell PATH.
    for name in ("/usr/sbin/lsof", "/usr/bin/lsof", "/sbin/lsof", "/bin/lsof"):
        if Path(name).is_file() and os.access(name, os.X_OK):
            return name
    return None


def recover_orphan_git_locks(repo: Path, *, now: float | None = None) -> dict:
    """Reclaim only verified orphan metadata in the dedicated normal clone.

    Caller holds the scheduler's kernel lock. Dirty files and Git history are
    never repaired or discarded. Unknown or inconclusive lock state is retained.
    """
    result = {"examined": 0, "removed": 0, "active": 0, "skipped": 0, "failed": 0}
    now = time.time() if now is None else now
    lsof = _system_lsof()
    if not lsof or not math.isfinite(now):
        result["skipped"] = len(RECOVERABLE_GIT_LOCKS)
        return result
    try:
        expected = repo / ".git"
        info = expected.lstat()
        # Shared/linked worktrees and ambient GIT_DIR overrides are outside
        # this dedicated-runtime recovery scope.
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return result
        resolved = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], cwd=repo,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
        if resolved.returncode or len(resolved.stdout) > 4096:
            return result
        gitdir = Path(os.fsdecode(resolved.stdout.strip()))
        if not gitdir.is_absolute() or gitdir != expected.resolve():
            return result
    except (OSError, ValueError, subprocess.SubprocessError):
        result["failed"] += 1
        return result

    def safe_parents(relative):
        current = gitdir.lstat()
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid()
                or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            return False
        parent = gitdir
        for part in Path(relative).parts[:-1]:
            parent = parent / part
            item = parent.lstat()
            if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid():
                return False
        return True

    def snapshot(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            item = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or item.st_nlink != 1
                or item.st_size > 4 * 1024 * 1024 or now - item.st_mtime <= 2 * 3600):
            return None
        return item.st_dev, item.st_ino, item.st_uid, item.st_nlink, item.st_size, item.st_mtime_ns

    for relative in RECOVERABLE_GIT_LOCKS:
        path = gitdir / relative
        try:
            if not safe_parents(relative):
                continue
            before = snapshot(path)
            result["examined"] += 1
            if before is None:
                result["skipped"] += 1
                continue
            # Our inspection descriptor is already closed, so it cannot make
            # an orphan appear active to lsof.
            handles = subprocess.run([lsof, "-nP", "-t", "--", str(path)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
            if handles.returncode == 0 or handles.stdout.strip():
                result["active"] += 1
                continue
            if handles.returncode != 1 or handles.stderr.strip():
                result["failed"] += 1
                continue
            if not safe_parents(relative) or snapshot(path) != before:
                result["skipped"] += 1
                continue
            final = path.lstat()
            if (not stat.S_ISREG(final.st_mode)
                    or (final.st_dev, final.st_ino, final.st_uid, final.st_nlink,
                        final.st_size, final.st_mtime_ns) != before):
                result["skipped"] += 1
                continue
            path.unlink()
            result["removed"] += 1
        except FileNotFoundError:
            continue
        except OSError:
            result["skipped"] += 1
        except (ValueError, subprocess.SubprocessError):
            result["failed"] += 1
    return result


def _read_state(path: Path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("state exceeds size limit")
    return json.loads(raw)


def load_state(path: Path) -> dict:
    try:
        value = _read_state(path)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}


def normalize_scheduler_state(value, now: float | None = None) -> tuple[dict, list[str]]:
    """Recover diagnostic state without inventing validation/publication evidence.

    Past event times must be finite positive epochs, permitting at most five
    minutes of clock skew. Retry deadlines may be zero or at most one hour plus
    that skew in the future. Invalid fields are discarded, so corrupted retry
    state cannot suppress future work. Unknown fields are not trusted.
    """
    now = time.time() if now is None else now
    if not isinstance(value, dict):
        return {}, ["state-object"]
    timestamps = {
        "last_validated_at", "last_published_at", "last_published_validation_at",
        "last_local_result_at", "last_attempt_at", "last_failure_at",
        "last_scheduler_started_at", "last_scheduler_finished_at",
        "last_input_checked_at", "input_generated_at", "recovered_interrupted_at",
        "last_replenishment_dispatched_at", "last_replenishment_attempt_at",
        "state_recovered_at",
    }
    retries = {"next_retry_at", "next_replenishment_retry_at"}
    counters = {"consecutive_failures": 1000, "replenishment_consecutive_failures": 1000,
                "last_local_qualified": 50, "last_published_count": 50,
                "pid": 2 ** 31 - 1, "poll_seconds": 86400,
                "revalidate_seconds": 7 * 86400, "validation_due_seconds": 7 * 86400,
                "state_recovery_count": 1000000}
    strings = {"last_validated_signature", "last_attempt_signature", "input_signature",
               "health", "last_error", "last_replenishment_error"}
    ages = {"published_age_seconds", "published_validation_age_seconds", "input_age_seconds"}
    normalized, recovered = {}, []
    for name, item in value.items():
        valid = False
        number = (isinstance(item, int) and not isinstance(item, bool)) or (isinstance(item, float) and math.isfinite(item))
        if name in timestamps:
            valid = number and 0 < item <= now + 300
        elif name in retries:
            valid = number and 0 <= item <= now + MAX_RETRY_FUTURE_SECONDS
        elif name in counters:
            valid = isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= counters[name]
        elif name in strings:
            maximum = 3000 if "error" in name else 256
            valid = isinstance(item, str) and len(item) <= maximum and not any(ord(char) < 32 for char in item)
        elif name in {"running", "published_stale"}:
            valid = isinstance(item, bool)
        elif name in ages:
            valid = item is None or (number and -300 <= item <= now)
        elif name == "last_service_totals":
            valid = isinstance(item, dict) and set(item) == {"chatgpt", "youtube", "instagram"}
            if valid:
                for total in item.values():
                    if (not isinstance(total, dict) or set(total) != {"attempts", "passed", "all_round_candidates"}
                            or any(not isinstance(count, int) or isinstance(count, bool) for count in total.values())
                            or not 0 <= total["passed"] <= total["attempts"] <= 750
                            or not 0 <= total["all_round_candidates"] <= 150):
                        valid = False
                        break
        if valid:
            normalized[name] = item
        else:
            recovered.append(name if name in timestamps | retries | set(counters) | strings | ages | {"running", "published_stale", "last_service_totals"} else "unknown-field")
    # This is derived evidence, never a trusted persisted assertion of freshness.
    validation = normalized.get("last_published_validation_at")
    normalized["published_stale"] = not validation or now - validation > REVALIDATE_SECONDS
    return normalized, sorted(set(recovered))


def load_scheduler_state(path: Path, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    try:
        value = _read_state(path)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, UnicodeError, RecursionError):
        value = None
    state, recovered = normalize_scheduler_state(value, now)
    if recovered:
        state["state_recovered_at"] = now
        state["state_recovery_count"] = min(state.get("state_recovery_count", 0) + 1, 1000000)
        log("Recovered invalid scheduler state fields: " + ", ".join(recovered))
    return state


def retry_delay(failures: int, jitter: float | None = None) -> float:
    base = min(3600, 60 * 2 ** min(max(failures - 1, 0), 6))
    return min(3600, base * (0.8 + 0.4 * (random.random() if jitter is None else jitter)))


def validation_interval(state: dict) -> int:
    count = state.get("last_local_qualified")
    if type(count) is int and 0 <= count < LOW_POOL_SIZE:
        return 3600 if count <= 2 else 2 * 3600
    return VALIDATION_DUE_SECONDS


def validation_due(state: dict, signature: str, now: float) -> bool:
    if signature != state.get("last_validated_signature"):
        return now >= state.get("next_retry_at", 0) or signature != state.get("last_attempt_signature")
    return now - state.get("last_validated_at", 0) >= validation_interval(state) and now >= state.get("next_retry_at", 0)


class CommandFailure(RuntimeError):
    def __init__(self, label: str, returncode: int, detail: str = ""):
        super().__init__(f"{label} failed (exit {returncode})" + (": " + redact(detail[-3000:]) if detail else ""))
        self.returncode = returncode


def supervise(parent_pid: int, seconds: float, command: list[str]) -> int:
    """Watch parent liveness and reap only the command group we create."""
    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + seconds
    timed_out = False
    try:
        while process.poll() is None:
            if stopped or os.getppid() != parent_pid or time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.1)
    finally:
        # The group ID belongs to this exact child; no global process matching.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
    return 124 if timed_out else process.returncode


class Runner:
    def __init__(self, repo: Path, deadline: float):
        self.repo = repo
        self.deadline = deadline
        self.active: subprocess.Popen | None = None
        self.environment: dict[str, str] = {}

    def run(self, command: list[str], label: str, timeout: float = 90, *, check: bool = True) -> tuple[int, str]:
        remaining = min(timeout, self.deadline - time.monotonic())
        if remaining <= 0:
            raise CommandFailure("job deadline", 124)
        environment = os.environ.copy()
        environment.update({"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1", **self.environment})
        # Ignore ambient proxy variables for loopback proxy tests. No system settings change.
        if "scripts/local_probe.py" in command:
            for key in list(environment):
                if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                    environment.pop(key)
        helper = self.repo / "scripts/control_plane.py"
        if sys.platform == "darwin" and helper.is_file() and (
            Path(command[0]).name in {"git", "gh"} or "scripts/local_probe.py" in command
        ):
            command = [sys.executable, str(helper), "--", *command]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--supervise", str(os.getpid()), str(remaining), "--", *command],
                cwd=self.repo, env=environment, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
            )
            self.active = process
            exceeded = False
            try:
                while process.poll() is None:
                    if time.monotonic() >= self.deadline or output.tell() > MAX_OUTPUT_BYTES:
                        exceeded = True
                        self.stop()
                        break
                    time.sleep(0.1)
                process.wait(timeout=5)
            finally:
                self.stop()
            output.seek(0)
            detail = output.read(MAX_OUTPUT_BYTES).decode(errors="replace")
            code = 124 if exceeded else process.returncode
            if check and code:
                raise CommandFailure(label, code, detail)
            return code, detail

    def stop(self) -> None:
        if self.active is None:
            return
        process = self.active
        self.active = None
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            pass
        # Also remove descendants left behind after their immediate parent exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)

    def git(self, *arguments: str, timeout: float = 90) -> str:
        return self.run(["git", *arguments], "git " + arguments[0], timeout)[1].strip()

    def fetch(self) -> None:
        for attempt in range(3):
            try:
                self.git("fetch", "--quiet", "origin", "main")
                return
            except CommandFailure:
                if attempt == 2:
                    raise
                delay = min(5 * 2 ** attempt + random.random() * 3, self.deadline - time.monotonic())
                if delay <= 0:
                    raise
                log(f"Git fetch retry {attempt + 1}/2 in {delay:.1f}s")
                time.sleep(delay)


def input_metadata(runner: Runner) -> tuple[str, float]:
    blob = runner.git("rev-parse", "origin/main:output/best50.txt")
    status = json.loads(runner.git("show", "origin/main:output/status.json"))
    generated = parse_timestamp(status.get("generated_at"), "Best50 generated_at")
    # Relevant code changes also require validation even if Best50 stays the same.
    digest = hashlib.sha256(blob.encode())
    scripts = runner.repo / "scripts"
    for path in sorted([*scripts.glob("*.py"), *scripts.glob("*.js")]):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    digest.update((runner.repo / "config.json").read_bytes())
    return digest.hexdigest(), float(generated)


def dispatch_replenishment(runner: Runner, state: dict, state_path: Path, now: float, reason: str) -> None:
    # Critical pools (at most two unique servers) need hourly exploration.
    # Other supplemental dispatches retain the six-hour limit; the ordinary
    # two-hour cloud schedule remains independent.
    count = state.get("last_local_qualified")
    interval = 3600 if type(count) is int and 0 <= count <= 2 else REPLENISH_SECONDS
    if now - state.get("last_replenishment_dispatched_at", 0) < interval:
        return
    if now < state.get("next_replenishment_retry_at", 0):
        return
    state["last_replenishment_attempt_at"] = now
    atomic_json(state_path, state)
    try:
        command = ["gh", "workflow", "run", "build.yml", "--ref", "main"]
        try:
            runner.run(command, "candidate replenishment dispatch", 60)
        except CommandFailure:
            # A long-lived public repository can have its schedule disabled by
            # GitHub inactivity policy. Respect deliberate manual disabling.
            _, workflow_state = runner.run(
                ["gh", "api", "repos/{owner}/{repo}/actions/workflows/build.yml", "--jq", ".state"],
                "primary workflow recovery status", 60,
            )
            if workflow_state.strip() != "disabled_inactivity":
                raise
            runner.run(["gh", "workflow", "enable", "build.yml"], "primary workflow inactivity recovery", 60)
            runner.run(command, "recovered candidate replenishment dispatch", 60)
            log("Recovered primary workflow disabled by GitHub inactivity policy")
        state.update({"last_replenishment_dispatched_at": now, "replenishment_consecutive_failures": 0, "next_replenishment_retry_at": 0})
        state.pop("last_replenishment_error", None)
        log(f"Candidate replenishment requested: {reason}")
    except (OSError, CommandFailure) as exc:
        previous = state.get("replenishment_consecutive_failures", 0)
        failures = previous + 1 if isinstance(previous, int) and 0 <= previous <= 1000 else 1
        delay = retry_delay(failures)
        state.update({"last_replenishment_error": redact(str(exc)), "replenishment_consecutive_failures": failures, "next_replenishment_retry_at": now + delay})
        log(f"WARNING: candidate replenishment dispatch unavailable: {exc}; retry eligible in {delay:.0f}s")
    atomic_json(state_path, state)


def run_scheduler(repo: Path, state_dir: Path) -> int:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_path = state_dir / "regional-scheduler-status.json"
    # Kernel locks disappear on crash; never unlink a live lock inode.
    with (state_dir / "regional-scheduler.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Another scheduler owns the runtime; skipped overlap")
            return 0
        try:
            git_locks = recover_orphan_git_locks(repo)
            if git_locks["removed"] or git_locks["failed"]:
                log(f"Owned Git lock recovery: removed={git_locks['removed']} deferred={git_locks['failed']}")
            cleanup = cleanup_owned_temporary(state_dir / "temporary", repos=[repo])
            if cleanup["removed"] or cleanup["failed"]:
                log(f"Owned temporary recovery: removed={cleanup['removed']} deferred={cleanup['failed']}")
            if state_dir == (Path.home() / "Library/Application Support/best50-vpn").resolve():
                rotate_logs(Path.home() / "Library/Logs/best50-vpn")
        except (OSError, ValueError, RuntimeError):
            log("WARNING: optional owned temporary/log cleanup deferred")
        now = time.time()
        state = load_scheduler_state(state_path, now)
        if state.get("running"):
            log("Recovering interrupted prior run; process supervision already bounds owned children")
            state["recovered_interrupted_at"] = now
        state.update({"running": True, "last_scheduler_started_at": now, "pid": os.getpid(), "poll_seconds": POLL_SECONDS, "revalidate_seconds": REVALIDATE_SECONDS, "validation_due_seconds": VALIDATION_DUE_SECONDS})
        atomic_json(state_path, state)
        runner = Runner(repo, time.monotonic() + JOB_DEADLINE_SECONDS)
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt
        original_handlers = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        try:
            if runner.git("status", "--porcelain"):
                raise RuntimeError("Production runtime is dirty; refusing self-update")
            if runner.git("branch", "--show-current") != "main":
                raise RuntimeError("Production runtime must be on main")
            runner.fetch()
            runner.git("merge", "--ff-only", "--quiet", "origin/main")
            if runner.git("rev-parse", "HEAD") != runner.git("rev-parse", "origin/main"):
                raise RuntimeError("Runtime main differs from origin/main after fast-forward")
            signature, generated = input_metadata(runner)
            now = time.time()
            age = now - generated
            state.update({"input_generated_at": generated, "input_age_seconds": age, "input_signature": signature, "last_input_checked_at": now})
            if age < -300 or age > MAX_INPUT_AGE_SECONDS:
                dispatch_replenishment(runner, state, state_path, now, "stale or invalid Best50 timestamp")
                raise RuntimeError(f"Best50 age {age / 3600:.1f}h is outside permitted freshness (18h)")
            if not validation_due(state, signature, now):
                known_count = state.get("last_local_qualified")
                if isinstance(known_count, int) and 0 <= known_count < LOW_POOL_SIZE:
                    dispatch_replenishment(runner, state, state_path, now, f"only {known_count} local qualifiers; retry pending dispatch")
                state["health"] = "waiting_retry" if now < state.get("next_retry_at", 0) else "current"
                log("Input current; next six-hour validation or changed input will trigger a run")
                return 0
            state.update({"last_attempt_at": now, "last_attempt_signature": signature, "health": "validating"})
            atomic_json(state_path, state)
            geoip = state_dir / "geoip"
            runner.environment = {"BEST50_CITY_DB_IPV4": str(geoip / "dbip-city-ipv4.csv.gz"), "BEST50_CITY_DB_IPV6": str(geoip / "dbip-city-ipv6.csv.gz")}
            if (repo / "scripts/update_exit_geoip.py").is_file():
                geo_code, _ = runner.run([sys.executable, "scripts/update_exit_geoip.py", "--state-dir", str(state_dir), "--max-age-days", "7"], "exit GeoIP cache refresh", 180, check=False)
                if geo_code:
                    log("WARNING: GeoIP refresh failed; existing cache retained")
            code, output = runner.run([sys.executable, "scripts/local_probe.py", "--interface", "en0", "--rounds", "5", "--minimum-successes", "5", "--publish"], "local validation/publication", timeout=80 * 60, check=False)
            for line in output.splitlines()[-100:]:
                log(line)
            try:
                local_status = load_state(repo / "output/local-status.json")
                qualified = local_status.get("stability", {}).get("qualified", len(local_status.get("nodes", [])))
                if not isinstance(qualified, int) or isinstance(qualified, bool) or not 0 <= qualified <= 50 or qualified != len(local_status.get("nodes", [])):
                    raise RuntimeError("Invalid local validation status")
                generated_at = parse_timestamp(local_status.get("generated_at"), "local validation")
                if generated_at < now - 5:
                    raise RuntimeError("Local validation status is missing, stale, or has invalid timestamp")
                service_totals = {name: {"attempts": 0, "passed": 0, "all_round_candidates": 0} for name in ("chatgpt", "youtube", "instagram")}
                rounds = local_status.get("stability", {}).get("rounds", 5)
                for diagnostic in local_status.get("diagnostics", []):
                    for name, total in service_totals.items():
                        service = diagnostic.get("services", {}).get(name, {})
                        attempts, passed = service.get("attempts", 0), service.get("passed", 0)
                        if isinstance(attempts, int) and isinstance(passed, int) and 0 <= passed <= attempts <= 5:
                            total["attempts"] += attempts
                            total["passed"] += passed
                            total["all_round_candidates"] += int(attempts == passed == rounds)
                state.update({"last_local_result_at": generated_at, "last_local_qualified": qualified, "last_service_totals": service_totals})
                for name, total in service_totals.items():
                    log(f"Service {name}: {total['passed']}/{total['attempts']} successful HTTPS checks; {total['all_round_candidates']} candidates passed every round")
            except (RuntimeError, TypeError, AttributeError, ValueError):
                if code not in (0, 2):
                    raise CommandFailure("local validation/publication; no fresh local result", code, output) from None
                raise
            if qualified < LOW_POOL_SIZE:
                dispatch_replenishment(runner, state, state_path, time.time(), f"only {qualified} local qualifiers")
            if code not in (0, 2):
                # A freshly completed validation remains useful even when GitHub
                # publication fails. It never advances last-published state.
                raise CommandFailure("local validation/publication", code, output)
            if code == 2 or qualified == 0:
                raise CommandFailure("local validation found no qualifying servers; last published artifact retained", 2)
            state.update({"last_validated_at": generated_at, "last_validated_signature": signature, "last_published_validation_at": generated_at, "last_published_at": time.time(), "last_published_count": qualified, "consecutive_failures": 0, "next_retry_at": 0, "health": "published"})
            state.pop("last_error", None)
            log(f"Local validation and publication complete: {qualified} servers")
            return 0
        except (Exception, KeyboardInterrupt) as exc:
            previous_failures = state.get("consecutive_failures", 0)
            failures = previous_failures + 1 if isinstance(previous_failures, int) and 0 <= previous_failures <= 1000 else 1
            delay = retry_delay(failures)
            state.update({"consecutive_failures": failures, "next_retry_at": time.time() + delay, "last_error": redact(str(exc) or "interrupted"), "last_failure_at": time.time(), "health": "failed"})
            log(f"ERROR: {str(exc) or 'interrupted'}; retry eligible in {delay:.0f}s; published artifact preserved")
            return 1
        finally:
            runner.stop()
            state["validation_due_seconds"] = validation_interval(state)
            state.update({"running": False, "last_scheduler_finished_at": time.time()})
            published = state.get("last_published_at")
            state["published_age_seconds"] = time.time() - published if published else None
            validation_time = state.get("last_published_validation_at")
            state["published_validation_age_seconds"] = time.time() - validation_time if validation_time else None
            state["published_stale"] = not validation_time or time.time() - validation_time > REVALIDATE_SECONDS
            atomic_json(state_path, state)
            for sig, handler in original_handlers.items():
                signal.signal(sig, handler)


def main() -> int:
    if len(sys.argv) >= 6 and sys.argv[1] == "--supervise":
        return supervise(int(sys.argv[2]), float(sys.argv[3]), sys.argv[5:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(os.environ.get("BEST50_REPO", str(Path.home() / "best50-vpn-regional-runtime"))))
    parser.add_argument("--state-dir", type=Path, default=Path.home() / "Library/Application Support/best50-vpn")
    args = parser.parse_args()
    return run_scheduler(args.repo.resolve(), args.state_dir.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
