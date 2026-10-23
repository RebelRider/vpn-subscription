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
import subprocess
import sys
import tempfile
import time

POLL_SECONDS = 900
REVALIDATE_SECONDS = 6 * 3600
MAX_INPUT_AGE_SECONDS = 18 * 3600
JOB_DEADLINE_SECONDS = 90 * 60
REPLENISH_SECONDS = 6 * 3600
VALIDATION_DUE_SECONDS = REVALIDATE_SECONDS - JOB_DEADLINE_SECONDS - POLL_SECONDS
LOW_POOL_SIZE = 10
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


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
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rotate_logs(directory: Path, limit: int = 5 * 1024 * 1024) -> None:
    # launchd opens the new path next run; the current descriptor keeps writing
    # its rotated inode. Only these two BestLocal-owned files are eligible.
    for name in ("regional-refresh.log", "regional-refresh-error.log"):
        path = directory / name
        if path.is_file() and path.stat().st_size > limit:
            previous = directory / (name + ".1")
            os.replace(path, previous)


def load_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def retry_delay(failures: int, jitter: float | None = None) -> float:
    base = min(3600, 60 * 2 ** min(max(failures - 1, 0), 6))
    return min(3600, base * (0.8 + 0.4 * (random.random() if jitter is None else jitter)))


def validation_due(state: dict, signature: str, now: float) -> bool:
    if signature != state.get("last_validated_signature"):
        return now >= state.get("next_retry_at", 0) or signature != state.get("last_attempt_signature")
    return now - state.get("last_validated_at", 0) >= VALIDATION_DUE_SECONDS and now >= state.get("next_retry_at", 0)


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
    for path in sorted((runner.repo / "scripts").glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    digest.update((runner.repo / "config.json").read_bytes())
    return digest.hexdigest(), float(generated)


def dispatch_replenishment(runner: Runner, state: dict, state_path: Path, now: float, reason: str) -> None:
    if now - state.get("last_replenishment_dispatched_at", 0) < REPLENISH_SECONDS:
        return
    if now < state.get("next_replenishment_retry_at", 0):
        return
    state["last_replenishment_attempt_at"] = now
    atomic_json(state_path, state)
    try:
        runner.run(["gh", "workflow", "run", "build.yml", "--ref", "main"], "candidate replenishment dispatch", 60)
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
        if state_dir == (Path.home() / "Library/Application Support/best50-vpn").resolve():
            rotate_logs(Path.home() / "Library/Logs/best50-vpn")
        state = load_state(state_path)
        now = time.time()
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
            state.update({"running": False, "last_scheduler_finished_at": time.time()})
            published = state.get("last_published_at")
            state["published_age_seconds"] = time.time() - published if published else None
            validation_time = state.get("last_published_validation_at", state.get("last_validated_at"))
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
