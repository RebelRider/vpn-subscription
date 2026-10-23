import importlib.util
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scheduler = load("regional_scheduler", ROOT / "scripts/regional_scheduler.py")
installer = load("install_local_automation", ROOT / "scripts/install_local_automation.py")


class SchedulerTests(unittest.TestCase):
    def test_six_hour_revalidation_and_changed_input(self):
        state = {"last_validated_signature": "same", "last_validated_at": 100, "last_attempt_signature": "same"}
        self.assertFalse(scheduler.validation_due(state, "same", 101))
        self.assertTrue(scheduler.validation_due(state, "same", 100 + 6 * 3600))
        self.assertTrue(scheduler.validation_due(state, "changed", 101))
        state.update(next_retry_at=1000, last_attempt_signature="changed")
        self.assertFalse(scheduler.validation_due(state, "changed", 101))
        self.assertTrue(scheduler.validation_due(state, "newer", 101))

    def test_timestamp_accepts_real_iso_and_legacy_numeric(self):
        now = time.time()
        self.assertAlmostEqual(scheduler.parse_timestamp(datetime.fromtimestamp(now, timezone.utc).isoformat(), "local"), now, places=5)
        self.assertEqual(scheduler.parse_timestamp(100, "legacy"), 100)
        for invalid in (None, "2026-01-01T12:00:00", float("nan"), time.time() + 1000, "not-a-date"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                scheduler.parse_timestamp(invalid, "test")

    def test_all_proxy_protocols_and_json_credentials_redacted(self):
        for scheme in ("vless", "vmess", "trojan", "ss", "hy2", "hysteria2", "tuic", "socks5"):
            self.assertNotIn("credential", scheduler.redact(scheme + "://credential@host"))
        self.assertNotIn("auth-value", scheduler.redact("Authorization: Bearer auth-value"))
        value = scheduler.redact('{"password": "long secret here", "api_key": "sensitive", "uuid": "private-id"}')
        for secret in ("long secret here", "sensitive", "private-id"):
            self.assertNotIn(secret, value)

    def test_input_rejects_nonfinite_timestamp(self):
        runner = mock.Mock()
        runner.git.side_effect = ["blob", '{"generated_at": NaN}']
        with self.assertRaisesRegex(RuntimeError, "invalid"):
            scheduler.input_metadata(runner)

    def test_backoff_is_exponential_and_bounded(self):
        self.assertEqual(scheduler.retry_delay(1, 0.5), 60)
        self.assertEqual(scheduler.retry_delay(3, 0.5), 240)
        self.assertEqual(scheduler.retry_delay(100, 0.5), 3600)

    def test_redaction(self):
        value = scheduler.redact("vless://uuid@endpoint password=secret https://user:pass@github.com/repo ghp_abcdef TOKEN=abc")
        for secret in ["uuid", "secret", "user:pass", "ghp_abcdef", "TOKEN=abc"]:
            self.assertNotIn(secret, value)

    def test_supervised_command_timeout_cleans_only_owned_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = scheduler.Runner(Path(temporary), time.monotonic() + 10)
            started = time.monotonic()
            with self.assertRaises(scheduler.CommandFailure) as raised:
                runner.run([sys.executable, "-c", "import time; time.sleep(30)"], "owned timeout test", timeout=0.3)
            self.assertEqual(raised.exception.returncode, 124)
            self.assertLess(time.monotonic() - started, 6)
            self.assertIsNone(runner.active)

    def test_supervisor_reaps_child_when_parent_is_gone(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "pid"
            command = [sys.executable, "-c", "import os,time; open(" + repr(str(pid_path)) + ",'w').write(str(os.getpid())); time.sleep(30)"]
            proc = subprocess.Popen([sys.executable, str(ROOT / "scripts/regional_scheduler.py"), "--supervise", "2147483000", "10", "--", *command], start_new_session=True)
            try:
                self.assertEqual(proc.wait(timeout=6), 124)
                if pid_path.exists():
                    pid = int(pid_path.read_text())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()

    def test_successful_command_output_preserved(self):
        runner = scheduler.Runner(ROOT, time.monotonic() + 10)
        self.assertEqual(runner.run([sys.executable, "-c", "print('healthy')"], "test"), (0, "healthy\n"))

    def test_failed_empty_run_preserves_published_state_and_artifact(self):
        for probe_code in (2, 1):
            with self.subTest(probe_exit=probe_code), tempfile.TemporaryDirectory() as temporary:
                now = time.time()
                calls = []
                class FakeRunner:
                    def __init__(self, repo, deadline): self.repo = repo
                    def git(self, *args, **kwargs):
                        return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
                    def fetch(self): pass
                    def run(self, command, label, *args, **kwargs):
                        calls.append(command)
                        return (probe_code, "LOCAL QUALIFIED: 0; publication health fetch unavailable\n") if "scripts/local_probe.py" in command else (0, "")
                    def stop(self): pass
                repo = Path(temporary) / "runtime"
                state_dir = Path(temporary) / "state"
                (repo / "output").mkdir(parents=True)
                state_dir.mkdir()
                artifact = repo / "output/best-local.txt"
                artifact.write_text("last-known-good")
                (repo / "output/local-status.json").write_text(json.dumps({"generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "stability": {"qualified": 0}, "nodes": [], "diagnostics": [{"services": {"chatgpt": {"attempts": 1, "passed": 0}}}]}))
                state_path = state_dir / "regional-scheduler-status.json"
                scheduler.atomic_json(state_path, {"last_published_at": now - 100, "last_published_count": 3})
                with mock.patch.object(scheduler, "Runner", FakeRunner), mock.patch.object(scheduler, "input_metadata", return_value=("changed", now)):
                    self.assertEqual(scheduler.run_scheduler(repo, state_dir), 1)
                state = scheduler.load_state(state_path)
                self.assertEqual(state["last_published_count"], 3)
                self.assertEqual(state["last_published_at"], now - 100)
                self.assertEqual(state["last_local_qualified"], 0)
                self.assertEqual(state["last_service_totals"]["chatgpt"]["attempts"], 1)
                self.assertEqual(state["last_service_totals"]["chatgpt"]["passed"], 0)
                self.assertTrue(any(command[:3] == ["gh", "workflow", "run"] for command in calls))
                self.assertFalse(state["running"])
                self.assertEqual(artifact.read_text(), "last-known-good")

    def test_nonzero_probe_without_fresh_status_does_not_record_or_dispatch(self):
        now = time.time()
        calls = []
        class FakeRunner:
            def __init__(self, repo, deadline): self.repo = repo
            def git(self, *args, **kwargs): return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
            def fetch(self): pass
            def run(self, command, label, *args, **kwargs): calls.append(command); return 1, "GitHub unavailable"
            def stop(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "output").mkdir()
            (repo / "output/local-status.json").write_text(json.dumps({"generated_at": now - 100, "stability": {"qualified": 0}, "nodes": []}))
            state_dir = repo / "state"
            with mock.patch.object(scheduler, "Runner", FakeRunner), mock.patch.object(scheduler, "input_metadata", return_value=("input", now)):
                self.assertEqual(scheduler.run_scheduler(repo, state_dir), 1)
            state = scheduler.load_state(state_dir / "regional-scheduler-status.json")
            self.assertNotIn("last_local_qualified", state)
            self.assertIn("no fresh local result", state["last_error"])
            self.assertFalse(any(command[:3] == ["gh", "workflow", "run"] for command in calls))

    def test_stale_input_blocks_probe_and_dispatches(self):
        calls = []
        class FakeRunner:
            def __init__(self, repo, deadline): self.repo = repo
            def git(self, *args, **kwargs): return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
            def fetch(self): pass
            def run(self, command, *args, **kwargs): calls.append(command); return 0, ""
            def stop(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with mock.patch.object(scheduler, "Runner", FakeRunner), mock.patch.object(scheduler, "input_metadata", return_value=("stale", time.time() - 19 * 3600)):
                self.assertEqual(scheduler.run_scheduler(path, path / "state"), 1)
            self.assertTrue(any(command[:3] == ["gh", "workflow", "run"] for command in calls))
            self.assertFalse(any("scripts/local_probe.py" in command for command in calls))

    def test_success_failure_and_interruption_keep_publication_truthful(self):
        for outcome in ("success", "publication-failed", "interrupted"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                now = time.time()
                directory = Path(temporary)
                (directory / "output").mkdir()
                (directory / "output/local-status.json").write_text(json.dumps({"generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "stability": {"qualified": 12}, "nodes": [{}] * 12, "diagnostics": [{"services": {"chatgpt": {"passed": 1, "attempts": 2}}}]}))
                state_dir = directory / "state"
                state_path = state_dir / "regional-scheduler-status.json"
                scheduler.atomic_json(state_path, {"last_published_at": now - 100, "last_published_count": 3, "running": True})
                class FakeRunner:
                    def __init__(self, repo, deadline): self.repo = repo
                    def git(self, *args, **kwargs): return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
                    def fetch(self): pass
                    def run(self, command, *args, **kwargs):
                        if outcome == "interrupted": raise KeyboardInterrupt
                        return (0, "published") if outcome == "success" else (1, "GitHub temporarily unavailable")
                    def stop(self): pass
                with mock.patch.object(scheduler, "Runner", FakeRunner), mock.patch.object(scheduler, "input_metadata", return_value=("new", now)):
                    code = scheduler.run_scheduler(directory, state_dir)
                state = scheduler.load_state(state_path)
                self.assertFalse(state["running"])
                self.assertIn("recovered_interrupted_at", state)
                if outcome == "success":
                    self.assertEqual(code, 0)
                    self.assertEqual(state["last_published_count"], 12)
                    self.assertAlmostEqual(state["last_published_validation_at"], now, places=5)
                    self.assertEqual(state["last_service_totals"]["chatgpt"]["attempts"], 2)
                    self.assertEqual(state["last_service_totals"]["chatgpt"]["passed"], 1)
                    self.assertFalse(state["published_stale"])
                    self.assertEqual(state["last_validated_signature"], "new")
                    self.assertEqual(state["next_retry_at"], 0)
                else:
                    self.assertEqual(code, 1)
                    self.assertEqual(state["last_published_count"], 3)
                    self.assertEqual(state["last_published_at"], now - 100)
                    self.assertGreater(state["next_retry_at"], now)
                    self.assertNotIn("last_validated_signature", state)

    def test_empty_pool_replenishment_is_hourly_and_bounded(self):
        runner = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            now = time.time()
            state = {"last_local_qualified": 0, "last_replenishment_dispatched_at": now}
            path = Path(temporary) / "status.json"
            scheduler.dispatch_replenishment(runner, state, path, now + 3599, "empty")
            self.assertEqual(runner.run.call_count, 0)
            scheduler.dispatch_replenishment(runner, state, path, now + 3600, "empty")
            self.assertEqual(runner.run.call_count, 1)
            scheduler.dispatch_replenishment(runner, state, path, now + 3601, "empty")
            self.assertEqual(runner.run.call_count, 1)

    def test_replenishment_dispatch_throttled(self):
        runner = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            state = {}
            path = Path(temporary) / "status.json"
            now = time.time()
            scheduler.dispatch_replenishment(runner, state, path, now, "empty")
            scheduler.dispatch_replenishment(runner, state, path, now + 100, "empty")
            self.assertEqual(runner.run.call_count, 1)

    def test_failed_replenishment_retries_before_six_hours_and_then_throttles_success(self):
        runner = mock.Mock()
        runner.run.side_effect = [scheduler.CommandFailure("dispatch", 1, "temporary GitHub error"), (0, ""), (0, "")]
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(scheduler.random, "random", return_value=0.5):
            path = Path(temporary) / "state.json"
            state = {}
            scheduler.dispatch_replenishment(runner, state, path, now, "empty")
            self.assertNotIn("last_replenishment_dispatched_at", state)
            self.assertEqual(state["next_replenishment_retry_at"], now + 60)
            scheduler.dispatch_replenishment(runner, state, path, now + 30, "empty")
            self.assertEqual(runner.run.call_count, 1)
            scheduler.dispatch_replenishment(runner, state, path, now + 61, "empty")
            self.assertEqual(runner.run.call_count, 2)
            self.assertEqual(state["last_replenishment_dispatched_at"], now + 61)
            self.assertEqual(state["next_replenishment_retry_at"], 0)
            self.assertNotIn("last_replenishment_error", state)
            scheduler.dispatch_replenishment(runner, state, path, now + 100, "empty")
            self.assertEqual(runner.run.call_count, 2)
            scheduler.dispatch_replenishment(runner, state, path, now + 61 + 6 * 3600, "empty")
            self.assertEqual(runner.run.call_count, 3)

    def test_unchanged_successful_input_retries_pending_low_pool_dispatch(self):
        now = time.time()
        calls = []
        class FakeRunner:
            def __init__(self, repo, deadline): self.repo = repo
            def git(self, *args, **kwargs): return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
            def fetch(self): pass
            def run(self, command, *args, **kwargs): calls.append(command); return 0, ""
            def stop(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            state_dir = path / "state"
            scheduler.atomic_json(state_dir / "regional-scheduler-status.json", {"last_validated_signature": "same", "last_validated_at": now - 100, "last_local_qualified": 2, "next_replenishment_retry_at": now - 10})
            with mock.patch.object(scheduler, "Runner", FakeRunner), mock.patch.object(scheduler, "input_metadata", return_value=("same", now)):
                self.assertEqual(scheduler.run_scheduler(path, state_dir), 0)
            self.assertTrue(any(command[:3] == ["gh", "workflow", "run"] for command in calls))
            self.assertFalse(any("scripts/local_probe.py" in command for command in calls))

    def test_owned_logs_rotate_without_touching_unrelated_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "regional-refresh.log").write_text("old log")
            unrelated = directory / "unrelated.log"
            unrelated.write_text("keep")
            scheduler.rotate_logs(directory, limit=3)
            self.assertEqual((directory / "regional-refresh.log.1").read_text(), "old log")
            self.assertEqual(unrelated.read_text(), "keep")

    def test_kernel_lock_skips_overlap_without_modifying_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (directory / "regional-scheduler.lock").open("a+") as lock:
                scheduler.fcntl.flock(lock, scheduler.fcntl.LOCK_EX | scheduler.fcntl.LOCK_NB)
                self.assertEqual(scheduler.run_scheduler(directory, directory), 0)
            self.assertFalse((directory / "regional-scheduler-status.json").exists())

    def test_installer_is_scoped_and_preserves_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            repo = home / "runtime"
            (repo / "scripts").mkdir(parents=True)
            (repo / "scripts/regional_scheduler.py").write_text("# test")
            plist = home / "Library/LaunchAgents" / f"{installer.LABEL}.plist"
            plist.parent.mkdir(parents=True)
            plist.write_bytes(plistlib.dumps({"EnvironmentVariables": {"EXISTING_AUTH_SETTING": "preserved"}}))
            with mock.patch.object(installer.subprocess, "run") as run:
                installer.install(home, repo, Path(sys.executable), load=False)
            run.assert_not_called()
            value = plistlib.loads(plist.read_bytes())
            self.assertEqual(value["StartInterval"], 900)
            self.assertEqual(value["EnvironmentVariables"]["EXISTING_AUTH_SETTING"], "preserved")
            self.assertTrue(value["RunAtLoad"])
            self.assertEqual(value["Label"], installer.LABEL)
            launcher = home / "Library/Application Support/best50-vpn/regional-bootstrap.sh"
            self.assertIn("regional_scheduler.py", launcher.read_text())
            self.assertNotIn("git fetch", launcher.read_text())


if __name__ == "__main__":
    unittest.main()
