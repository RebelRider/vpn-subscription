"""Fault injection for optional local state, with no external network probes."""
import asyncio
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scheduler = load("state_recovery_scheduler", "regional_scheduler.py")
local = load("state_recovery_local", "local_probe.py")


def identifier(index):
    return format(index, "064x")


def record(now, **changes):
    return {"last_seen": now - 10, "runs": 5, "passes": 3, "qualified": True, **changes}


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


class SchedulerRecoveryTests(unittest.TestCase):
    def test_invalid_retry_fields_cannot_disable_work_forever(self):
        now = time.time()
        for invalid in ("tomorrow", None, True, -1, float("nan"), float("inf"),
                        now + scheduler.MAX_RETRY_FUTURE_SECONDS + 1, 10 ** 400):
            for name in ("next_retry_at", "next_replenishment_retry_at"):
                with self.subTest(value=repr(invalid), field=name):
                    state, recovered = scheduler.normalize_scheduler_state({
                        "last_validated_signature": "same", "last_validated_at": now - 8 * 3600,
                        name: invalid,
                    }, now)
                    self.assertNotIn(name, state)
                    self.assertIn(name, recovered)
                    self.assertTrue(scheduler.validation_due(state, "same", now))

    def test_valid_backoff_and_last_known_good_evidence_are_preserved(self):
        now = time.time()
        original = {"last_published_at": now - 100, "last_published_validation_at": now - 150,
                    "last_published_count": 3, "last_validated_at": now - 150,
                    "last_validated_signature": "same", "next_retry_at": now + 60,
                    "consecutive_failures": 2}
        state, recovered = scheduler.normalize_scheduler_state(original, now)
        self.assertEqual(recovered, [])
        for key, value in original.items():
            self.assertEqual(state[key], value)
        self.assertFalse(state["published_stale"])
        self.assertFalse(scheduler.validation_due(state, "same", now))

    def test_corrupt_publication_time_never_invents_freshness(self):
        now = time.time()
        for invalid in (None, "yesterday", True, float("nan"), now + 10000):
            state, _ = scheduler.normalize_scheduler_state({
                "last_published_at": now - 100, "last_published_count": 3,
                "last_validated_at": now - 10, "last_published_validation_at": invalid,
                "published_stale": False,
            }, now)
            self.assertEqual(state["last_published_at"], now - 100)
            self.assertEqual(state["last_published_count"], 3)
            self.assertTrue(state["published_stale"])

    def test_counters_shapes_and_nonfinite_values_are_not_trusted(self):
        now = time.time()
        state, recovered = scheduler.normalize_scheduler_state({
            "consecutive_failures": "many", "replenishment_consecutive_failures": -1,
            "last_local_qualified": True, "last_published_count": 51,
            "running": "yes", "last_validated_signature": [],
            "last_service_totals": {"chatgpt": {"attempts": float("nan")}},
            "unknown": {"value": float("nan")},
        }, now)
        self.assertTrue(state["published_stale"])
        self.assertEqual(set(state), {"published_stale"})
        self.assertIn("unknown-field", recovered)
        json.dumps(state, allow_nan=False)

    def test_malformed_oversized_deep_or_nonobject_state_recovers(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            for data in (b"{broken", b"[]", b"[" * 2000 + b"]" * 2000,
                         b"x" * (scheduler.MAX_STATE_BYTES + 1)):
                with self.subTest(size=len(data)):
                    path.write_bytes(data)
                    with patch.object(scheduler, "log") as log:
                        state = scheduler.load_scheduler_state(path)
                    self.assertEqual(state["state_recovery_count"], 1)
                    self.assertNotIn("last_published_at", state)
                    log.assert_called_once()

    def test_corrupt_state_then_healthy_run_recovers_without_manual_deletion(self):
        now = time.time()
        calls = []
        class FakeRunner:
            def __init__(self, repo, deadline): self.repo = repo
            def git(self, *args, **kwargs):
                return "" if args[0] == "status" else "main" if args[0] == "branch" else "sha"
            def fetch(self): pass
            def run(self, command, *args, **kwargs):
                calls.append(command)
                return 0, "healthy simulated local publication"
            def stop(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "output").mkdir()
            (repo / "output/local-status.json").write_text(json.dumps({
                "generated_at": stamp(now), "stability": {"qualified": 12},
                "nodes": [{}] * 12, "diagnostics": [],
            }))
            state_dir = repo / "state"
            state_dir.mkdir()
            path = state_dir / "regional-scheduler-status.json"
            path.write_text(json.dumps({"running": True, "next_retry_at": float("nan"),
                                       "last_published_at": "yesterday", "last_published_count": 3}))
            with patch.object(scheduler, "Runner", FakeRunner), \
                    patch.object(scheduler, "input_metadata", return_value=("same", now)):
                self.assertEqual(scheduler.run_scheduler(repo, state_dir), 0)
            state = scheduler.load_scheduler_state(path)
            self.assertTrue(any("scripts/local_probe.py" in command for command in calls))
            self.assertFalse(state["running"])
            self.assertEqual(state["last_published_count"], 12)
            self.assertEqual(state["next_retry_at"], 0)
            self.assertFalse(state["published_stale"])


class ReliabilityRecoveryTests(unittest.TestCase):
    def test_invalid_record_fields_and_expired_records_are_discarded(self):
        now = time.time()
        invalid = [record(now, last_seen="yesterday"), record(now, last_seen=True),
                   record(now, last_seen=float("nan")), record(now, last_seen=now + 10000),
                   record(now, last_seen=10 ** 400), record(now, last_seen=now - 29 * 86400),
                   record(now, runs="five"), record(now, runs=True), record(now, runs=-3),
                   record(now, runs=101), record(now, passes=6), record(now, passes=False),
                   record(now, qualified="yes"), record(now, passes=0, qualified=True)]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            value = {identifier(1): record(now), "short-hash": record(now), identifier(2): []}
            value.update({identifier(index + 3): item for index, item in enumerate(invalid)})
            path.write_text(json.dumps(value))
            self.assertEqual(local.load_local_reliability(path, now), {identifier(1): record(now)})

    def test_nonobject_malformed_deep_and_oversized_history_recovers_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            for data in (b"[]", b"{broken", b"[" * 2000 + b"]" * 2000,
                         b"x" * (local.MAX_PERSISTED_JSON_BYTES + 1)):
                with self.subTest(size=len(data)):
                    path.write_bytes(data)
                    self.assertEqual(local.load_local_reliability(path), {})

    def test_history_retains_at_most_5000_most_recent_records(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            path.write_text(json.dumps({identifier(index): record(now, last_seen=now - index)
                                        for index in range(5001)}))
            history = local.load_local_reliability(path, now)
            self.assertEqual(len(history), 5000)
            self.assertIn(identifier(0), history)
            self.assertNotIn(identifier(5000), history)

    def test_corrupt_history_is_rebuilt_by_subsequent_healthy_validation(self):
        now = time.time()
        link, key = "vless://test#DE-test", identifier(1)
        services = {name: {"passed": 3, "attempts": 3, "reasons": ["ok"] * 3}
                    for name in ("chatgpt", "youtube", "instagram")}
        report = {"qualified": True, "services": services, "median_ms": 100,
                  "p95_ms": 100, "latency_samples_ms": [100, 100, 100],
                  "validated_at": stamp(now), "rejection_reasons": []}
        build = SimpleNamespace(CFG={}, parse_vless=lambda value: {}, normalized_fingerprint=lambda node: key)
        service = SimpleNamespace(validate_candidates=AsyncMock(return_value={link: report}))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "local-reliability.json"
            path.write_text("[]")
            with patch.object(local, "STATE_DIR", directory), patch.object(local, "load_service_probe", return_value=service), \
                    patch.object(local, "route_interface", return_value="en0"):
                qualified, _ = asyncio.run(local.run_local_probe(build, [link], 3, 3, "simulated"))
            self.assertEqual(qualified, [link])
            self.assertEqual(local.load_local_reliability(path)[key],
                             {"last_seen": int(json.loads(path.read_text())[key]["last_seen"]),
                      "runs": 1, "passes": 1, "qualified": True, "outcome": "pass"})


class HealthRecoveryTests(unittest.TestCase):
    def test_invalid_previous_health_cannot_block_a_valid_current_report(self):
        now = time.time()
        invalid = (b"{broken", b"[]", b"{}", b'{"latest_attempt_at":NaN}',
                   b'{"latest_attempt_at":"bad"}', b'{"latest_attempt_at":"2026-01-01T12:00:00"}',
                   json.dumps({"latest_attempt_at": stamp(now + 10000)}).encode(),
                   b"x" * (local.MAX_PERSISTED_JSON_BYTES + 1))
        for previous in invalid:
            with self.subTest(previous=previous[:80]), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                calls = []
                written = []
                def fake_git(*args, **kwargs):
                    calls.append(args)
                    if args[:2] == ("worktree", "add"):
                        worktree = Path(args[3])
                        (worktree / "output").mkdir(parents=True)
                        (worktree / "output/local-health.json").write_bytes(previous)
                    return ""
                real_write = local.write_status
                def capture(path, value):
                    written.append(value)
                    real_write(path, value)
                with patch.object(local, "STATE_DIR", state), patch.object(local, "git_output", side_effect=fake_git), \
                        patch.object(local, "write_status", side_effect=capture), \
                        patch.object(local.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                    local.publish_regional_health({"generated_at": stamp(now), "stability": {"qualified": 0}})
                self.assertTrue(any(command[0] == "push" for command in calls))
                self.assertEqual(len(written), 1)
                self.assertFalse(written[0]["current_policy_validated"])

    def test_valid_newer_previous_health_is_preserved(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def fake_git(*args, **kwargs):
                if args[:2] == ("worktree", "add"):
                    worktree = Path(args[3])
                    (worktree / "output").mkdir(parents=True)
                    (worktree / "output/local-health.json").write_text(json.dumps({"latest_attempt_at": stamp(now)}))
                return ""
            with patch.object(local, "STATE_DIR", directory), patch.object(local, "git_output", side_effect=fake_git) as git, \
                    patch.object(local, "write_status") as write, patch.object(local.subprocess, "run"):
                local.publish_regional_health({"generated_at": stamp(now - 10), "stability": {"qualified": 0}})
            write.assert_not_called()
            self.assertFalse(any(call.args[0] == "push" for call in git.call_args_list))

    def test_invalid_current_health_is_rejected_before_git(self):
        now = time.time()
        invalid = ({"generated_at": "bad", "stability": {"qualified": 0}},
                   {"generated_at": stamp(now + 10000), "stability": {"qualified": 0}},
                   {"generated_at": stamp(now - 7 * 3600), "stability": {"qualified": 0}},
                   {"generated_at": stamp(now), "stability": []},
                   {"generated_at": stamp(now), "stability": {"qualified": True}},
                   {"generated_at": stamp(now), "stability": {"qualified": 51}})
        with patch.object(local, "git_output") as git:
            for status in invalid:
                with self.subTest(status=status), self.assertRaises(RuntimeError):
                    local.publish_regional_health(status)
            git.assert_not_called()


if __name__ == "__main__":
    unittest.main()
