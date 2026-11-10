"""Controlled daily lifecycle; no live model, network or production mutations."""
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qwen_worker_test", ROOT / "scripts/qwen_discovery.py")
worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
from qwen_lmstudio import LMStudioBusy, LMStudioError

NOW = 1794355320.0


class FakeTools:
    def __init__(self, *args, **kwargs): self.calls = []
    def seed_queries(self): return []
    def execute(self, value): self.calls.append(value); return {"status": "ok", "candidate_count": 1}
    def proposal(self): return {"schema": 1, "sources": [{"url": "https://public.example/feed.txt", "evidence_url": "https://public.example/about"}]}
    def public_metadata(self): return {"schema": 1, "candidates": [{"id": "f" * 64}]}
    def snapshot(self): return {"schema": 1}
    def save_private_cache(self): pass


class FakeLease:
    responses = []
    closed = False
    starts = 0
    def __init__(self, *args): pass
    def __enter__(self): FakeLease.starts += 1; return self
    def __exit__(self, *args): FakeLease.closed = True
    def complete(self, *args, **kwargs):
        answer = self.responses.pop(0)
        if isinstance(answer, BaseException): raise answer
        return answer


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / "repo"; self.repo.mkdir()
        self.state = Path(self.temporary.name) / "qwen"
        self.coordination = Path(self.temporary.name) / "coordination"
        self.promotions, self.publications = [], []
        FakeLease.responses = ['{"action":"fetch","url":"https://public.example/feed.txt"}', '{"action":"finish"}']
        FakeLease.starts = 0; FakeLease.closed = False
    def promote(self, *args, **kwargs): self.promotions.append(args); return {"added": 1, "published": True}
    def publish(self, *args, **kwargs): self.publications.append(args); return {"published": True, "pr_url": None}
    def execute(self, **kwargs):
        return worker.execute(self.repo, self.state, lease_factory=FakeLease, tools_factory=FakeTools,
                              publisher=self.publish, promoter=self.promote, **kwargs)
    def read(self, name): return json.loads((self.state / name).read_text())

    def test_dry_run_uses_model_and_tools_without_publication(self):
        self.assertEqual(self.execute(dry_run=True), 0)
        self.assertTrue(FakeLease.closed)
        self.assertTrue(self.read(worker.RESULT)["model_success"])
        self.assertEqual(self.read(worker.RESULT)["status"], "controlled-test")
        self.assertFalse(self.promotions); self.assertFalse(self.publications)

    def test_pending_github_retry_never_reloads_model_or_repeats_catalog_admission(self):
        calls = 0
        def fail_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1: raise RuntimeError("do-not-log-raw-private-token")
            return {"published": True}
        with patch.object(self, "publish", side_effect=fail_once):
            self.assertEqual(self.execute(), 1)
            self.assertEqual(self.execute(), 0)
        self.assertEqual(FakeLease.starts, 1)
        self.assertEqual(len(self.promotions), 1)
        self.assertNotIn("private-token", (self.state / worker.RESULT).read_text())
        self.assertFalse((self.state / worker.PENDING).exists())

    def test_invalid_output_is_not_executable_or_published(self):
        FakeLease.responses = ['{"action":"shell","command":"rm -rf /"}'] * 3
        self.assertEqual(self.execute(iterations=3), 1)
        self.assertEqual(self.read(worker.RESULT)["error"], "invalid-model-output")
        self.assertFalse(self.promotions); self.assertFalse(self.publications)

    def test_api_error_or_interruption_closes_owned_lease_and_preserves_outputs(self):
        for error in (LMStudioError("lm-api-authentication"), KeyboardInterrupt()):
            FakeLease.responses = [error]
            artifact = self.repo / "best-local.txt"; artifact.write_text("unchanged production proof")
            self.assertEqual(self.execute(), 1)
            self.assertTrue(FakeLease.closed)
            self.assertEqual(artifact.read_text(), "unchanged production proof")
            self.assertFalse(self.publications)

    def test_closed_action_schema_rejects_duplicate_keys_extra_paths_and_controls(self):
        for value in ('{"action":"finish","path":".github/workflows/build.yml"}',
                      '{"action":"finish","action":"fetch"}', '["finish"]',
                      '{"action":"fetch","url":"https://example.com/\\n"}'):
            with self.subTest(value=value), self.assertRaises(worker.DiscoveryError): worker.action(value)
        self.assertEqual(worker.action('{"action":"finish"}'), {"action": "finish"})

    def test_query_length_matches_deterministic_tool_boundary(self):
        self.assertEqual(worker.action(json.dumps({"action": "search", "query": "x" * 160}))["query"], "x" * 160)
        with self.assertRaises(worker.DiscoveryError):
            worker.action(json.dumps({"action": "search", "query": "x" * 161}))

    def test_rejected_tool_inputs_use_bounded_model_repair(self):
        FakeLease.responses = [json.dumps({"action": "fetch", "url": "http://127.0.0.1/private"}),
                               json.dumps({"action": "search", "query": "https://example.com/secret"}),
                               '{"action":"fetch","url":"https://public.example/feed.txt"}',
                               '{"action":"finish"}']
        self.assertEqual(self.execute(iterations=4, dry_run=True), 0)
        self.assertTrue(self.read(worker.RESULT)["model_success"])
        self.assertFalse(self.promotions)

    def runner(self, *, valid=True, interrupt=False):
        state = self.state
        class FakeRunner:
            def __init__(self, *args): pass
            def stop(self): pass
            def run(self, *args, **kwargs):
                if interrupt: raise KeyboardInterrupt()
                if valid:
                    worker.atomic_json(state / worker.RESULT, {"schema": 1, "started_at": NOW,
                        "finished_at": NOW + 1, "dry_run": False, "model_success": True, "status": "empty"})
                return 0, ""
        return FakeRunner
    def poll(self, **kwargs):
        return worker.poll(self.repo, self.state, now=NOW, coordination_dir=self.coordination, **kwargs)

    def test_initial_install_waits_for_next_slot_then_missed_days_coalesce_once(self):
        runner = self.runner()
        self.assertEqual(self.poll(runner_factory=runner), 0)
        self.assertEqual(self.read(worker.STATE)["status"], "scheduled")
        worker.atomic_json(self.state / worker.STATE, {"last_completed_slot": "2026-11-01", "not_before": 0})
        self.assertEqual(self.poll(runner_factory=runner), 0)
        self.assertEqual(self.read(worker.STATE)["last_completed_slot"], worker.latest_due_slot(NOW)[0])
        with patch.object(runner, "run", side_effect=AssertionError("duplicate day")):
            self.assertEqual(self.poll(runner_factory=runner), 0)

    def test_overlap_skips_without_starting_worker(self):
        self.state.mkdir()
        with (self.state / "qwen-discovery.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.poll(run_now=True, runner_factory=lambda *a: self.fail("overlap")), 0)

    def test_old_github_replay_does_not_consume_todays_discovery(self):
        runner = self.runner()
        original = runner.run
        previous_slot = worker.latest_due_slot(NOW - 86400)[0]
        def replay(instance, *args, **kwargs):
            result = original(instance, *args, **kwargs)
            row = self.read(worker.RESULT)
            row["discovery_slot"] = previous_slot
            worker.atomic_json(self.state / worker.RESULT, row)
            return result
        with patch.object(runner, "run", replay):
            self.assertEqual(self.poll(run_now=True, runner_factory=runner), 0)
        self.assertEqual(self.read(worker.STATE)["last_completed_slot"], previous_slot)
        self.assertEqual(self.poll(runner_factory=self.runner()), 0)
        self.assertEqual(self.read(worker.STATE)["last_completed_slot"], worker.latest_due_slot(NOW)[0])

    def test_stale_success_marker_cannot_confirm_a_failed_or_absent_worker(self):
        self.state.mkdir()
        worker.atomic_json(self.state / worker.RESULT, {"schema": 1, "started_at": NOW - 86400,
            "finished_at": NOW - 86399, "dry_run": False, "model_success": True, "status": "success"})
        self.assertEqual(self.poll(run_now=True, runner_factory=self.runner(valid=False)), 1)
        self.assertNotIn("last_completed_slot", self.read(worker.STATE))

    def test_parent_interruption_records_retry_and_releases_locks(self):
        self.assertEqual(self.poll(run_now=True, runner_factory=self.runner(interrupt=True)), 1)
        state = self.read(worker.STATE)
        self.assertFalse(state["running"]); self.assertEqual(state["status"], "interrupted")
        self.assertEqual(state["next_retry_at"], NOW + 300)
        self.assertEqual(self.poll(run_now=True, runner_factory=self.runner()), 0)

    def test_due_validation_window_and_active_probe_lock_defer_without_model_work(self):
        self.coordination.mkdir()
        worker.atomic_json(self.coordination / "regional-scheduler-status.json", {
            "last_validated_at": NOW - 3500, "last_local_qualified": 1, "health": "current"})
        self.assertEqual(self.poll(run_now=True, runner_factory=lambda *a: self.fail("unsafe overlap")), 0)
        self.assertEqual(self.read(worker.STATE)["status"], "deferred-validation-window")
        worker.atomic_json(self.coordination / "regional-scheduler-status.json", {
            "last_validated_at": NOW - 10, "last_local_qualified": 1, "health": "current"})
        with (self.coordination / "local-probe.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.poll(run_now=True, runner_factory=lambda *a: self.fail("probe active")), 0)
        self.assertEqual(self.read(worker.STATE)["status"], "deferred-validation-busy")

    def test_corrupt_far_future_not_before_cannot_disable_discovery_forever(self):
        self.state.mkdir()
        worker.atomic_json(self.state / worker.STATE, {"not_before": NOW + 10**8})
        self.assertEqual(self.poll(runner_factory=self.runner()), 0)
        self.assertEqual(self.read(worker.STATE)["status"], "success")

    def test_first_login_after_missed_installed_schedule_runs_one_catchup(self):
        self.state.mkdir()
        worker.atomic_json(self.state / "installation.json", {"schema": 1, "installed_at": NOW - 2 * 86400})
        self.assertEqual(self.poll(runner_factory=self.runner()), 0)
        self.assertEqual(self.read(worker.STATE)["last_completed_slot"], worker.latest_due_slot(NOW)[0])

    def test_qwen_operational_logs_use_shared_bounded_rotation_allowlist(self):
        logs = Path(self.temporary.name) / "logs"; logs.mkdir()
        target = logs / "qwen-discovery.log"; target.write_text("owned log")
        foreign = logs / "another-project.log"; foreign.write_text("preserve")
        worker.rotate_logs(logs, limit=1, names=("qwen-discovery.log", "qwen-discovery-error.log"))
        self.assertEqual((logs / "qwen-discovery.log.1").read_text(), "owned log")
        self.assertEqual(foreign.read_text(), "preserve")

    def test_prompt_keeps_generation_and_template_context_headroom(self):
        messages = worker.messages_for([{"text": "я" * 30000, "status": "ok"}] * 4)
        self.assertLessEqual(len(json.dumps(messages, ensure_ascii=False).encode()),
                             worker.CONFIG["context_length"] - 4096 - 512)

    def test_actual_source_checkpoint_survives_later_generation_failure_without_reload(self):
        FakeLease.responses = ['{"action":"fetch","url":"https://public.example/feed.txt"}',
                               LMStudioError("model-output-truncated")]
        self.assertEqual(self.execute(), 1)
        self.assertTrue((self.state / worker.PENDING).exists())
        self.assertEqual(self.execute(), 0)
        self.assertEqual(FakeLease.starts, 1)
        self.assertEqual(len(self.publications), 1)

    def test_daily_admission_deferrals_survive_public_ack_and_progress_without_model(self):
        self.state.mkdir()
        rows = [{"url": f"https://public.example/{i}.txt", "evidence_url": "https://public.example/about"} for i in range(12)]
        calls = []
        def promote(proposal, *args, **kwargs):
            calls.append(proposal)
            return {"added": min(8, len(proposal["sources"])), "deferred_sources": proposal["sources"][8:]}
        worker.admit({"schema": 1, "sources": rows}, self.repo, self.state, promote)
        self.assertEqual(len(self.read(worker.BACKLOG)["sources"]), 4)
        class Busy(FakeLease):
            def __enter__(self): raise LMStudioBusy("foreign-loaded-model-preserved")
        self.assertEqual(worker.execute(self.repo, self.state, lease_factory=Busy, tools_factory=FakeTools,
                                       promoter=promote, publisher=self.publish), 75)
        self.assertFalse(self.read(worker.BACKLOG)["sources"])
        self.assertEqual(len(calls[1]["sources"]), 4)

    def test_empty_dry_run_cannot_be_replayed_as_a_new_model_execution(self):
        class Empty(FakeTools):
            def proposal(self): return {"schema": 1, "sources": []}
            def public_metadata(self): return {"schema": 1, "candidates": []}
        for _ in range(2):
            FakeLease.responses = ['{"action":"finish"}']
            self.assertEqual(worker.execute(self.repo, self.state, dry_run=True, lease_factory=FakeLease,
                                           tools_factory=Empty, publisher=self.publish, promoter=self.promote), 0)
        self.assertEqual(FakeLease.starts, 2)


if __name__ == "__main__": unittest.main()
