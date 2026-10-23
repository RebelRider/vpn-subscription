import importlib.util
import json
import math
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000.0
MODELS = "auto - Auto\ncursor-grok-4.6-xhigh - Grok 4.6 Extra High\ngrok-4.7-xhigh - Grok 4.7 Extra High\ngrok-4.7-fast - Grok 4.7 Fast\n"
EMPTY = json.dumps({"schema": 1, "sources": []})
PROPOSAL = json.dumps({"schema": 1, "sources": [{"url": "https://public.example/feed.txt", "evidence_url": "https://public.example/about", "name": "Public feed", "protocols": ["vless", "hysteria2"]}]})


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


research = load("source_research_test", "source_research.py")
installer = load("install_source_research_test", "install_source_research.py")


def stream(result=PROPOSAL, model="Grok 4.7 Extra High"):
    return "\n".join(json.dumps(event) for event in [
        {"type": "system", "subtype": "init", "model": model},
        {"type": "tool_result", "text": '{"schema":1,"sources":["untrusted-tool-output"]}'},
        {"type": "assistant", "message": "ignored commentary"},
        {"type": "result", "subtype": "success", "is_error": False, "result": result},
    ])


class FakeRunner:
    responses = []
    instances = []
    def __init__(self, repo, deadline):
        self.repo, self.deadline = repo, deadline
        self.calls = []
        self.stopped = False
        self.assert_empty = list(repo.iterdir()) == []
        FakeRunner.instances.append(self)
    def run(self, command, label, timeout=90, **kwargs):
        self.calls.append((command, timeout, dict(os.environ)))
        if not FakeRunner.responses:
            raise AssertionError("unexpected agent call")
        return FakeRunner.responses.pop(0)
    def stop(self): self.stopped = True


class SourceResearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / "runtime"
        self.repo.mkdir()
        self.state = self.directory / "state"
        self.state.mkdir()
        FakeRunner.instances = []
        FakeRunner.responses = []
        self.catalog_patcher = mock.patch("source_catalog.load_regional_sources", return_value=([], {}))
        self.catalog_context = self.catalog_patcher.start()
        self.addCleanup(self.catalog_patcher.stop)
    def tearDown(self): self.temporary.cleanup()
    def status(self): return json.loads((self.state / research.STATE_NAME).read_text())
    def run_research(self, now=NOW, outcome=None):
        if outcome is None: outcome = {"accepted": 1, "added": 1, "refreshed": 0, "published": True}
        with mock.patch.object(research, "Runner", FakeRunner), mock.patch.object(research, "process_catalog", return_value=outcome) as publish:
            code = research.run_once(self.repo, self.state, now=now, agent="/fake/agent")
        return code, publish

    def test_quota_failure_then_time_advance_verified_model_and_promotion(self):
        FakeRunner.responses = [(1, "ActionRequiredError: You're out of usage token=must-not-log")]
        code, publish = self.run_research()
        self.assertEqual(code, 1)
        publish.assert_not_called()
        self.assertEqual(self.status()["last_error"], "quota")
        self.assertEqual(self.status()["next_retry_at"], NOW + 3600)
        self.assertNotIn("last_success_at", self.status())
        self.assertNotIn("must-not-log", (self.state / research.STATE_NAME).read_text())
        self.assertEqual(self.run_research(NOW + 1800)[0], 0)
        self.assertEqual(len(FakeRunner.instances), 1)
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        code, publish = self.run_research(NOW + 3601)
        self.assertEqual(code, 0)
        self.assertEqual(publish.call_args.args[0], PROPOSAL)
        state = self.status()
        self.assertEqual(state["model_id"], "grok-4.7-xhigh")
        self.assertEqual(state["last_success_at"], NOW + 3601)
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertFalse((self.state / research.PENDING_NAME).exists())
        worker = FakeRunner.instances[-1]
        self.assertTrue(worker.assert_empty)
        self.assertNotEqual(worker.repo, self.repo)
        self.assertTrue(worker.stopped)
        command, timeout, environment = worker.calls[1]
        self.assertEqual(timeout, 1800)
        self.assertEqual(worker.calls[0][1], 15)
        self.assertIn("--mode=ask", command)
        self.assertIn("--trust", command)
        self.assertNotIn("--force", command)
        self.assertIn("stream-json", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "enabled")
        self.assertNotIn("GH_TOKEN", environment)
        self.assertFalse(worker.repo.exists())

    def test_strict_strongest_model_selection_refuses_weaker_or_fast_fallback(self):
        self.assertEqual(research.select_model(MODELS), ("grok-4.7-xhigh", "4.7"))
        for invalid in ("auto - Auto", MODELS + "grok-4.8-fast - Grok 4.8 Fast\n", MODELS + "grok-newest - Grok Newest\n", "grok-4.7-xhigh - Grok 4.7 Extra High Fast"):
            with self.subTest(invalid=invalid), self.assertRaises(research.ResearchFailure):
                research.select_model(invalid)

    def test_wrong_model_malformed_and_oversized_stream_fail_closed(self):
        for text, error in ((stream(model="Grok 4.6 Extra High"), "unverified-model"), (stream(model="Grok 4.7 Extra High Fast"), "unverified-model"), ("not JSON", "invalid-output"), (json.dumps({"type": "result", "result": EMPTY}), "unverified-model"), (stream(result="```json\n{}\n```"), "invalid-output"), (stream() + "\n" + json.dumps({"type": "tool_call"}), "invalid-output"), ("x" * (research.OUTPUT_LIMIT + 1), "output-limit")):
            with self.subTest(error=error), self.assertRaisesRegex(research.ResearchFailure, error):
                research.verified_result(text, "4.7")
        self.assertEqual(research.verified_result(stream(), "4.7"), PROPOSAL)

    def test_schema_rejects_duplicate_keys_or_configs_instead_of_sources(self):
        for invalid in ('{"schema":1,"schema":1,"sources":[]}', '{"schema":true,"sources":[]}', '{"schema":1.0,"sources":[]}', '{"schema":1,"sources":["vless://private-config"]}', json.dumps({"schema": 1, "sources": [] * 0, "extra": "untrusted"})):
            with self.assertRaises(research.ResearchFailure): research.parse_proposal(invalid)

    def test_timeout_remains_pending_and_owned_runner_is_stopped(self):
        FakeRunner.responses = [(0, MODELS), (124, "")]
        code, publish = self.run_research()
        self.assertEqual(code, 1)
        self.assertEqual(self.status()["last_error"], "timeout")
        self.assertFalse(self.status()["running"])
        self.assertTrue(FakeRunner.instances[0].stopped)
        publish.assert_not_called()

    def test_interruption_keeps_retryable_state_and_restores_handlers(self):
        original = research.signal.getsignal(research.signal.SIGTERM)
        with mock.patch.object(research, "research", side_effect=KeyboardInterrupt):
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW, agent="fake"), 1)
        self.assertEqual(self.status()["last_error"], "interrupted")
        self.assertFalse(self.status()["running"])
        self.assertIs(research.signal.getsignal(research.signal.SIGTERM), original)

    def test_success_is_persisted_before_pending_proposal_is_deleted(self):
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        original = Path.unlink
        observed = []
        def unlink(path, *args, **kwargs):
            if path == self.state / research.PENDING_NAME:
                observed.append(self.status().get("last_success_at"))
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "unlink", unlink):
            self.assertEqual(self.run_research()[0], 0)
        self.assertEqual(observed, [NOW])

    def test_publication_retry_uses_pending_without_new_agent_quota(self):
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        with mock.patch.object(research, "Runner", FakeRunner), mock.patch.object(research, "process_catalog", side_effect=RuntimeError("temporary GitHub error; no raw logging")):
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW, agent="fake"), 1)
        pending = self.state / research.PENDING_NAME
        self.assertTrue(pending.exists())
        self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o600)
        self.assertEqual(self.status()["last_error"], "publication")
        with mock.patch.object(research, "research", side_effect=AssertionError("agent must not rerun")), mock.patch.object(research, "process_catalog", return_value={"accepted": 1, "added": 0, "published": False}) as publish:
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW + 3601), 0)
        publish.assert_called_once()
        self.assertEqual(self.status()["last_research_generated_at"], NOW)
        self.assertEqual(self.status()["last_success_at"], NOW + 3601)
        self.assertFalse(pending.exists())

    def test_source_retry_after_preserves_pending_and_waits_without_new_agent(self):
        class Unavailable(RuntimeError):
            retry_at = NOW + 12 * 3600
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        with mock.patch.object(research, "Runner", FakeRunner), mock.patch.object(research, "process_catalog", side_effect=Unavailable):
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW, agent="fake"), 1)
        self.assertEqual(self.status()["next_retry_at"], NOW + 12 * 3600)
        self.assertTrue((self.state / research.PENDING_NAME).exists())
        with mock.patch.object(research, "research", side_effect=AssertionError("no new agent quota")), mock.patch.object(research, "process_catalog", return_value={"accepted": 1, "added": 1, "published": True}) as publish:
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW + 3600), 0)
            publish.assert_not_called()
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW + 12 * 3600), 0)
            publish.assert_called_once()
        self.assertEqual(self.status()["last_research_generated_at"], NOW)
        self.assertNotIn("source_retry_after_at", self.status())
        self.assertEqual(len(FakeRunner.instances), 1)

    def test_source_policy_wait_survives_pending_expiration_and_invalid_deadlines(self):
        pending = self.state / research.PENDING_NAME
        research.atomic_json(pending, {"schema": 1, "generated_at": NOW - research.DAY - 1, "model_id": "grok-4.7-xhigh", "result": EMPTY})
        research.atomic_json(self.state / research.STATE_NAME, {"schema": 1, "next_retry_at": NOW + research.DAY, "source_retry_after_at": NOW + research.DAY})
        with mock.patch.object(research, "research", side_effect=AssertionError("honor server wait")), mock.patch.object(research, "process_catalog") as publish:
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW), 0)
            publish.assert_not_called()
        self.assertFalse(pending.exists())
        self.assertEqual(self.status()["next_retry_at"], NOW + research.DAY)
        for invalid in (float("inf"), 10 ** 1000, NOW + research.DAY + 1, "tomorrow", True):
            state = research.normalize_state({"schema": 1, "next_retry_at": invalid, "source_retry_after_at": invalid}, NOW)
            self.assertNotIn("next_retry_at", state)
            self.assertNotIn("source_retry_after_at", state)

    def test_empty_proposal_is_successful_daily_research(self):
        FakeRunner.responses = [(0, MODELS), (0, stream(result=EMPTY))]
        self.assertEqual(self.run_research(outcome={"accepted": 0, "added": 0, "published": False})[0], 0)
        self.assertEqual(self.status()["last_success_at"], NOW)
        self.assertFalse(self.status()["published"])

    def test_huge_numbers_and_deep_state_proposals_and_pending_fail_closed(self):
        self.assertFalse(research.finite_number(10 ** 1000))
        self.assertFalse(research.finite_number(-(10 ** 1000)))
        path = self.state / research.STATE_NAME
        path.write_text(json.dumps({"schema": 1, "next_retry_at": 10 ** 1000, "last_success_at": 10 ** 1000}))
        state = research.load_state(path, NOW)
        self.assertNotIn("next_retry_at", state)
        self.assertNotIn("last_success_at", state)
        deep = "[" * 2000 + "0" + "]" * 2000
        path.write_text(deep)
        self.assertEqual(research.load_state(path, NOW)["status"], "pending")
        with self.assertRaisesRegex(research.ResearchFailure, "invalid-output"):
            research.parse_proposal(deep)
        with self.assertRaisesRegex(research.ResearchFailure, "invalid-output"):
            research.verified_result(deep, "4.7")
        pending = self.state / research.PENDING_NAME
        pending.write_text(deep)
        self.assertIsNone(research.load_pending(pending, NOW))
        research.atomic_json(pending, {"schema": 1, "generated_at": 10 ** 1000, "model_id": "grok-4.7-xhigh", "result": EMPTY})
        self.assertIsNone(research.load_pending(pending, NOW))
        research.atomic_json(pending, {"schema": 1, "generated_at": NOW, "model_id": "grok-4.7-xhigh", "result": deep})
        self.assertIsNone(research.load_pending(pending, NOW))
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        self.assertEqual(self.run_research()[0], 0)

    def test_prompt_contains_bounded_canonical_public_context_only(self):
        sources = [{"url": "https://github.com/public/repo/blob/main/feed.txt"},
                   {"url": "https://feed.example/sub?token=private-token"},
                   {"url": "https://user:password@feed.example/feed.txt"},
                   {"url": "https://127.0.0.1/private/feed.txt"},
                   {"url": "https://feed.example/private/credentials.txt"},
                   {"url": "https://feed.example/sub/550e8400-e29b-41d4-a716-446655440000"},
                   {"url": "vless://private-config"}, {"url": "/Users/private/local-file"}]
        (self.repo / "config.json").write_text(json.dumps({"sources": sources}))
        self.catalog_context.return_value = (["https://regional.example/public-feed.txt"], {"active": 1})
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        self.assertEqual(self.run_research()[0], 0)
        prompt = FakeRunner.instances[0].calls[1][0][2]
        self.assertIn("https://raw.githubusercontent.com/public/repo/main/feed.txt", prompt)
        self.assertIn("https://regional.example/public-feed.txt", prompt)
        self.assertIn("Prefer previously unknown alternatives", prompt)
        self.assertIn("supported-protocol authority", prompt)
        for forbidden in ("private-token", "user:password", "127.0.0.1", "/Users/private", "private-config", "550e8400", "TUIC"):
            self.assertNotIn(forbidden, prompt)
        sources = [{"url": f"https://source.example/feed-{index}.txt"} for index in range(100)]
        (self.repo / "config.json").write_text(json.dumps({"sources": sources}))
        context = research.existing_source_context(self.repo)
        urls = json.loads(context[context.index("["):])
        self.assertEqual(len(urls), 64)
        self.assertLessEqual(len(context), 17 * 1024)

    def test_deep_source_context_is_optional_and_recovers(self):
        (self.repo / "config.json").write_text("[" * 2000 + "0" + "]" * 2000)
        self.assertEqual(research.existing_source_context(self.repo), "")

    def test_daily_interval_and_hourly_poll_do_not_spend_extra_quota(self):
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        self.assertEqual(self.run_research()[0], 0)
        self.assertEqual(self.run_research(NOW + 3600)[0], 0)
        self.assertEqual(self.run_research(NOW + research.DAY - 1)[0], 0)
        self.assertEqual(len(FakeRunner.instances), 1)
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        self.assertEqual(self.run_research(NOW + research.DAY)[0], 0)
        self.assertEqual(len(FakeRunner.instances), 2)

    def test_initial_defer_is_seeded_once_without_agent_call(self):
        with mock.patch.object(research, "research", side_effect=AssertionError("do not call agent")):
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW, defer_hours=1), 0)
            self.assertEqual(research.run_once(self.repo, self.state, now=NOW + 10, defer_hours=1), 0)
        self.assertEqual(self.status()["next_retry_at"], NOW + 3600)
        self.assertNotIn("last_attempt_at", self.status())
        self.assertNotIn("last_success_at", self.status())

    def test_kernel_lock_skips_overlap_without_mutating_status(self):
        with (self.state / "source-research.lock").open("a+") as lock:
            research.fcntl.flock(lock, research.fcntl.LOCK_EX | research.fcntl.LOCK_NB)
            with mock.patch.object(research, "research", side_effect=AssertionError("overlap")):
                self.assertEqual(research.run_once(self.repo, self.state, now=NOW), 0)
        self.assertFalse((self.state / research.STATE_NAME).exists())

    def test_corrupt_state_recovers_without_stranded_retry(self):
        path = self.state / research.STATE_NAME
        for content in ("not JSON", json.dumps({"schema": 1, "next_retry_at": float("inf"), "last_research_generated_at": 1e99, "consecutive_failures": "bad", "accepted": float("nan")}), json.dumps({"schema": True, "next_retry_at": NOW + 1000000}), json.dumps({"schema": 1, "status": [], "last_error": {"unexpected": "object"}, "next_retry_at": "forever", "running": True})):
            with self.subTest(content=content):
                path.write_text(content)
                FakeRunner.responses = [(0, MODELS), (0, stream())]
                self.assertEqual(self.run_research()[0], 0)
                self.assertEqual(self.status()["consecutive_failures"], 0)
                self.assertEqual(self.status()["last_success_at"], NOW)

    def test_expired_pending_proposal_triggers_new_verified_research(self):
        research.atomic_json(self.state / research.PENDING_NAME, {"schema": 1, "generated_at": NOW - research.DAY - 1, "model_id": "grok-4.7-xhigh", "result": EMPTY})
        research.atomic_json(self.state / research.STATE_NAME, {"schema": 1, "next_retry_at": NOW + 4 * 3600})
        FakeRunner.responses = [(0, MODELS), (0, stream())]
        self.assertEqual(self.run_research()[0], 0)
        self.assertEqual(len(FakeRunner.instances), 1)

    def test_repeated_failures_keep_bounded_six_hour_retry_and_success_history(self):
        research.atomic_json(self.state / research.STATE_NAME, {"schema": 1, "last_success_at": NOW - 2 * research.DAY, "last_research_generated_at": NOW - 2 * research.DAY})
        now = NOW
        for expected in (1, 2, 4, 6, 6):
            FakeRunner.responses = [(1, "Cursor is not available in your region")]
            self.assertEqual(self.run_research(now)[0], 1)
            state = self.status()
            self.assertEqual(state["next_retry_at"] - now, expected * 3600)
            self.assertEqual(state["last_success_at"], NOW - 2 * research.DAY)
            now = state["next_retry_at"]

    def test_agent_environment_excludes_git_tokens_and_restores_parent(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "private", "GITHUB_TOKEN": "private2", "CURSOR_API_KEY": "cursor-auth", "HOME": "/home/test"}, clear=True):
            with research.cursor_environment():
                self.assertNotIn("GH_TOKEN", os.environ)
                self.assertNotIn("GITHUB_TOKEN", os.environ)
                self.assertEqual(os.environ["CURSOR_API_KEY"], "cursor-auth")
            self.assertEqual(os.environ["GH_TOKEN"], "private")

    def test_installer_is_scoped_atomic_and_preserves_existing_state(self):
        home = self.directory / "home"
        runtime = home / "runtime"
        (runtime / "scripts").mkdir(parents=True)
        (runtime / "scripts/source_research.py").write_text("# fixture")
        with mock.patch.object(installer.subprocess, "run") as launchctl:
            path = installer.install(home, runtime, Path(sys.executable), load=False, defer_hours=1)
        launchctl.assert_not_called()
        value = plistlib.loads(path.read_bytes())
        self.assertEqual(value["Label"], "com.rebelrider.best50-source-research")
        self.assertEqual(value["StartInterval"], 3600)
        self.assertTrue(value["RunAtLoad"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        state_path = home / "Library/Application Support/best50-vpn" / research.STATE_NAME
        original = state_path.read_bytes()
        value["EnvironmentVariables"]["EXISTING_AUTH"] = "preserved"
        path.write_bytes(plistlib.dumps(value))
        installer.install(home, runtime, Path(sys.executable), load=False, defer_hours=6)
        self.assertEqual(state_path.read_bytes(), original)
        self.assertEqual(plistlib.loads(path.read_bytes())["EnvironmentVariables"]["EXISTING_AUTH"], "preserved")
        self.assertFalse((path.parent / "com.rebelrider.best50-regional-refresh.plist").exists())

    def test_installer_respects_the_source_research_kernel_lock(self):
        home = self.directory / "home"
        runtime = home / "runtime"
        (runtime / "scripts").mkdir(parents=True)
        (runtime / "scripts/source_research.py").write_text("# fixture")
        state = home / "Library/Application Support/best50-vpn"
        state.mkdir(parents=True)
        with (state / "source-research.lock").open("a+") as lock:
            research.fcntl.flock(lock, research.fcntl.LOCK_EX | research.fcntl.LOCK_NB)
            with mock.patch.object(installer.subprocess, "run") as launchctl:
                with self.assertRaisesRegex(RuntimeError, "running"):
                    installer.install(home, runtime, Path(sys.executable), load=True)
        launchctl.assert_not_called()
        self.assertFalse((state / research.STATE_NAME).exists())

    def test_installer_refuses_to_reload_running_job(self):
        home = self.directory / "home"
        runtime = home / "runtime"
        (runtime / "scripts").mkdir(parents=True)
        (runtime / "scripts/source_research.py").write_text("# fixture")
        active = mock.Mock(returncode=0, stdout="state = running\n")
        with mock.patch.object(installer.subprocess, "run", return_value=active) as launchctl:
            with self.assertRaisesRegex(RuntimeError, "active"):
                installer.install(home, runtime, Path(sys.executable), load=True)
        self.assertEqual(launchctl.call_count, 1)
        self.assertIn(installer.LABEL, launchctl.call_args.args[0][-1])


if __name__ == "__main__":
    unittest.main()
