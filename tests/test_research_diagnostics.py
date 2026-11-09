"""Controlled CLI/transport diagnostics; no tests invoke a real model."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import regional_scheduler as scheduler
from scripts import source_research as research
from scripts import source_catalog as catalog

MODELS = "grok-4.7-xhigh - Grok 4.7 Extra High\n"
EMPTY = json.dumps({"schema": 1, "sources": []})
FEED = "https://public.example/new-feed.txt"
LINK = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com"
SECRET = "must-not-persist-private-token"


def stream(final=EMPTY):
    return "\n".join(json.dumps(item) for item in (
        {"type": "system", "subtype": "init", "model": "Grok 4.7 Extra High " + SECRET},
        {"type": "assistant", "message": SECRET},
        {"type": "result", "subtype": "success", "is_error": False, "result": final},
    ))


class FakeRunner:
    responses = []
    calls = []
    def __init__(self, *args):
        self.last_stderr = ""
        self.last_output_metadata = {}
    def run(self, command, *args, **kwargs):
        self.calls.append((command, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        code, text, self.last_stderr = response
        return code, text
    def stop(self):
        pass


class SplitRunnerTests(unittest.TestCase):
    def test_real_owned_child_stdout_and_stderr_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            worker = scheduler.Runner(Path(directory), time.monotonic() + 10)
            code, text = worker.run([sys.executable, "-c", "import sys;print('{\"schema\":1}');sys.stderr.write('warning: public diagnostic\\n')"],
                                    "controlled local output", separate_stderr=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text), {"schema": 1})
        self.assertIn("warning", worker.last_stderr)
        self.assertEqual(worker.last_output_metadata["stdout_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertGreater(worker.last_output_metadata["stderr_bytes"], 0)

    def test_combined_output_limit_covers_fast_exiting_stderr_writer(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(scheduler, "MAX_OUTPUT_BYTES", 128):
            worker = scheduler.Runner(Path(directory), time.monotonic() + 10)
            code, text = worker.run([sys.executable, "-c", "import sys;sys.stdout.write('a'*64);sys.stderr.write('b'*128)"],
                                    "controlled bounded output", separate_stderr=True, check=False)
        self.assertEqual(code, 124)
        self.assertLessEqual(len(text) + len(worker.last_stderr), 128)
        self.assertTrue(worker.last_output_metadata["stderr_truncated"])


class ResearchAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / "repo"
        self.state = Path(self.temporary.name) / "state"
        self.repo.mkdir(); self.state.mkdir()
        self.now = time.time()
        FakeRunner.responses, FakeRunner.calls = [], []
        for target, replacement in (("Runner", FakeRunner), ("run_independent_catalog", lambda *args: {}),
                                    ("existing_source_context", lambda *args: "")):
            patcher = patch.object(research, target, replacement);patcher.start();self.addCleanup(patcher.stop)

    def run_once(self, now=None):
        return research.run_once(self.repo, self.state, now=self.now if now is None else now, agent="/fake/agent")

    def status(self):
        return json.loads((self.state / research.STATE_NAME).read_text())

    def test_warning_stderr_cannot_corrupt_valid_stream_or_enter_audit(self):
        FakeRunner.responses = [(0, MODELS, ""), (0, stream(), "Warning token=" + SECRET)]
        with patch.object(research, "process_catalog", return_value={"accepted": 0, "published": False}):
            self.assertEqual(self.run_once(), 0)
        state = self.status();audit = state["last_model_diagnostic"]
        self.assertTrue(audit["model_success"])
        self.assertEqual(audit["stage"], "model-complete")
        self.assertEqual(audit["verified_model"], "grok-4.7-xhigh")
        self.assertEqual(audit["event_counts"], {"system": 1, "assistant": 1, "result": 1})
        self.assertGreater(audit["stderr_bytes"], 0)
        self.assertEqual(audit["catalog_status"], "current")
        self.assertIn("last_model_success_at", state)
        self.assertNotIn("last_catalog_publication_at", state)
        self.assertTrue(all(options["separate_stderr"] for _, options in FakeRunner.calls))
        for name in (research.STATE_NAME, research.ATTEMPT_HISTORY, research.RESEARCH_HISTORY):
            self.assertNotIn(SECRET, (self.state / name).read_text())

    def test_invalid_output_gets_granular_safe_failure_and_no_success(self):
        FakeRunner.responses = [(0, MODELS, ""), (0, "not-json " + SECRET, "Authorization: Bearer " + SECRET)]
        with patch.object(research, "process_catalog") as publisher:
            self.assertEqual(self.run_once(), 1)
        publisher.assert_not_called()
        state = self.status();audit = state["last_model_diagnostic"]
        self.assertEqual(audit["failure_code"], "stream-not-json")
        self.assertEqual(audit["stage"], "stream")
        self.assertFalse(audit["model_success"])
        self.assertNotIn("last_model_success_at", state)
        for path in self.state.glob("*.json"):
            self.assertNotIn(SECRET, path.read_text())

    def test_interruption_is_a_failed_attempt_and_restored_quota_is_only_simulated(self):
        FakeRunner.responses = [(0, MODELS, ""), KeyboardInterrupt()]
        self.assertEqual(self.run_once(), 1)
        self.assertEqual(self.status()["last_model_diagnostic"]["failure_code"], "interrupted")
        self.assertNotIn("last_model_success_at", self.status())
        FakeRunner.responses = [(0, MODELS, ""), (1, "", "quota exceeded token=" + SECRET)]
        self.assertEqual(self.run_once(self.now + 3601), 1)
        self.assertEqual(self.status()["last_error"], "quota")
        calls = len(FakeRunner.calls)
        self.assertEqual(self.run_once(self.now + 4000), 0)
        self.assertEqual(len(FakeRunner.calls), calls)
        FakeRunner.responses = [(0, MODELS, ""), (0, stream(), "")]
        retry = self.status()["next_retry_at"] + 1
        with patch.object(research, "process_catalog", return_value={"accepted": 1, "published": True}):
            self.assertEqual(self.run_once(retry), 0)
        self.assertEqual(self.status()["last_model_success_at"], retry)
        self.assertEqual(self.status()["last_catalog_publication_at"], retry)

    def test_catalog_failure_keeps_model_success_and_replays_without_model(self):
        FakeRunner.responses = [(0, MODELS, ""), (0, stream(), "")]
        with patch.object(research, "process_catalog", side_effect=RuntimeError(SECRET)):
            self.assertEqual(self.run_once(), 1)
        state = self.status()
        self.assertEqual(state["last_model_success_at"], self.now)
        self.assertEqual(state["last_model_diagnostic"]["catalog_status"], "failed")
        self.assertTrue((self.state / research.PENDING_NAME).exists())
        calls = len(FakeRunner.calls)
        with patch.object(research, "process_catalog", return_value={"accepted": 1, "published": True}):
            self.assertEqual(self.run_once(state["next_retry_at"] + 1), 0)
        self.assertEqual(len(FakeRunner.calls), calls)
        self.assertEqual(len(json.loads((self.state / research.ATTEMPT_HISTORY).read_text())), 1)

    def test_unknown_diagnostic_fields_and_untrusted_values_are_removed(self):
        clean = research.safe_attempt({"stage": SECRET, "cli_version": SECRET,
            "verified_model": SECRET, "raw_output": SECRET, "failure_code": SECRET,
            "event_counts": {SECRET: 1, "assistant": 2}, "model_success": True})
        self.assertEqual(clean, {"event_counts": {"assistant": 2}, "model_success": True})

    def test_attempt_history_is_bounded_and_reloaded_through_closed_schema(self):
        previous = [{"at": self.now - i, "stage": "models", "raw_output": SECRET}
                    for i in range(100)]
        path = self.state / research.ATTEMPT_HISTORY
        path.write_text(json.dumps(previous))
        research.append_attempt_history(self.state, {"at": self.now, "stage": "model-run", "raw_output": SECRET}, self.now)
        values = json.loads(path.read_text())
        self.assertEqual(len(values), 64)
        self.assertNotIn(SECRET, path.read_text())


class SourceProvenanceTests(unittest.TestCase):
    def test_new_sources_record_finder_but_legacy_refresh_never_invents_one(self):
        now = time.time()
        legacy = {"url": FEED, "evidence_url": FEED, "first_seen": now - 100,
                  "last_verified_at": now - 100, "enabled": True}
        new = {**legacy, "last_verified_at": now, "discovered_by": "grok", "discovery_model": "grok-4.7-xhigh"}
        result = catalog._merge_catalog({"sources": [legacy]}, [new], now)
        self.assertNotIn("discovered_by", result["sources"][0])
        parsed = catalog.parse_catalog(json.dumps({"schema": 1, "sources": [new]}).encode(), now)
        self.assertEqual(parsed["sources"][0]["discovered_by"], "grok")
        self.assertEqual(parsed["sources"][0]["discovery_model"], "grok-4.7-xhigh")
        del new["discovered_by"]
        parsed = catalog.parse_catalog(json.dumps({"schema": 1, "sources": [new]}).encode(), now)
        self.assertNotIn("discovery_model", parsed["sources"][0])

    def test_verified_new_feed_carries_actual_actor_metadata(self):
        proposal = json.dumps({"schema": 1, "sources": [{"url": FEED, "evidence_url": FEED}]})
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "_git_blob", return_value=b"{}"), \
                patch.object(catalog.SourcePool, "allowed", return_value=True), \
                patch.object(catalog.SourcePool, "get", return_value=(LINK.encode(), {})), \
                patch.object(catalog, "publish_catalog", return_value=True) as publisher:
            catalog.process_research_result(proposal, Path(directory), Path(directory), time.time(),
                                             discovered_by="grok", model_id="grok-4.7-xhigh")
        update = publisher.call_args.args[2][0]
        self.assertEqual(update["discovered_by"], "grok")
        self.assertEqual(update["discovery_model"], "grok-4.7-xhigh")

    def test_productive_serbia_and_main_registries_join_without_writing_them(self):
        import regional_pool
        now = time.time()
        main = {"url": FEED, "candidate_count": 1, "failures": 0, "last_success": now - 20}
        serbia = [{**main, "last_success": now - 1, "candidate_count": 8},
                  {**main, "url": "https://another.example/serbia.txt"}]
        loaded = []
        class Registry:
            def __init__(self, seeds, path, **kwargs):
                loaded.append(path)
                self.sources = {str(i): value for i, value in enumerate(serbia if path.parent.name == "serbia" else [main])}
            def collect(self):
                raise AssertionError("Productive regional feeds avoid a second standalone collection")
        with tempfile.TemporaryDirectory() as directory, patch.object(regional_pool, "PrivateSourcePool", Registry):
            proposal = json.loads(catalog.independent_proposal(Path(directory), now))
        self.assertEqual({x["url"] for x in proposal["sources"]}, {FEED, "https://another.example/serbia.txt"})
        self.assertEqual(len(loaded), 2)


if __name__ == "__main__":
    unittest.main()
