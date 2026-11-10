"""Resource ownership and bounded local inference; never starts LM Studio."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from scripts import qwen_lmstudio as lm


class FakeLMStudio:
    def __init__(self, directory, *, running=False, models=None, desktop=False):
        self.directory = directory
        self.backend = 500 if running else None
        self.server = running
        self.port = 1234 if running else 12431
        self.models = dict(models or {})
        self.desktop = desktop
        self.calls, self.requests, self.terminated = [], [], []
        self.generation = "original"
        self.load_key = "qwen3.8-27b"
        self.fail = None
        self.answer = {"choices": [{"finish_reason": "stop", "message": {"content": '{"action":"finish"}'}}]}

    def identity(self, pid):
        return {"pid": pid, "started": self.generation, "executable": "LM Studio"} if pid == self.backend else None

    def terminate(self, identity):
        if identity != self.identity(identity["pid"]):
            return False
        self.terminated.append(identity["pid"])
        self.backend, self.server = None, False
        return True

    def command(self, argv, timeout):
        args = argv[1:]
        self.calls.append(args)
        assert 0 < timeout <= 180
        if args[:2] == ["daemon", "status"]:
            return 0, json.dumps({"status": "not-running"} if self.backend is None else
                                 {"status": "running", "pid": self.backend, "isDaemon": not self.desktop})
        if args[:2] == ["server", "status"]:
            return 0, json.dumps({"running": self.server, **({"port": self.port} if self.server else {})})
        if args[:2] == ["ps", "--json"]:
            return 0, json.dumps([{"identifier": key} for key in self.models])
        if args[:2] == ["ls", "--json"]:
            return 0, json.dumps([{"modelKey": self.load_key, "path": lm.MODEL_KEY,
                                  "indexedModelIdentifier": lm.MODEL_KEY, "format": "safetensors", "deviceIdentifier": None}])
        if args[:2] in (["daemon", "up"], ["server", "start"]) or args[0] == "load":
            journal = json.loads((self.directory / lm.JOURNAL).read_text())
            assert journal["schema"] == 1  # Persist intention before each action.
        if args[:2] == ["daemon", "up"]:
            self.backend = 500
            return 0, json.dumps({"status": "running", "pid": 500, "isDaemon": not self.desktop})
        if args[:2] == ["server", "start"]:
            self.server, self.port = True, int(args[args.index("--port") + 1])
            if self.fail == "start":
                return 1, "untrusted authentication secret"
            return 0, "started"
        if args[0] == "load":
            identifier = args[args.index("--identifier") + 1]
            assert journal["model_load_intent"] is True and journal["model_identifier"] == identifier
            assert args[1] == self.load_key
            self.models[identifier] = self.load_key
            if self.fail == "load":
                raise lm.LMStudioError("cli-timeout-or-output-limit")
            return 0, "loaded"
        if args[0] == "unload":
            assert args[1].startswith(lm.PREFIX) and len(args) == 2
            self.models.pop(args[1], None)
            return 0, "unloaded"
        if args[:2] == ["server", "stop"]:
            self.server = False
            return 0, "stopped"
        raise AssertionError("Unexpected command")

    def http(self, method, base_url, path, payload, timeout):
        self.requests.append((method, base_url, path, payload))
        if self.fail == "api":
            raise urllib.error.HTTPError(base_url, 401, "secret-private-token", {}, None)
        if path == "/api/v1/models":
            groups = {lm.MODEL_KEY: []}
            for key, model in self.models.items():
                groups.setdefault(model, []).append({"id": key})
            return {"models": [{"key": key, "loaded_instances": values} for key, values in groups.items()]}
        if path == "/v1/chat/completions":
            return self.answer
        raise AssertionError("Unexpected HTTP path")


class LMStudioLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.state = self.directory / "state"
        self.state.mkdir()
        model = self.directory / "models" / lm.MODEL_KEY
        model.mkdir(parents=True)
        (model / "config.json").write_text("{}")
        (model / "model.safetensors.index.json").write_text("{}")
        self.config = {"model_dir": str(self.directory / "models")}
        self.fake = FakeLMStudio(self.state)

    def lease(self, **overrides):
        return lm.LMStudioLease(self.config, self.state, 1000, command=self.fake.command,
            http=self.fake.http, process_info=self.fake.identity, available_memory=lambda: 32 * 1024**3,
            terminate_process=self.fake.terminate, clock=lambda: 100, wall_clock=lambda: 200, **overrides)

    def test_owned_cold_start_complete_and_exact_cleanup(self):
        with self.lease() as client:
            self.assertEqual(client.complete([{"role": "user", "content": "Find public sources"}]), '{"action":"finish"}')
            identifier = client.model_identifier
            self.assertRegex(identifier, r"bestlocal-qwen-[0-9a-f]{24}")
            load = next(c for c in self.fake.calls if c[0] == "load")
            self.assertEqual(load[load.index("--context-length") + 1], "8192")
            self.assertEqual(load[load.index("--parallel") + 1], "1")
            self.assertEqual(load[load.index("--ttl") + 1], "300")
            self.assertIn("--yes", load)
            self.assertEqual((self.state / lm.JOURNAL).stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.fake.models)
        self.assertFalse(self.fake.server)
        self.assertEqual(self.fake.terminated, [500])
        self.assertFalse((self.state / lm.JOURNAL).exists())
        self.assertIn(["unload", identifier], self.fake.calls)

    def test_reuses_empty_running_server_without_reconfiguration_or_stopping_it(self):
        self.fake = FakeLMStudio(self.state, running=True)
        with self.lease() as client:
            self.assertEqual(client.base_url, "http://127.0.0.1:1234")
        self.assertTrue(self.fake.server)
        self.assertEqual(self.fake.terminated, [])
        self.assertFalse(any(c[:2] in (["server", "start"], ["server", "stop"], ["daemon", "up"]) for c in self.fake.calls))

    def test_foreign_qwen_and_other_models_are_deferred_not_reloaded_or_unloaded(self):
        for model in (lm.MODEL_KEY, "another/user-model"):
            self.fake = FakeLMStudio(self.state, running=True, models={"user-instance": model})
            with self.subTest(model=model), self.assertRaisesRegex(lm.LMStudioBusy, "foreign-loaded-model-preserved"):
                with self.lease():
                    self.fail("must defer")
            self.assertEqual(self.fake.models, {"user-instance": model})
            self.assertFalse(any(c[0] in {"load", "unload"} for c in self.fake.calls))
            self.assertTrue(self.fake.server)

    def test_existing_backend_foreign_model_is_detected_before_starting_rest(self):
        self.fake = FakeLMStudio(self.state, running=True, models={"user-instance": lm.MODEL_KEY})
        self.fake.server = False
        with self.assertRaises(lm.LMStudioBusy):
            with self.lease():
                pass
        self.assertFalse(any(c[:2] == ["server", "start"] for c in self.fake.calls))
        self.assertFalse((self.state / lm.JOURNAL).exists())

    def test_model_load_timeout_recovers_only_recorded_unique_instance(self):
        self.fake.fail = "load"
        with self.assertRaises(lm.LMStudioError):
            with self.lease():
                pass
        self.assertFalse(self.fake.models)
        self.assertEqual(len([c for c in self.fake.calls if c[0] == "unload"]), 1)

    def test_api_errors_are_sanitized_and_do_not_load_a_model(self):
        self.fake.fail = "api"
        with self.assertRaises(lm.LMStudioError) as caught:
            with self.lease():
                pass
        self.assertEqual(str(caught.exception), "api-authentication-required")
        self.assertNotIn("secret", json.dumps(self.fake.calls))
        self.assertFalse(any(c[0] == "load" for c in self.fake.calls))

    def test_interruption_cleans_own_model_and_releases_duplicate_lock(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.lease():
                with self.assertRaisesRegex(lm.LMStudioBusy, "another-lm-lease-active"):
                    with self.lease():
                        pass
                raise KeyboardInterrupt()
        self.assertFalse(self.fake.models)
        with self.lease():
            pass

    def test_foreign_adoption_preserves_backend_and_server(self):
        with self.lease():
            self.fake.models["foreign-new"] = "another/user-model"
        self.assertEqual(self.fake.models, {"foreign-new": "another/user-model"})
        self.assertTrue(self.fake.server)
        self.assertFalse(self.fake.terminated)

    def test_desktop_service_adoption_uncertainty_leaves_only_idle_app(self):
        self.fake.desktop = True
        with self.lease() as client:
            pass
        self.assertFalse(self.fake.models)
        self.assertFalse(self.fake.server)
        self.assertEqual(self.fake.backend, 500)
        self.assertIn({"action": "backend-cleanup", "outcome": "desktop-adoption-unconfirmed-left-idle"}, client.diagnostics)

    def test_pid_reuse_cannot_stop_replacement_process_or_unload_its_models(self):
        with self.lease():
            self.fake.generation = "replacement"
        self.assertTrue(self.fake.models)
        self.assertFalse(self.fake.terminated)
        self.assertFalse(any(c[0] == "unload" for c in self.fake.calls))

    def test_cleanup_only_recovers_crash_without_any_start_or_load(self):
        client = self.lease().__enter__()
        client.lock.close(); client.lock = None  # Simulate kernel lock release on process exit.
        before = len(self.fake.calls)
        events = lm.cleanup_owned_resources(self.config, self.state, 1000, command=self.fake.command,
            http=self.fake.http, process_info=self.fake.identity, terminate_process=self.fake.terminate,
            clock=lambda: 100)
        self.assertTrue(events)
        self.assertFalse(self.fake.models)
        self.assertFalse(any(c[0] == "load" or c[:2] in (["daemon", "up"], ["server", "start"]) for c in self.fake.calls[before:]))

    def test_low_or_unknown_memory_prevents_model_load(self):
        for amount in (None, 8 * 1024**3):
            self.fake = FakeLMStudio(self.state)
            client = self.lease()
            client.available_memory = lambda: amount
            with self.assertRaisesRegex(lm.LMStudioBusy, "insufficient-or-unconfirmed-memory"):
                with client:
                    pass
            self.assertFalse(any(c[0] == "load" for c in self.fake.calls))

    def test_server_start_failure_has_no_model_and_reaps_only_owned_daemon(self):
        self.fake.fail = "start"
        with self.assertRaisesRegex(lm.LMStudioError, "cli-request-failed"):
            with self.lease():
                pass
        self.assertFalse(self.fake.models)
        self.assertEqual(self.fake.terminated, [500])

    def test_untrusted_journal_cannot_name_a_foreign_model_for_cleanup(self):
        (self.state / lm.JOURNAL).write_text(json.dumps({"schema": 1, "nonce": "f" * 24,
            "model_key": lm.MODEL_KEY, "model_identifier": "user-instance"}))
        with self.assertRaisesRegex(lm.LMStudioBusy, "untrusted-resource-journal"):
            lm.cleanup_owned_resources(self.config, self.state, 1000, command=self.fake.command,
                http=self.fake.http, process_info=self.fake.identity, clock=lambda: 100)
        self.assertFalse(self.fake.calls)

    def test_private_corrupt_journal_recovers_without_guessing_model_ownership(self):
        self.state.chmod(0o700)
        journal = self.state / lm.JOURNAL
        journal.write_bytes(b'{"schema":1,"nonce":"partial')
        journal.chmod(0o600)
        # An old worker-looking instance is still foreign without a valid
        # ownership journal. Never guess its identity from its prefix.
        unknown = lm.PREFIX + "a" * 24
        self.fake = FakeLMStudio(self.state, running=True, models={unknown: lm.MODEL_KEY})
        client = self.lease()
        with self.assertRaisesRegex(lm.LMStudioBusy, "foreign-loaded-model-preserved"):
            with client:
                self.fail("unknown instance must be preserved")
        self.assertEqual(self.fake.models, {unknown: lm.MODEL_KEY})
        self.assertTrue(self.fake.server)
        self.assertFalse(any(call[0] in {"load", "unload"} for call in self.fake.calls))
        self.assertFalse(journal.exists())
        archive = self.state / lm.QUARANTINE
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertIn({"action": "cleanup", "outcome": "invalid-journal-quarantined"}, client.diagnostics)
        # Simulate the unknown instance's own expiry, not a worker unload.
        self.fake.models.clear()
        with self.lease():
            pass
        self.assertTrue(self.fake.server)  # Preexisting server remains untouched.

    def test_quarantine_is_bounded_and_preserves_unrelated_destinations(self):
        self.state.chmod(0o700)
        journal, archive = self.state / lm.JOURNAL, self.state / lm.QUARANTINE
        for content in (b"broken", b"x" * 100000):
            journal.write_bytes(content); journal.chmod(0o600)
            client = self.lease()
            self.assertIsNone(client._read_journal())
            data = json.loads(archive.read_text())
            self.assertEqual(data["original_size"], len(content))
            self.assertEqual(data["truncated"], len(content) > 16384)
            self.assertLess(archive.stat().st_size, 32768)
            self.assertFalse(journal.exists())
        archive.write_text('{"unrelated":"keep"}'); archive.chmod(0o600)
        journal.write_text("broken"); journal.chmod(0o600)
        with self.assertRaisesRegex(lm.LMStudioBusy, "untrusted-resource-journal"):
            self.lease()._read_journal()
        self.assertEqual(archive.read_text(), '{"unrelated":"keep"}')
        self.assertTrue(journal.exists())

    def test_unsafe_journal_paths_and_permissions_cannot_be_quarantined(self):
        self.state.chmod(0o700)
        journal = self.state / lm.JOURNAL
        external = self.directory / "unrelated.json"
        external.write_text("broken"); external.chmod(0o600)
        journal.symlink_to(external)
        with self.assertRaisesRegex(lm.LMStudioBusy, "untrusted-resource-journal"):
            self.lease()._read_journal()
        self.assertTrue(journal.is_symlink())
        self.assertEqual(external.read_text(), "broken")
        journal.unlink()
        journal.write_text("broken"); journal.chmod(0o644)
        with self.assertRaises(lm.LMStudioBusy):
            self.lease()._read_journal()
        journal.chmod(0o600)
        with patch.object(lm.os, "getuid", return_value=journal.stat().st_uid + 1):
            with self.assertRaises(lm.LMStudioBusy):
                self.lease()._read_journal()
        self.assertFalse((self.state / lm.QUARANTINE).exists())
        self.assertFalse(self.fake.calls)

    def test_expired_deadline_starts_nothing_and_unknown_model_key_is_refused(self):
        client = self.lease()
        client.deadline = 99
        with self.assertRaisesRegex(lm.LMStudioError, "lease-deadline"):
            with client:
                pass
        self.assertFalse(self.fake.calls)
        self.config["model_key"] = "another/download-me"
        with self.assertRaisesRegex(lm.LMStudioError, "invalid-lease-configuration"):
            self.lease()

    def test_reasoning_is_not_a_discovery_decision_and_truncation_is_rejected(self):
        with self.lease() as client:
            self.fake.answer["choices"][0]["message"].update(content='<think>private analysis</think>{"ok":true}', reasoning_content="private reasoning")
            self.assertEqual(client.complete([{"role": "user", "content": "public task"}]), '{"ok":true}')
            for content, finish in (("", "stop"), (None, "stop"), ('{"partial":', "length"), ("<think>only thoughts</think>", "stop")):
                self.fake.answer = {"choices": [{"finish_reason": finish, "message": {"content": content}}]}
                expected = "model-output-truncated" if finish == "length" else "model-output-incomplete"
                with self.subTest(finish=finish), self.assertRaisesRegex(lm.LMStudioError, expected):
                    client.complete([{"role": "user", "content": "public task"}])

    def test_context_and_output_limits_are_enforced_before_generation(self):
        with self.lease() as client:
            for messages, limit, reason in (([{"role": "user", "content": "x" * 30000}], 100, "context-budget-exceeded"),
                                            ([{"role": "user", "content": "ok"}], 999999, "invalid-output-budget")):
                with self.assertRaisesRegex(lm.LMStudioError, reason):
                    client.complete(messages, max_tokens=limit)

    def test_resolves_renamed_live_load_key_from_fixed_installed_artifact(self):
        self.fake.load_key = "renamed-qwen-local"
        with self.lease() as client:
            self.assertEqual(client.runtime_model_key, "renamed-qwen-local")
            self.assertEqual(self.fake.models[client.model_identifier], "renamed-qwen-local")
        self.assertFalse(self.fake.models)
        self.assertFalse(any(r[0] == "POST" for r in self.fake.requests))

    def test_default_http_disables_environment_proxies_and_redirects(self):
        client = self.lease()
        client.http_adapter = None
        client.base_url = "http://127.0.0.1:12431"
        response = io.BytesIO(b'{"models":[]}')
        with patch.object(lm.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            self.assertEqual(client._http("GET", "/api/v1/models"), {"models": []})
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], lm._NoRedirect)
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, "", {}, "https://outside.example/"))
        client.base_url = "https://outside.example"
        with self.assertRaisesRegex(lm.LMStudioError, "nonlocal-api-refused"):
            client._http("GET", "/api/v1/models")

    def test_cleanup_preserves_production_subscription_bytes(self):
        production = self.directory / "production"
        production.mkdir()
        files = {name: production / name for name in ("best-local.txt", "best-local-Serbia.txt")}
        for name, path in files.items():
            path.write_text("original " + name)
        before = {name: path.read_bytes() for name, path in files.items()}
        with self.lease():
            pass
        self.assertEqual(before, {name: path.read_bytes() for name, path in files.items()})


if __name__ == "__main__":
    unittest.main()
