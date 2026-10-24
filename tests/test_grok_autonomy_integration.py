"""Joined recovery proof with real parsers and a local, atomic Git remote.

Only Grok's transport and public HTTP responses are simulated. The research
state machine, proposal validation, feed parser, catalog transaction, retry
proposal replay and final source-pool ingestion are the production code.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import source_catalog as catalog
import source_discovery as discovery
import source_research as research


FEED = "https://public.example/previously-unknown.txt"
INVALID_FEED = "https://public.example/incompatible.txt"
EVIDENCE = "https://public.example/about"
UUID = "11111111-1111-4111-8111-111111111111"
LINK = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com"
MODELS = "grok-4.6-xhigh - Grok 4.6 Extra High\ngrok-4.7-xhigh - Grok 4.7 Extra High\n"


class GrokAutonomyIntegrationTests(unittest.TestCase):
    def test_quota_restoration_pending_replay_real_promotion_and_ingestion(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repo = directory / "runtime"
            repo.mkdir()
            remote = directory / "remote.git"
            state = directory / "state"
            now = time.time()

            def git(*arguments, cwd=repo):
                return subprocess.check_output(
                    ["git", *arguments], cwd=cwd, text=True,
                    stderr=subprocess.DEVNULL, timeout=15,
                ).strip()

            git("init", "--bare", str(remote))
            git("init", "-b", "main")
            (repo / "output").mkdir()
            retained = "retained known-good public subscription\n"
            (repo / "output/best-local.txt").write_text(retained)
            git("add", ".")
            git("-c", "user.name=Autonomy Test", "-c", "user.email=test@example.invalid",
                "commit", "-m", "initial retained artifact")
            git("remote", "add", "origin", str(remote))
            git("push", "origin", "HEAD:refs/heads/regional")
            initial_remote = git("ls-remote", "origin", "refs/heads/regional")

            # A real receive hook rejects the first catalog transaction's
            # three bounded pushes. Its next push succeeds on the later poll.
            # No publication function, Git runner or parser is mocked.
            hook = remote / "hooks/pre-receive"
            hook.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\nimport sys\n"
                "counter=Path(__file__).with_name('controlled-push-count')\n"
                "number=int(counter.read_text())+1 if counter.exists() else 1\n"
                "counter.write_text(str(number))\n"
                "if number<=3:\n"
                " sys.stderr.write('Controlled temporary Git publication failure\\n')\n"
                " sys.exit(1)\n"
            )
            hook.chmod(0o700)

            proposal = json.dumps({"schema": 1, "sources": [
                {"url": FEED, "evidence_url": EVIDENCE, "name": "New public feed",
                 # The real parser, not the model's protocol claim, decides.
                 "protocols": ["wireguard"]},
                {"url": INVALID_FEED, "evidence_url": EVIDENCE, "name": "Unusable feed",
                 "protocols": ["vless"]},
                {"url": "https://127.0.0.1/private", "evidence_url": EVIDENCE,
                 "name": "Must never be fetched"},
            ]})
            success_stream = "\n".join(json.dumps(event) for event in (
                {"type": "system", "subtype": "init", "model": "Grok 4.7 Extra High"},
                {"type": "result", "subtype": "success", "is_error": False, "result": proposal},
            ))
            responses = [
                (0, MODELS),
                (1, "ActionRequiredError: You're out of usage; token=must-not-persist"),
                (0, MODELS),
                (0, success_stream),
            ]
            workers, model_calls, http_calls = [], [], []

            class ModelTransport:
                def __init__(self, workspace, deadline):
                    self.repo = workspace
                    self.stopped = False
                    workers.append(self)
                    self_test.assertEqual(list(workspace.iterdir()), [])
                    self_test.assertNotEqual(workspace, repo)

                def run(self, command, label, timeout=90, **kwargs):
                    model_calls.append(command)
                    self_test.assertEqual(command[0], "/fake/agent")
                    self_test.assertTrue(responses, "pending replay must not call Grok again")
                    return responses.pop(0)

                def stop(self):
                    self.stopped = True

            self_test = self

            def public_http(url, **kwargs):
                http_calls.append(url)
                if url == "https://public.example/robots.txt":
                    return b"User-agent: *\nAllow: /\n", {}
                if url == FEED:
                    return (LINK + "\n").encode(), {"content-type": "text/plain"}
                if url == INVALID_FEED:
                    return b"tuic://unsupported@1.1.1.1:443\n", {"content-type": "text/plain"}
                if urlsplit(url).hostname == "api.github.com":
                    return b'{"items":[]}', {"content-type": "application/json"}
                self.fail("unexpected public HTTP request: " + url)

            def status():
                return json.loads((state / research.STATE_NAME).read_text())

            with patch.object(research, "Runner", ModelTransport), \
                 patch.object(discovery, "safe_get", side_effect=public_http):
                self.assertEqual(research.run_once(repo, state, now=now, agent="/fake/agent"), 1)
                self.assertEqual(status()["last_error"], "quota")
                self.assertNotIn("last_success_at", status())
                self.assertFalse((state / research.PENDING_NAME).exists())
                self.assertNotIn("must-not-persist", (state / research.STATE_NAME).read_text())
                self.assertEqual(http_calls, [])
                self.assertEqual(git("ls-remote", "origin", "refs/heads/regional"), initial_remote)

                # The next hourly poll before quota retry does no model work.
                self.assertEqual(research.run_once(repo, state, now=now + 1800, agent="/fake/agent"), 0)
                self.assertEqual(len(model_calls), 2)

                restored = now + 3601
                self.assertEqual(research.run_once(repo, state, now=restored, agent="/fake/agent"), 1)
                self.assertEqual(status()["last_error"], "publication")
                self.assertEqual(status()["model_id"], "grok-4.7-xhigh")
                self.assertTrue((state / research.PENDING_NAME).is_file())
                self.assertEqual(len(model_calls), 4)
                self.assertEqual((remote / "hooks/controlled-push-count").read_text(), "3")
                self.assertEqual(git("ls-remote", "origin", "refs/heads/regional"), initial_remote)
                self.assertNotIn("last_success_at", status())

                retry = status()["next_retry_at"]
                self.assertEqual(research.run_once(repo, state, now=retry - 1, agent="/fake/agent"), 0)
                self.assertEqual(len(model_calls), 4)
                self.assertEqual(research.run_once(repo, state, now=retry + 1, agent="/fake/agent"), 0)
                current = status()
                self.assertEqual(current["status"], "success")
                self.assertEqual(current["consecutive_failures"], 0)
                self.assertEqual(current["accepted"], 1)
                self.assertEqual(current["added"], 1)
                self.assertIs(current["published"], True)
                self.assertFalse((state / research.PENDING_NAME).exists())
                self.assertEqual(len(model_calls), 4)
                self.assertEqual(responses, [])
                self.assertEqual((remote / "hooks/controlled-push-count").read_text(), "4")

                # Both production readers use this same loader. A fresh real
                # SourcePool consumes the newly published catalog, including
                # policy checks, extraction, persistence and provenance.
                sources, summary = catalog.load_regional_sources(repo, now=retry + 1)
                self.assertEqual(sources, [FEED])
                self.assertEqual(summary, {"status": "available", "active": 1})
                pool = discovery.SourcePool([], state / "ingested-discovery.json", now=int(retry + 1))
                self.assertTrue(pool.add(sources[0], origin="grok-research"))
                links, stats = pool.collect()
                self.assertEqual(links, [LINK])
                self.assertEqual(pool.stats["fetched_sources"], 1)
                self.assertEqual(len(stats), 1)
                self.assertTrue(pool.link_sources[LINK])

                # Daily success gating remains unattended without reusing quota.
                self.assertEqual(research.run_once(repo, state, now=retry + 3601, agent="/fake/agent"), 0)
                self.assertEqual(len(model_calls), 4)

            self.assertTrue(all(worker.stopped and not worker.repo.exists() for worker in workers))
            raw_catalog = git("show", "origin/regional:" + catalog.CATALOG_PATH)
            self.assertNotIn(UUID, raw_catalog)
            self.assertNotIn("protocols", raw_catalog)
            self.assertNotIn("127.0.0.1", raw_catalog)
            self.assertNotIn(INVALID_FEED, raw_catalog)
            self.assertEqual(git("show", "origin/regional:output/best-local.txt") + "\n", retained)
            self.assertEqual(git("worktree", "list", "--porcelain").count("worktree "), 1)
            self.assertEqual(list((state / "temporary").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
