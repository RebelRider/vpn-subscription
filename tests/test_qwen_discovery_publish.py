"""Data-only publication in controlled local Git repositories; no GitHub writes."""
import copy
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import qwen_discovery_publish as publish
from scripts import source_catalog as catalog
from scripts.regional_scheduler import Runner

FEED = "https://raw.githubusercontent.com/example/public/main/servers.txt"
LINK = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com"


def metadata(now, index=0):
    url = FEED if not index else FEED + "-" + str(index)
    digest = hashlib.sha256(("public-body-" + str(index)).encode()).hexdigest()
    return {"schema": 1, "worker": "qwen", "model": publish.MODEL_ID, "generated_at": now,
            "unverified_inputs": True,
            "sources": [{"url": url, "evidence_url": url, "fetched_at": now, "body_sha256": digest,
                         "candidate_count": 1, "serbia_hint_unverified": True}],
            "candidates": [{"id": hashlib.sha256(("candidate-" + str(index)).encode()).hexdigest(),
                            "protocol": "vless", "source_url": url, "observed_at": now,
                            "source_body_sha256": digest, "serbia_hint_unverified": True}]}


class MetadataTests(unittest.TestCase):
    def test_untrusted_extra_fields_paths_and_positive_claims_are_rejected(self):
        now = time.time()
        for mutate in (lambda row: row.update(path=".github/workflows/build.yml"),
                       lambda row: row["candidates"][0].update(link=LINK),
                       lambda row: row["candidates"][0].update(qualified=True),
                       lambda row: row["sources"][0].update(url="https://127.0.0.1/private"),
                       lambda row: row.update(generated_at=now + 86400),
                       lambda row: row.update(model="untrusted-model")):
            row = metadata(now); mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(publish.DiscoveryPublishFailure):
                publish.validate_metadata(row, now=now)

    def test_qwen_provenance_is_explicit_and_independently_fetched(self):
        now = time.time()
        proposal = json.dumps({"schema": 1, "sources": [{"url": FEED, "evidence_url": FEED}]})
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "_git_blob", side_effect=ValueError), \
                patch.object(catalog.SourcePool, "allowed", return_value=True), \
                patch.object(catalog.SourcePool, "get", return_value=(LINK.encode(), {})), \
                patch.object(catalog, "publish_catalog", return_value=True) as writer:
            result = catalog.process_research_result(proposal, Path(directory), Path(directory), now,
                                                     discovered_by="qwen", model_id=publish.MODEL_ID)
        self.assertEqual(result["added"], 1)
        record = writer.call_args.args[2][0]
        self.assertEqual(record["discovered_by"], "qwen")
        self.assertEqual(record["discovery_model"], publish.MODEL_ID)
        parsed = catalog.parse_catalog(json.dumps({"schema": 1, "generated_at": now, "sources": [record]}).encode(), now)
        self.assertEqual(parsed["sources"][0]["discovered_by"], "qwen")
        self.assertEqual(parsed["sources"][0]["discovery_model"], publish.MODEL_ID)

    def test_daily_budget_survives_failure_replays_same_urls_and_resets_moscow_day(self):
        # 20:59 UTC is 23:59 Moscow; day rollover must not use host timezone.
        now = 1794344340.0
        rows = [{"url": FEED + "-" + str(i), "evidence_url": FEED} for i in range(12)]
        proposal = {"schema": 1, "sources": rows}
        calls = []
        def process(text, *args, **kwargs):
            accepted = json.loads(text)["sources"]; calls.append(accepted)
            if len(calls) == 1:
                raise catalog.ResearchSourcesUnavailable("controlled failure")
            return {"accepted": len(accepted), "added": len(accepted), "refreshed": 0, "rejected": 0, "published": True}
        with tempfile.TemporaryDirectory() as directory, patch.object(publish.source_catalog, "_git_blob", side_effect=ValueError), \
                patch.object(publish.source_catalog, "process_research_result", side_effect=process):
            path = Path(directory)
            with self.assertRaises(catalog.ResearchSourcesUnavailable):
                publish.promote_sources(proposal, path, path, now=now)
            self.assertEqual(len(calls[0]), 8)
            result = publish.promote_sources(proposal, path, path, now=now + 1)
            self.assertEqual(calls[0], calls[1])
            self.assertEqual(result["budget_deferred"], 4)
            self.assertEqual(result["deferred_sources"], rows[8:])
            different = {"schema": 1, "sources": result["deferred_sources"]}
            result = publish.promote_sources(different, path, path, now=now + 2)
            self.assertEqual(result["accepted"], 0)
            result = publish.promote_sources(different, path, path, now=now + 120)
            self.assertEqual(result["accepted"], 4)

    def test_auth_failure_keeps_pending_data_without_disclosing_error_or_touching_git(self):
        class AuthRunner:
            def __init__(self, *args): pass
            def run(self, *args, **kwargs): return 1, "Bearer token=never-persist"
            def git(self, *args): raise AssertionError("authorization must precede writes")
            def stop(self): pass
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with self.assertRaisesRegex(publish.DiscoveryPublishFailure, "authentication"):
                publish.publish_discovery(path, path, metadata(time.time()), runner_factory=AuthRunner)
            pending = (path / publish.PENDING).read_text()
            self.assertNotIn("never-persist", pending)
            self.assertNotIn("Bearer", pending)

    def test_empty_and_overlapping_jobs_never_start_git(self):
        now = time.time(); data = metadata(now); data.update(sources=[], candidates=[])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(publish, "Runner", side_effect=AssertionError("no Git")):
                self.assertEqual(publish.publish_discovery(path, path, data)["reason"], "empty")
                with (path / "qwen-discovery-publication.lock").open("a+") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(publish.DiscoveryPublishFailure, "busy"):
                        publish.publish_discovery(path, path, metadata(now))


class GitPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name); self.repo = self.path / "repo"; self.repo.mkdir()
        self.remote = self.path / "remote.git"; self.state = self.path / "state"
        self.git("init", "--bare", str(self.remote)); self.git("init", "-b", "main")
        self.git("config", "user.name", "Controlled Publisher"); self.git("config", "user.email", "controlled@example.invalid")
        (self.repo / "output").mkdir(); (self.repo / "output/best-local.txt").write_text("immutable main subscription\n")
        (self.repo / "output/best-local-Serbia.txt").write_text("immutable Serbia subscription\n")
        self.git("add", "."); self.git("commit", "-m", "controlled baseline")
        self.git("remote", "add", "origin", str(self.remote)); self.git("push", "origin", "HEAD:main", "HEAD:regional")
        self.original_main = self.git("rev-parse", "HEAD"); self.original_region = self.original_main

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True, stderr=subprocess.DEVNULL).strip()

    def assert_production_unchanged(self):
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/main").split()[0], self.original_main)
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/regional").split()[0], self.original_region)
        self.assertEqual((self.repo / "output/best-local.txt").read_text(), "immutable main subscription\n")
        self.assertEqual((self.repo / "output/best-local-Serbia.txt").read_text(), "immutable Serbia subscription\n")

    def test_actual_data_branch_is_atomic_allowlisted_and_idempotent_without_date_only_commits(self):
        now = time.time(); data = metadata(now)
        first = publish.publish_discovery(self.repo, self.state, data, now=now, create_pr=False)
        self.assertTrue(first["published"])
        head = self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH)
        self.assertEqual(self.git("diff", "--name-only", "origin/main...origin/" + publish.BRANCH), publish.DATA_PATH)
        changed_time = metadata(now + 60)
        self.assertFalse(publish.publish_discovery(self.repo, self.state, changed_time, now=now + 60, create_pr=False)["published"])
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH), head)
        self.assert_production_unchanged()
        self.assertFalse((self.state / publish.PENDING).exists())

    def test_transient_push_failure_retries_and_preserves_prior_discoveries(self):
        now = time.time()
        publish.publish_discovery(self.repo, self.state, metadata(now), now=now, create_pr=False)
        class FlakyRunner(Runner):
            failures = 0
            def git(self, *args, **kwargs):
                if "push" in args and type(self).failures == 0:
                    type(self).failures += 1
                    raise RuntimeError("controlled transport failure token=never-log")
                return super().git(*args, **kwargs)
        result = publish.publish_discovery(self.repo, self.state, metadata(now + 1, 1), now=now + 1,
                                           runner_factory=FlakyRunner, create_pr=False)
        self.assertTrue(result["published"])
        raw = self.git("show", "origin/" + publish.BRANCH + ":" + publish.DATA_PATH)
        self.assertEqual(len(json.loads(raw)["sources"]), 2)
        self.assertNotIn("never-log", raw)
        self.assert_production_unchanged()

    def test_compromised_discovery_branch_cannot_modify_workflows_or_code(self):
        self.git("checkout", "-b", publish.BRANCH)
        (self.repo / "unexpected.py").write_text("untrusted\n")
        self.git("add", "."); self.git("commit", "-m", "controlled unwanted path")
        self.git("push", "origin", "HEAD:refs/heads/" + publish.BRANCH)
        self.git("checkout", "main")
        with self.assertRaisesRegex(publish.DiscoveryPublishFailure, "branch-not-data-only"):
            publish.publish_discovery(self.repo, self.state, metadata(time.time()), create_pr=False)
        self.assert_production_unchanged()

    def test_pr_failure_replays_existing_branch_without_duplicate_commit(self):
        class GitHubRunner(Runner):
            available = False
            def run(self, command, *args, **kwargs):
                if command[0] != "gh":
                    return super().run(command, *args, **kwargs)
                if command[1] == "api":
                    return 0, "true\n"
                if command[1:3] == ["pr", "list"]:
                    return 0, "[]"
                if not type(self).available:
                    raise RuntimeError("controlled unavailable GitHub")
                return 0, "https://github.com/RebelRider/vpn-subscription/pull/42\n"
        now = time.time(); data = metadata(now)
        with self.assertRaisesRegex(publish.DiscoveryPublishFailure, "pr-unavailable"):
            publish.publish_discovery(self.repo, self.state, data, now=now, runner_factory=GitHubRunner)
        first = self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH)
        self.assertTrue((self.state / publish.PENDING).exists())
        GitHubRunner.available = True
        result = publish.publish_discovery(self.repo, self.state, data, now=now, runner_factory=GitHubRunner)
        self.assertFalse(result["published"])
        self.assertEqual(result["pr_url"], "https://github.com/RebelRider/vpn-subscription/pull/42")
        self.assertEqual(first, self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH))
        self.assertFalse((self.state / publish.PENDING).exists())
        self.assert_production_unchanged()

    def test_symlink_data_file_cannot_overwrite_other_worktree_paths(self):
        self.git("checkout", "-b", publish.BRANCH)
        path = self.repo / publish.DATA_PATH
        path.parent.mkdir(parents=True)
        path.symlink_to("../../output/best-local.txt")
        self.git("add", "."); self.git("commit", "-m", "controlled symlink data")
        self.git("push", "origin", "HEAD:refs/heads/" + publish.BRANCH)
        self.git("checkout", "main")
        with self.assertRaisesRegex(publish.DiscoveryPublishFailure, "branch-not-data-only"):
            publish.publish_discovery(self.repo, self.state, metadata(time.time()), create_pr=False)
        self.assert_production_unchanged()

    def test_public_ack_does_not_lose_daily_admission_backlog_or_create_timestamp_only_commit(self):
        now = time.time()
        data = metadata(now)
        records = [metadata(now, index) for index in range(12)]
        data["sources"] = [row["sources"][0] for row in records]
        data["candidates"] = [row["candidates"][0] for row in records]
        proposal = {"schema": 1, "sources": [{"url": row["url"], "evidence_url": row["evidence_url"]} for row in data["sources"]]}
        admissions = []
        def admit(text, *args, **kwargs):
            rows = json.loads(text)["sources"]; admissions.append(rows)
            return {"accepted": len(rows), "added": len(rows), "refreshed": 0, "rejected": 0, "published": True}
        with patch.object(publish.source_catalog, "_git_blob", side_effect=ValueError), \
                patch.object(publish.source_catalog, "process_research_result", side_effect=admit):
            first = publish.promote_sources(proposal, self.repo, self.state, now=now)
            self.assertEqual((first["added"], first["budget_deferred"]), (8, 4))
            publish.publish_discovery(self.repo, self.state, data, now=now, create_pr=False)
            before = self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH)
            self.assertTrue((self.state / publish.LAST_PUBLISHED).exists())
            second = publish.promote_sources({"schema": 1, "sources": first["deferred_sources"]},
                                              self.repo, self.state, now=now + 86400)
            self.assertEqual(second["added"], 4)
            self.assertFalse(second["deferred_sources"])
            refreshed = copy.deepcopy(data)
            refreshed["generated_at"] = now + 86400
            for row in refreshed["sources"]: row["fetched_at"] = now + 86400
            for row in refreshed["candidates"]: row["observed_at"] = now + 86400
            self.assertFalse(publish.publish_discovery(self.repo, self.state, refreshed, now=now + 86400, create_pr=False)["published"])
            self.assertEqual(before, self.git("ls-remote", "origin", "refs/heads/" + publish.BRANCH))
        self.assertEqual([len(rows) for rows in admissions], [8, 4])
        self.assert_production_unchanged()


if __name__ == "__main__":
    unittest.main()
