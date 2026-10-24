"""Controlled local evidence and Git publication; no external network calls."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import build
from scripts import local_probe as local
from scripts import regional_pool as regional


UUID = "11111111-1111-4111-8111-111111111111"
BEST50 = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com#DE"
EXPLORATION = "trojan://public-candidate@8.8.8.8:443?sni=example.com"


def verified_node(link, latency=123.0, rank=1):
    return {"id": build.normalized_fingerprint(build.parse_vless(link)),
            "link": link, "rank": rank, "country": "XX", "exit_country": None,
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "median_latency": latency, "p95_latency": latency,
            "latency_samples_ms": [latency] * 5, "successful_final_rounds": 5,
            "services": {name: {"passed": 5, "attempts": 5}
                         for name in ("chatgpt", "youtube", "instagram")}}


def verified_status(nodes):
    stamp = datetime.now(timezone.utc).isoformat()
    return {"algorithm": "bestlocal-strict-services-v6", "generated_at": stamp,
            "upstream_generated_at": stamp, "input": {"nodes": len(nodes)},
            "stability": {"rounds": 5, "minimum_successes": 5, "qualified": len(nodes)},
            "nodes": nodes}


class MetadataAcceptanceTests(unittest.TestCase):
    def test_fr_and_unknown_exit_are_metadata_while_all_service_latency_gates_remain_strict(self):
        unknown = "hy2://public-candidate@8.8.4.4:443?sni=example.com"
        status = verified_status([verified_node(EXPLORATION, rank=1), verified_node(unknown, rank=2)])
        with patch.object(local, "_lookup_city_database", return_value={}):
            local.apply_exit_geography(status, {EXPLORATION: {
                "exit_ip": "8.8.8.8", "trace_country": "FR", "exit_geo_status": "trace-ok"}},
                strict_country_gate=False)
        selected = local.finalize_local_selection([EXPLORATION, unknown], status)
        self.assertEqual(selected, [EXPLORATION, unknown])
        self.assertEqual(status["nodes"][0]["exit_country"], "FR")
        self.assertEqual(status["nodes"][1]["exit_country"], "ZZ")
        self.assertFalse(status["exit_geography"]["affects_qualification"])
        self.assertEqual(status["exit_geography"]["unknown_rejected"], 0)
        with tempfile.TemporaryDirectory() as directory:
            output, status_path = Path(directory) / "subscription.txt", Path(directory) / "status.json"
            local.write_subscription(output, selected, status)
            local.write_status(status_path, status)
            local.validate_generated_result(output, status_path)
        for latency in (500, 500.01, float("nan"), True):
            self.assertFalse(local.valid_node_evidence(verified_node(EXPLORATION, latency), 5))
        for name in ("chatgpt", "youtube", "instagram"):
            incomplete = verified_node(EXPLORATION)
            incomplete["services"][name]["passed"] = 4
            self.assertFalse(local.valid_node_evidence(incomplete, 5))


class RegionalPublicationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name)
        self.repo, self.remote, self.state = base / "repo", base / "remote.git", base / "private-state"
        self.repo.mkdir()
        self.state.mkdir(mode=0o700)
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("remote", "add", "origin", str(self.remote))
        (self.repo / "output").mkdir()
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/protocols.py").write_bytes((build.ROOT / "scripts/protocols.py").read_bytes())
        (self.repo / "output/best50.txt").write_text(BEST50 + "\n")
        self.git("add", ".")
        self.git("commit", "-m", "private controlled input fixture")
        self.git("push", "-u", "origin", "main")
        self.git("fetch", "origin", "main")
        self.sha = self.git("rev-parse", "HEAD")
        self.output, self.status_path = self.repo / "output/best-local.txt", self.repo / "output/local-status.json"
        self.local_patch = patch.multiple(local, ROOT=self.repo, STATE_DIR=self.state,
            DEFAULT_OUTPUT=self.output, DEFAULT_STATUS=self.status_path)
        self.local_patch.start()
        self.build_patch = patch.object(local, "load_build_module", return_value=build)
        self.build_patch.start()
        self.root_patch = patch.object(build, "ROOT", self.repo)
        self.root_patch.start()

    def tearDown(self):
        self.build_patch.stop()
        self.root_patch.stop()
        self.local_patch.stop()
        self.directory.cleanup()

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.repo,
            stderr=subprocess.DEVNULL, text=True).strip()

    def manifest(self, *, private=False, source_links=None):
        if private:
            path = self.state / "managed-pool.json"
            path.write_text(json.dumps({"schema": 1, "servers": [{"uri": EXPLORATION}]}))
            path.chmod(0o600)
        class Pool:
            def __init__(self, *args, **kwargs):
                self.sources, self.stats = {}, {}
                self.link_sources = {EXPLORATION: {"a" * 24}}
            def add(self, *args, **kwargs):
                return True
            def collect(self):
                return ([EXPLORATION] if source_links is None else source_links), {"a" * 24: {}}
        with patch.object(regional, "PrivateSourcePool", Pool), \
                patch.object(regional, "load_regional_sources", return_value=([], {"status": "unavailable"})):
            _, manifest = regional.collect_regional(build, [BEST50], self.state,
                now=time.time(), best50_sha=self.sha)
        return manifest

    def result(self, manifest=None):
        status = verified_status([verified_node(EXPLORATION)])
        status["exit_geography"] = {"affects_qualification": False}
        if manifest is not None:
            status["input"]["regional_manifest"] = {
                "file": regional.MANIFEST_NAME, "digest": manifest["manifest_digest"]}
        local.write_subscription(self.output, [EXPLORATION], status)
        local.write_status(self.status_path, status)

    def test_nonbest50_node_publishes_only_with_current_pinned_manifest(self):
        self.result()
        with self.assertRaisesRegex(RuntimeError, "absent from tested Best50"):
            local._publish_regional_once(self.output, self.status_path, self.sha)
        manifest = self.manifest()
        self.result(manifest)
        local._publish_regional_once(self.output, self.status_path, self.sha)
        published = self.git("show", "origin/regional:output/best-local.txt")
        self.assertIn("trojan://", published)
        self.assertNotIn("managed_pool_digest", self.git("show", "origin/regional:output/local-status.json"))

    def test_private_candidate_and_revoked_managed_policy_cannot_publish(self):
        manifest = self.manifest(private=True)
        self.result(manifest)
        with self.assertRaises(ValueError):
            local._publish_regional_once(self.output, self.status_path, self.sha)
        path = self.state / "managed-pool.json"
        path.write_text(json.dumps({"schema": 1, "servers": [{"uri": EXPLORATION, "publish_public": True}]}))
        manifest = self.manifest()
        self.result(manifest)
        path.write_text(json.dumps({"schema": 1, "servers": [{"uri": EXPLORATION, "publish_public": False}]}))
        with self.assertRaises(ValueError):
            local._publish_regional_once(self.output, self.status_path, self.sha)
        self.assertFalse(self.git("ls-remote", "--heads", "origin", "regional"))

    def test_legacy_best50_publication_preserved_but_live_private_collision_denied(self):
        status = verified_status([verified_node(BEST50)])
        status["exit_geography"] = {"affects_qualification": False}
        local.write_subscription(self.output, [BEST50], status)
        local.write_status(self.status_path, status)
        # No managed policy and no manifest retain the existing Best50 contract.
        local._publish_regional_once(self.output, self.status_path, self.sha)
        published = self.git("ls-remote", "--heads", "origin", "regional")
        path = self.state / "managed-pool.json"
        path.write_text(json.dumps({"schema": 1, "servers": [{
            "uri": BEST50.replace("#DE", "#private-label"), "publish_public": False}]}))
        path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "private managed candidate"):
            local._publish_regional_once(self.output, self.status_path, self.sha)
        self.assertEqual(self.git("ls-remote", "--heads", "origin", "regional"), published)

    def test_legacy_publication_rejects_malformed_and_unsafe_managed_policy(self):
        status = verified_status([verified_node(BEST50)])
        path = self.state / "managed-pool.json"
        for content in ("not JSON", "[]", json.dumps({"schema": 1, "servers": [
                {"uri": BEST50, "publish_public": "false"}]})):
            path.write_text(content)
            path.chmod(0o600)
            with self.subTest(policy=content[:20]), self.assertRaises(ValueError):
                local.validate_publication_membership(build, status, self.sha)
        path.write_text(json.dumps({"schema": 1, "servers": []}))
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            local.validate_publication_membership(build, status, self.sha)
        path.unlink()
        external = self.state / "symlink-target.json"
        external.write_text(json.dumps({"schema": 1, "servers": []}))
        external.chmod(0o600)
        path.symlink_to(external)
        with self.assertRaises(ValueError):
            local.validate_publication_membership(build, status, self.sha)

    def test_legacy_managed_opt_out_after_commit_prevents_public_push(self):
        status = verified_status([verified_node(BEST50)])
        status["exit_geography"] = {"affects_qualification": False}
        local.write_subscription(self.output, [BEST50], status)
        local.write_status(self.status_path, status)
        original_git = local.git_output
        committed = []
        def revoke_after_commit(*args, **kwargs):
            result = original_git(*args, **kwargs)
            if args[0] == "commit":
                path = self.state / "managed-pool.json"
                path.write_text(json.dumps({"schema": 1, "servers": [{"uri": BEST50}]}))
                path.chmod(0o600)
                committed.append(True)
            return result
        with patch.object(local, "git_output", side_effect=revoke_after_commit):
            with self.assertRaisesRegex(RuntimeError, "private managed candidate"):
                local._publish_regional_once(self.output, self.status_path, self.sha)
        self.assertEqual(committed, [True])
        self.assertFalse(self.git("ls-remote", "--heads", "origin", "regional"))

    def test_two_public_local_qualifiers_survive_source_disappearance_as_recheck_inputs(self):
        second = "hy2://public-second@8.8.4.4:443?sni=example.com"
        manifest = self.manifest(source_links=[EXPLORATION, second])
        status = verified_status([verified_node(EXPLORATION), verified_node(second, rank=2)])
        status["exit_geography"] = {"affects_qualification": False}
        status["input"]["regional_manifest"] = {"file": regional.MANIFEST_NAME, "digest": manifest["manifest_digest"]}
        local.write_subscription(self.output, [EXPLORATION, second], status)
        local.write_status(self.status_path, status)
        local._publish_regional_once(self.output, self.status_path, self.sha)
        recheck = self.manifest(source_links=[])
        entries = [node for node in recheck["nodes"] if node["origin"] == "local-recheck"]
        self.assertEqual({node["link"] for node in entries}, {EXPLORATION, second})
        self.assertEqual(recheck["summary"]["local_recheck"], 2)
        self.assertEqual(recheck["summary"]["exploration"], 2)
        self.assertTrue(recheck["unverified_inputs"])

    def test_manifest_for_different_baseline_is_rejected_even_with_matching_file_digest(self):
        manifest = self.manifest()
        path = Path(manifest["manifest_path"])
        raw = json.loads(path.read_text())
        raw["best50_sha"] = "b" * 40
        raw["best50_digest"] = hashlib.sha256(b"different Best50").hexdigest()
        path.write_text(json.dumps(raw))
        manifest["manifest_digest"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.result(manifest)
        with self.assertRaises(ValueError):
            local._publish_regional_once(self.output, self.status_path, self.sha)
        self.assertFalse(self.git("ls-remote", "--heads", "origin", "regional"))


if __name__ == "__main__":
    unittest.main()
