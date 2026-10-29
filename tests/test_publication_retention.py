"""Controlled Git histories for fresh/retained subscriptions; no public network."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import build
from scripts import local_probe as local
from scripts import publication_retention as retention
from scripts import regional_pool
from scripts import subscription_state


UUID = "11111111-1111-4111-8111-111111111111"
OLD_A = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com"
OLD_B = "trojan://retention-fixture@8.8.8.8:443?sni=example.com"
NEW = f"vless://{UUID}@8.8.4.4:443?security=tls&sni=example.com"


def node(link, stamp, rank=1):
    return {"id": build.normalized_fingerprint(build.parse_vless(link)), "link": link,
            "rank": rank, "validated_at": stamp, "exit_country": "NL", "exit_city": "Test",
            "median_latency": 123.0, "latency_samples_ms": [123.0] * 5,
            "services": {name: {"passed": 5, "attempts": 5, "reasons": ["ok"] * 5,
                                "evidence": [{"outcome": "pass", "reason": "ok", "http_reason": "ok",
                                              "http_status": 200, "curl_exit": None,
                                              "cf_challenge": False, "geo_restricted": False} for _ in range(5)]}
                         for name in ("chatgpt", "youtube", "instagram")}}


def status(links, stamp=None):
    stamp = stamp or datetime.now(timezone.utc).isoformat()
    return {"algorithm": "bestlocal-strict-services-v6", "generated_at": stamp,
            "upstream_generated_at": stamp, "input": {"nodes": len(links)},
            "stability": {"rounds": 5, "minimum_successes": 5, "qualified": len(links)},
            "exit_geography": {"affects_qualification": False},
            "nodes": [node(link, stamp, index) for index, link in enumerate(links, 1)]}


class PublicationRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.state = self.repo / "state"
        self.state.mkdir(mode=0o700)
        (self.repo / "output").mkdir()
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/protocols.py").write_bytes((build.ROOT / "scripts/protocols.py").read_bytes())
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Retention test")
        self.git("config", "user.email", "retention@example.invalid")
        self.original = status([OLD_A, OLD_B], (datetime.now(timezone.utc) - timedelta(days=3)).isoformat())
        # Historical browser proof is deliberately too old for today's fresh gate.
        chat = self.original["nodes"][0]["services"]["chatgpt"]
        chat["reasons"] = ["browser-functional-access"] * 5
        for item in chat["evidence"]:
            item.update(reason="browser-functional-access", http_reason="cloudflare-challenge-inconclusive",
                        http_outcome="inconclusive", http_status=403, cf_challenge=True,
                        browser={"passed": True, "checked_at": self.original["generated_at"],
                                 "actionable": True, "restriction_free": True})
        self.output = self.repo / "output/best-local.txt"
        self.status_path = self.repo / "output/local-status.json"
        self.patches = [patch.multiple(local, ROOT=self.repo, STATE_DIR=self.state),
                        patch.object(build, "ROOT", self.repo),
                        patch.object(build, "CFG", {"regional_publication": {
                            "protected_ids": [item["id"] for item in self.original["nodes"]]}}),
                        patch.object(local, "load_build_module", return_value=build)]
        for item in self.patches:
            item.start()
        self.write(self.original)
        self.git("add", "output")
        self.git("commit", "-m", "controlled original strict publication")
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/regional", self.base)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.repo,
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def write(self, value):
        local.write_subscription(self.output, [item["link"] for item in value["nodes"]], value)
        local.write_status(self.status_path, value)

    def mixed(self, links=None):
        value = status([NEW] if links is None else links)
        retention.prepare(local._retention_context(), build, value, self.base)
        return value

    def test_new_fresh_candidate_preserves_two_original_entries_without_fresh_count_inflation(self):
        value = self.mixed()
        self.assertEqual(value["stability"]["qualified"], 1)
        self.assertEqual(len(value["nodes"]), 1)
        self.assertEqual(value["published_total"], 3)
        self.assertEqual(value["retained_nodes"], self.original["nodes"])
        self.write(value)
        local.validate_generated_result(self.output, self.status_path)
        text = self.output.read_text()
        self.assertIn("STALE - 1 verified + 2 retained", text)
        self.assertEqual(len(subscription_state.connection_lines(text)), 3)
        self.assertTrue(subscription_state.has_fresh_validation(value))
        self.assertFalse(subscription_state.is_fresh_strict_status(value))

    def test_fresh_proof_replaces_retained_entry_without_duplicates(self):
        value = self.mixed([OLD_A, NEW])
        self.assertEqual(value["stability"]["qualified"], 2)
        self.assertEqual([item["link"] for item in value["retained_nodes"]], [OLD_B])
        self.assertEqual(value["retained_nodes"][0]["rank"], 2)
        self.write(value)
        local.validate_generated_result(self.output, self.status_path)
        self.assertEqual(len(subscription_state.connection_lines(self.output.read_text())), 3)

    def test_repeated_mixed_publication_preserves_original_source_without_a_provenance_chain(self):
        value = self.mixed()
        provenance = deepcopy(value["retained_provenance"])
        self.write(value)
        self.git("add", "output")
        self.git("commit", "-m", "controlled mixed publication")
        later = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/regional", later)
        retried = status([NEW])
        retention.prepare(local._retention_context(), build, retried, later)
        self.assertEqual(retried["retained_provenance"], provenance)
        self.assertTrue(all(item["commit"] == self.base for item in provenance.values()))
        retention.validate(local._retention_context(), build, retried, base_ref=later)

    def test_changed_payload_identity_or_blob_cannot_forge_retained_proof(self):
        value = self.mixed()
        mutations = [lambda item: item["retained_nodes"][0].update(median_latency=1),
                     lambda item: item["retained_nodes"][0].update(link=NEW),
                     lambda item: item["retained_nodes"][0].update(id="f" * 64),
                     lambda item: item["retained_provenance"][self.original["nodes"][0]["id"]].update(status_blob="0" * 40),
                     lambda item: item.update(published_total=1)]
        for mutate in mutations:
            invalid = deepcopy(value)
            mutate(invalid)
            with self.subTest(mutation=mutate), self.assertRaises(RuntimeError):
                retention.validate(local._retention_context(), build, invalid, base_ref=self.base)

    def test_unrelated_or_descendant_commit_cannot_supply_ancestral_provenance(self):
        value = self.mixed()
        self.git("commit", "--allow-empty", "-m", "controlled later commit")
        future = self.git("rev-parse", "HEAD")
        value["retained_provenance"][self.original["nodes"][0]["id"]]["commit"] = future
        with self.assertRaises(RuntimeError):
            retention.validate(local._retention_context(), build, value, base_ref=self.base)

    def test_original_future_or_invalid_service_evidence_is_rejected(self):
        for mutate in (lambda value: value.update(generated_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()),
                       lambda value: value["nodes"][0]["services"]["youtube"].update(passed=4)):
            invalid = deepcopy(self.original)
            mutate(invalid)
            self.write(invalid)
            self.git("add", "output")
            self.git("commit", "-m", "controlled invalid source")
            invalid_base = self.git("rev-parse", "HEAD")
            with self.assertRaises(RuntimeError):
                retention.prepare(local._retention_context(), build, status([NEW]), invalid_base)

    def test_old_historical_proof_still_fails_the_fresh_validator(self):
        self.assertFalse(local.valid_node_evidence(self.original["nodes"][0], 5, require_round_evidence=True))
        self.write(self.original)
        with self.assertRaisesRegex(RuntimeError, "Stale"):
            local.validate_generated_result(self.output, self.status_path)

    def test_duplicate_or_unconfigured_retained_nodes_are_rejected(self):
        value = self.mixed()
        value["nodes"].append(deepcopy(value["retained_nodes"][0]))
        value["published_total"] += 1
        with self.assertRaises(RuntimeError):
            retention.validate(local._retention_context(), build, value, base_ref=self.base)
        with patch.object(build, "CFG", {"regional_publication": {"protected_ids": []}}), self.assertRaises(RuntimeError):
            retention.validate(local._retention_context(), build, self.mixed_value(), base_ref=self.base)

    def mixed_value(self):
        # Reconstruct independent of the current test's patched configuration.
        source = retention.snapshot(self.repo, self.base)
        value = status([NEW])
        value.update(retained_nodes=deepcopy(self.original["nodes"]), published_total=3,
                     retained_provenance={item["id"]: {key: source[key] for key in
                                          ("commit", "status_blob", "subscription_blob")}
                                          for item in self.original["nodes"]})
        return value

    def test_private_managed_opt_out_blocks_retained_publication(self):
        value = self.mixed()
        private = self.state / "managed-pool.json"
        private.write_text(json.dumps({"schema": 1, "servers": [{"uri": OLD_A, "publish_public": False}]}))
        private.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "private retained"):
            local.validate_publication_membership(build, value, self.base, retention_base_ref=self.base)

    def test_automatic_recheck_reader_includes_both_retained_entries(self):
        value = self.mixed()
        self.write(value)
        self.git("add", "output")
        self.git("commit", "-m", "controlled mixed inventory")
        self.git("update-ref", "refs/remotes/origin/regional", self.git("rev-parse", "HEAD"))
        candidates = regional_pool._published_rechecks(build)
        self.assertEqual({item["link"] for item in candidates}, {NEW, OLD_A, OLD_B})

    def test_cap_remains_twelve_fresh_plus_two_retained(self):
        value = self.mixed()
        value["retained_nodes"].append(deepcopy(value["retained_nodes"][0]))
        with self.assertRaises(RuntimeError):
            retention.validate(local._retention_context(), build, value, base_ref=self.base)

    def test_actual_mixed_transaction_is_atomic_verified_and_idempotent(self):
        bare = self.repo / "remote.git"
        self.git("init", "--bare", str(bare))
        self.git("remote", "add", "origin", str(bare))
        (self.repo / "output/best50.txt").write_text(NEW + "\n")
        self.git("add", "output/best50.txt")
        self.git("commit", "-m", "controlled current primary input")
        tested = self.git("rev-parse", "HEAD")
        self.git("push", "origin", "HEAD:main", f"{self.base}:refs/heads/regional")
        self.git("fetch", "origin", "main", "regional")
        fresh = status([NEW])
        self.write(fresh)
        with patch.multiple(local, DEFAULT_OUTPUT=self.output, DEFAULT_STATUS=self.status_path):
            local._publish_regional_once(self.output, self.status_path, tested)
            first = self.git("rev-parse", "origin/regional")
            published = json.loads(self.git("show", "origin/regional:output/local-status.json"))
            self.assertEqual(published["stability"]["qualified"], 1)
            self.assertEqual(published["published_total"], 3)
            self.assertEqual(published["retained_nodes"], self.original["nodes"])
            self.assertEqual(local.previous_publication_timestamp(published),
                             datetime.fromisoformat(fresh["generated_at"]).timestamp())
            self.assertFalse(subscription_state.mark_regional(self.repo))
            self.assertEqual(self.git("rev-parse", "origin/regional"), first)
            self.assertIn("STALE - 1 verified + 2 retained", self.git("show", "origin/regional:output/best-local.txt"))
            local._publish_regional_once(self.output, self.status_path, tested)
            self.assertEqual(self.git("rev-parse", "origin/regional"), first)
            self.assertEqual(self.git("rev-parse", "origin/regional:output/best-local.txt"),
                             self.git("hash-object", str(self.output)))

    def test_empty_retention_metadata_still_requires_correct_schema_and_integer_totals(self):
        for changes in ({"retained_nodes": {}}, {"retained_nodes": None},
                        {"retained_provenance": []}, {"published_total": True}, {"published_total": 1.0}):
            value = status([NEW])
            value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                retention.validate(local._retention_context(), build, value)


if __name__ == "__main__":
    unittest.main()
