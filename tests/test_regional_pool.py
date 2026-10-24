import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import build
from scripts import regional_pool as regional


NOW = 2_000_000_000
UUID = "11111111-1111-4111-8111-111111111111"
SOURCE_A = "a" * 24
SOURCE_B = "b" * 24


def vless(address="1.1.1.1", remark="public"):
    return f"vless://{UUID}@{address}:443?security=tls&sni=example.com#{remark}"


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class FakePool:
    links = []
    provenance = {}

    def __init__(self, *args, **kwargs):
        self.sources = {}
        self.stats = {"fetched_sources": 2}
        self.link_sources = self.provenance

    def add(self, *args, **kwargs):
        return True

    def collect(self):
        return list(self.links), {SOURCE_A: {}, SOURCE_B: {}}


class RegionalPoolTests(unittest.TestCase):
    def test_private_tls_fingerprint_variant_blocks_equivalent_public_connection(self):
        public = "trojan://secret@8.8.8.8:443?type=ws&sni=example.com"
        private = public + "&fp=chrome"
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": private}]})
        links, manifest = self.collect([public])
        self.assertEqual(len(links), 2)
        self.assertTrue(all(node["public_publish_allowed"] is False for node in manifest["nodes"]))
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, [{"link": public}], manifest["manifest_path"], now=NOW)
        # A manifest from an older canonical-only permission implementation
        # cannot bypass the current live equivalent-connection private policy.
        data = json.loads(Path(manifest["manifest_path"]).read_text())
        for node in data["nodes"]:
            node["public_publish_allowed"] = True
        private_json(Path(manifest["manifest_path"]), data)
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, [{"link": public}], manifest["manifest_path"], now=NOW)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name)
        self.patch_pool = patch.object(regional, "PrivateSourcePool", FakePool)
        self.patch_catalog = patch.object(regional, "load_regional_sources", return_value=([], {"status": "unavailable"}))
        self.patch_rechecks = patch.object(regional, "_published_rechecks", return_value=[])
        self.patch_pool.start()
        self.patch_catalog.start()
        self.patch_rechecks.start()
        FakePool.links, FakePool.provenance = [], {}

    def tearDown(self):
        self.patch_catalog.stop()
        self.patch_pool.stop()
        self.patch_rechecks.stop()
        self.directory.cleanup()

    def collect(self, links=None, limit=50, now=NOW):
        return regional.collect_regional(build, links or [vless()], self.state, now=now, limit=limit)

    def test_exploration_bypasses_cloud_country_and_performance_admission(self):
        # No GeoIP or cloud proxy test is called here. A public non-cloud
        # candidate is merely admitted to the authoritative local validator.
        outside = "trojan://secret@8.8.8.8:443?sni=example.com"
        FakePool.links = [outside]
        FakePool.provenance = {outside: {SOURCE_A}}
        with patch.object(build, "classify_countries_batch", side_effect=AssertionError), patch.object(build, "run_first_pass", side_effect=AssertionError):
            links, manifest = self.collect()
        self.assertEqual(links, [vless(), outside])
        self.assertEqual(manifest["nodes"][1]["origin"], "regional-exploration")
        self.assertEqual(manifest["nodes"][1]["source_ids"], [SOURCE_A])
        self.assertTrue(manifest["unverified_inputs"])

    def test_previous_public_strict_nodes_are_retested_within_exploration_budget(self):
        first, second = vless("8.8.8.8"), "hy2://public@8.8.4.4:443?sni=example.com"
        candidates = [regional._candidate(build, link, origin="local-recheck") for link in (first, second)]
        FakePool.links = [vless("9.9.9.1"), vless("9.9.9.2")]
        with patch.object(regional, "_published_rechecks", return_value=candidates):
            links, manifest = self.collect(limit=2)
        self.assertEqual(links, [vless(), first, second])
        self.assertEqual(manifest["summary"]["local_recheck"], 2)
        self.assertEqual(manifest["summary"]["exploration"], 2)
        self.assertTrue(manifest["unverified_inputs"])
        self.assertTrue(all(node["origin"] == "local-recheck" for node in manifest["nodes"][1:]))

    def test_managed_privacy_overrides_previously_published_recheck(self):
        link = vless("8.8.8.8")
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": link}]})
        with patch.object(regional, "_published_rechecks", return_value=[regional._candidate(build, link, origin="local-recheck")]):
            links, manifest = self.collect()
        self.assertEqual(links, [vless(), link])
        self.assertFalse(manifest["nodes"][1]["public_publish_allowed"])

    def test_recheck_reader_ignores_legacy_corrupt_and_nonpublished_entries(self):
        self.patch_rechecks.stop()
        candidate = vless("8.8.8.8")
        def outputs(status, subscription):
            status_raw, subscription_raw = json.dumps(status).encode(), subscription.encode()
            return [b"a" * 40, b"b" * 40, str(len(status_raw)).encode(), status_raw,
                    b"c" * 40, str(len(subscription_raw)).encode(), subscription_raw]
        values = {"algorithm": "bestlocal-strict-services-v6", "nodes": [{"link": candidate}, {"link": vless("8.8.4.4")} ]}
        with patch.object(regional.subprocess, "check_output", side_effect=outputs(values, candidate)):
            result = regional._published_rechecks(build)
        self.assertEqual([node["link"] for node in result], [candidate])
        for bad in ([], {"algorithm": "old-v4", "nodes": [{"link": candidate}]},
                    {"algorithm": "bestlocal-strict-services-v6", "nodes": "bad"}):
            with patch.object(regional.subprocess, "check_output", side_effect=outputs(bad, candidate)):
                self.assertEqual(regional._published_rechecks(build), [])
        self.patch_rechecks.start()

    def test_best50_order_preserved_equivalent_configs_deduplicated(self):
        second = vless("8.8.8.8")
        FakePool.links = [vless(remark="different"), second, second]
        FakePool.provenance = {vless(remark="different"): {SOURCE_A}, second: {SOURCE_B}}
        links, manifest = self.collect([second, vless()])
        self.assertEqual(links, [second, vless()])
        self.assertEqual(manifest["nodes"][1]["source_ids"], [SOURCE_A])

    def test_rotation_explores_unknown_candidates_even_without_feedback(self):
        FakePool.links = [vless(f"9.9.9.{index}") for index in range(1, 7)]
        first, _ = self.collect(limit=2)
        second, _ = self.collect(limit=2, now=NOW + 1)
        self.assertFalse(set(first[1:]) & set(second[1:]))
        self.assertEqual(first[0], second[0])

    def test_recently_tested_candidates_leave_room_for_unseen_protocols(self):
        FakePool.links = [vless("9.9.9.1"), "trojan://password@8.8.8.8:443?sni=example.com", "hy2://password@8.8.4.4:443?sni=example.com"]
        first, manifest = self.collect(limit=1)
        regional.apply_local_feedback(self.state, [{"id": manifest["nodes"][1]["id"], "qualified": False, "rejection_reasons": ["connection-timeout"]}], now=NOW)
        second, _ = self.collect(limit=1, now=NOW + 1)
        self.assertNotEqual(first[1], second[1])

    def test_supported_protocols_and_public_endpoint_syntax_are_required(self):
        FakePool.links = ["trojan://password@8.8.8.8:443?sni=example.com", "hy2://password@8.8.4.4:443?sni=example.com", "socks://user:password@9.9.9.9:1080", "trojan://password@127.0.0.1:443", "tuic://password@8.8.8.8:443", "not-a-config"]
        _, manifest = self.collect()
        self.assertEqual({node["protocol"] for node in manifest["nodes"]}, {"vless", "trojan", "hysteria2", "socks"})
        self.assertEqual(manifest["summary"]["invalid"], 3)

    def test_managed_pool_defaults_to_private_and_requires_explicit_export(self):
        private = "trojan://private-credential@8.8.8.8:443?sni=example.com"
        public = "hy2://explicit-export@8.8.4.4:443?sni=example.com"
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": private}, {"uri": public, "publish_public": True}]})
        links, manifest = self.collect()
        self.assertIn(private, links)
        args = (build, [{"link": private}], manifest["manifest_path"])
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(*args, expected_digest=manifest["manifest_digest"], now=NOW)
        self.assertTrue(regional.validate_manifest_membership(*args, expected_digest=manifest["manifest_digest"], now=NOW, require_public=False))
        self.assertTrue(regional.validate_manifest_membership(build, [{"link": public}], manifest["manifest_path"], expected_digest=manifest["manifest_digest"], now=NOW))
        history = (self.state / regional.HISTORY_NAME).read_text()
        self.assertNotIn("private-credential", history)
        self.assertFalse((self.state / regional.DISCOVERY_NAME).exists())

    def test_private_managed_collision_overrides_best50_and_public_duplicates(self):
        duplicate = vless(remark="private-managed")
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [
            {"uri": duplicate, "publish_public": True},
            {"uri": duplicate, "publish_public": False},
            {"uri": duplicate, "publish_public": True}]})
        FakePool.links = [vless(remark="public-source")]
        links, manifest = self.collect()
        self.assertEqual(links, [vless()])
        self.assertFalse(manifest["nodes"][0]["public_publish_allowed"])
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, manifest["manifest_path"],
                expected_digest=manifest["manifest_digest"], now=NOW)

    def test_managed_export_revocation_replacement_and_deletion_invalidate_manifest(self):
        managed = "trojan://private-credential@8.8.8.8:443?sni=example.com"
        path = self.state / "managed-pool.json"
        initial = {"schema": 1, "servers": [{"uri": managed, "publish_public": True}]}
        for replacement in ({"schema": 1, "servers": [{"uri": managed, "publish_public": False}]},
                            {"schema": 1, "servers": []}, None):
            private_json(path, initial)
            _, manifest = self.collect()
            if replacement is None:
                path.unlink()
            else:
                private_json(path, replacement)
            with self.assertRaises(ValueError):
                regional.validate_manifest_membership(build, [managed], manifest["manifest_path"],
                    expected_digest=manifest["manifest_digest"], now=NOW)

    def test_new_private_managed_collision_after_collection_invalidates_export(self):
        links, manifest = self.collect()
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": vless()}]})
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, manifest["manifest_path"],
                expected_digest=manifest["manifest_digest"], now=NOW)

    def test_managed_pool_permissions_owner_and_symlinks_fail_closed(self):
        path = self.state / "managed-pool.json"
        private_json(path, {"schema": 1, "servers": []})
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.collect()
        path.unlink()
        external = self.state / "other.json"
        private_json(external, {"schema": 1, "servers": []})
        path.symlink_to(external)
        with self.assertRaises(ValueError):
            self.collect()

    def test_invalid_managed_data_cannot_enable_export_or_leak_parser_error(self):
        for servers in ([{"uri": "private-secret-malformed"}], [{"uri": vless("8.8.8.8"), "publish_public": "true"}], [{"uri": vless(), "extra": True}]):
            private_json(self.state / "managed-pool.json", {"schema": 1, "servers": servers})
            with self.assertRaises(ValueError) as caught:
                self.collect()
            self.assertNotIn("private-secret", str(caught.exception))

    def test_manifest_is_private_fresh_and_pinned_to_tested_bytes(self):
        links, manifest = self.collect()
        path = Path(manifest["manifest_path"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(regional.validate_manifest_membership(build, links, path, expected_digest=manifest["manifest_digest"], now=NOW))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), manifest["manifest_digest"])
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, path, expected_digest=manifest["manifest_digest"], now=NOW + regional.MAX_AGE + 1)
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "changed"):
            regional.validate_manifest_membership(build, links, path, expected_digest=manifest["manifest_digest"], now=NOW)

    def test_manifest_pins_tested_best50_commit_and_input_digest(self):
        best50_sha = "c" * 40
        links, manifest = regional.collect_regional(build, [vless()], self.state,
            now=NOW, best50_sha=best50_sha)
        expected = hashlib.sha256(vless().encode()).hexdigest()
        self.assertTrue(regional.validate_manifest_membership(build, links, manifest["manifest_path"],
            expected_digest=manifest["manifest_digest"], expected_best50_sha=best50_sha,
            expected_best50_digest=expected, now=NOW))
        for changes in ({"expected_best50_sha": "d" * 40}, {"expected_best50_digest": "e" * 64}):
            arguments = {"expected_best50_sha": best50_sha, "expected_best50_digest": expected, **changes}
            with self.assertRaises(ValueError):
                regional.validate_manifest_membership(build, links, manifest["manifest_path"],
                    expected_digest=manifest["manifest_digest"], now=NOW, **arguments)

    def test_manifest_rejects_forged_identity_future_timestamp_and_unrelated_node(self):
        links, manifest = self.collect()
        path = Path(manifest["manifest_path"])
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, [vless("8.8.8.8")], path, now=NOW)
        raw = json.loads(path.read_text())
        raw["nodes"][0]["id"] = "f" * 64
        private_json(path, raw)
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, path, now=NOW)
        raw["nodes"][0]["id"] = manifest["nodes"][0]["id"]
        raw["generated_at"] = NOW + 500
        private_json(path, raw)
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, path, now=NOW)
        raw["generated_at"] = 10 ** 1000
        private_json(path, raw)
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, links, path, now=NOW)

    def test_inconclusive_challenge_does_not_poison_source_reputation(self):
        FakePool.links = [vless("8.8.8.8")]
        FakePool.provenance = {FakePool.links[0]: {SOURCE_A}}
        _, manifest = self.collect()
        identifier = manifest["nodes"][1]["id"]
        regional.apply_local_feedback(self.state, [{"id": identifier, "qualified": True}], now=NOW)
        before = json.loads((self.state / regional.HISTORY_NAME).read_text())["sources"][SOURCE_A]["local_ema"]
        feedback = regional.apply_local_feedback(self.state, [{"id": identifier, "qualified": False, "services": {"chatgpt": {"reasons": ["cloudflare-challenge-inconclusive"]}}, "rejection_reasons": ["curl-28"]}], now=NOW + 1)
        after = json.loads((self.state / regional.HISTORY_NAME).read_text())["sources"][SOURCE_A]
        self.assertEqual(feedback["inconclusive"], 1)
        self.assertEqual(after["local_ema"], before)
        self.assertEqual(after["qualified"], 1)
        self.assertEqual(after["inconclusive"], 1)

    def test_definitive_failure_lowers_source_reputation_and_counts_once(self):
        FakePool.links = [vless("8.8.8.8")]
        FakePool.provenance = {FakePool.links[0]: {SOURCE_A}}
        _, manifest = self.collect()
        identifier = manifest["nodes"][1]["id"]
        regional.apply_local_feedback(self.state, [{"id": identifier, "qualified": True}], now=NOW)
        diagnostic = {"id": identifier, "qualified": False, "rejection_reasons": ["proxy-start-or-network-failure"]}
        result = regional.apply_local_feedback(self.state, [diagnostic, diagnostic], now=NOW + 1)
        record = json.loads((self.state / regional.HISTORY_NAME).read_text())["sources"][SOURCE_A]
        self.assertEqual(result["definitive_failure"], 1)
        self.assertLess(record["local_ema"], .35)
        self.assertEqual(record["definitive_failure"], 1)

    def test_corrupt_optional_history_recovers_without_inventing_success(self):
        private_json(self.state / regional.HISTORY_NAME, {"cursor": 10 ** 1000, "sources": {SOURCE_A: {"last_seen": NOW, "qualified": "bad", "local_ema": 10 ** 1000}}, "candidates": {"x": {}}})
        _, manifest = self.collect()
        self.assertEqual(manifest["summary"]["best50"], 1)
        data = json.loads((self.state / regional.HISTORY_NAME).read_text())
        self.assertEqual(data["cursor"], 0)
        self.assertEqual(data["sources"][SOURCE_A]["qualified"], 0)

    def test_unhashable_history_outcome_recovers_as_inconclusive(self):
        identifier = build.normalized_fingerprint(build.parse_vless(vless("8.8.8.8")))
        for outcome in ([], {}, ["qualified"]):
            private_json(self.state / regional.HISTORY_NAME, {"schema": 1,
                "candidates": {identifier: {"last_seen": NOW, "last_outcome": outcome}}})
            self.collect()
            history = json.loads((self.state / regional.HISTORY_NAME).read_text())
            self.assertEqual(history["candidates"][identifier]["last_outcome"], "inconclusive")

    def test_provenance_is_capped_at_eight_across_history_candidate_and_merge(self):
        link = vless("8.8.8.8")
        identifier = build.normalized_fingerprint(build.parse_vless(link))
        sources = [format(index, "024x") for index in range(160)]
        private_json(self.state / regional.HISTORY_NAME, {"schema": 1,
            "candidates": {identifier: {"last_seen": NOW, "source_ids": sources[80:]}}})
        FakePool.links = [link, vless("8.8.8.8", "duplicate")]
        FakePool.provenance = {link: set(sources[:80]), FakePool.links[1]: set(sources[40:])}
        _, manifest = self.collect()
        candidate = next(node for node in manifest["nodes"] if node["id"] == identifier)
        self.assertEqual(len(candidate["source_ids"]), regional.MAX_SOURCE_IDS)
        history = regional._load_history(self.state, NOW)
        self.assertEqual(len(history["candidates"][identifier]["source_ids"]), regional.MAX_SOURCE_IDS)

    def test_worst_case_eight_thousand_provenance_records_fit_private_budget(self):
        sources = [format(index, "024x") for index in range(regional.MAX_SOURCE_IDS)]
        history = {"schema": 1, "cursor": regional.MAX_PROVENANCE, "sources": {},
            "candidates": {format(index, "064x"): {"last_seen": NOW + .123456,
                "last_tested": NOW + .123456, "source_ids": sources,
                "last_outcome": "definitive-failure"} for index in range(regional.MAX_PROVENANCE)}}
        raw = regional._write_private(self.state / regional.HISTORY_NAME, history)
        self.assertLess(len(raw), regional.MAX_BYTES)
        restored = regional._load_history(self.state, NOW + 1)
        self.assertEqual(len(restored["candidates"]), regional.MAX_PROVENANCE)

    def test_real_source_pool_state_is_mode600_and_local_feedback_persists(self):
        self.patch_pool.stop()
        real_pool = regional.PrivateSourcePool([], self.state / regional.DISCOVERY_NAME, now=NOW)
        real_pool.add("https://example.com/subscription.txt", "seed")
        real_pool.save()
        self.assertEqual(stat.S_IMODE(real_pool.path.stat().st_mode), 0o600)
        real_pool.save()
        self.assertEqual(stat.S_IMODE(real_pool.path.stat().st_mode), 0o600)
        self.assertNotIn(UUID, real_pool.path.read_text())
        self.patch_pool.start()

    def test_transient_discovery_failure_preserves_best50_and_managed_inputs(self):
        managed = "trojan://private@8.8.8.8:443?sni=example.com"
        private_json(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": managed}]})
        with patch.object(FakePool, "collect", side_effect=TimeoutError):
            links, manifest = self.collect()
        self.assertEqual(links, [vless(), managed])
        self.assertEqual(manifest["summary"]["discovery"]["collection_error"], "regional-discovery-unavailable")

    def test_unavailable_optional_registry_or_provenance_cache_does_not_drop_best50(self):
        with patch.object(regional, "PrivateSourcePool", side_effect=ValueError("unsafe cache")):
            links, manifest = self.collect()
        self.assertEqual(links, [vless()])
        self.assertIn("collection_error", manifest["summary"]["discovery"])
        writer = regional._write_private
        def unavailable_history(path, value):
            if path.name == regional.HISTORY_NAME:
                raise OSError("optional cache unavailable")
            return writer(path, value)
        with patch.object(regional, "_write_private", side_effect=unavailable_history):
            links, manifest = self.collect()
        self.assertEqual(links, [vless()])
        self.assertEqual(manifest["summary"]["provenance_persistence"], "unavailable")
        self.assertTrue(Path(manifest["manifest_path"]).is_file())

    def test_feedback_updates_real_source_pool_without_counting_challenges_as_failures(self):
        self.patch_pool.stop()
        pool = regional.PrivateSourcePool([], self.state / regional.DISCOVERY_NAME, now=NOW)
        url = "https://example.com/subscription.txt"
        pool.add(url, "seed")
        pool.save()
        source = next(iter(pool.sources))
        identifier = build.normalized_fingerprint(build.parse_vless(vless("8.8.8.8")))
        private_json(self.state / regional.HISTORY_NAME, {"schema": 1, "cursor": 0,
            "sources": {}, "candidates": {identifier: {"last_seen": NOW, "source_ids": [source]}}})
        regional.apply_local_feedback(self.state, [{"id": identifier, "qualified": True}], now=NOW)
        record = json.loads(pool.path.read_text())["sources"][source]
        self.assertEqual(record["validation_runs"], 1)
        self.assertEqual(record["functional_ema"], .35)
        regional.apply_local_feedback(self.state, [{"id": identifier, "qualified": False,
            "services": {"chatgpt": {"reasons": ["challenge-inconclusive"]}}}], now=NOW + 1)
        after = json.loads(pool.path.read_text())["sources"][source]
        self.assertEqual(after["validation_runs"], 1)
        self.assertEqual(after["functional_ema"], record["functional_ema"])
        self.patch_pool.start()

    def test_private_reader_cannot_be_stalled_by_a_fifo(self):
        path = self.state / "managed-pool.json"
        os.mkfifo(path, 0o600)
        with self.assertRaises(ValueError):
            self.collect()

    def test_collection_limits_are_bounded(self):
        for limit in (-1, 51, True, 10 ** 1000):
            with self.assertRaises(ValueError):
                self.collect(limit=limit)
        with self.assertRaises(ValueError):
            regional.collect_regional(build, [vless()] * 51, self.state, now=NOW)


if __name__ == "__main__":
    unittest.main()
