"""Fresh historical RS inputs supplement healthy sources, never their proof."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import build
from scripts import regional_pool as regional


NOW = 2_000_000_000
SOURCE = "a" * 24
UUID = "11111111-1111-4111-8111-111111111111"


def uri(address, label="public"):
    return f"vless://{UUID}@{address}:443?security=tls&sni=example.com#{label}"


class HealthySourcePool:
    links = []

    def __init__(self, *args, **kwargs):
        self.sources = {SOURCE: {}}
        self.stats = {"fetched_sources": 1, "source_failures": 0}
        self.link_sources = {link: [SOURCE] for link in self.links}

    def add(self, *args, **kwargs):
        return True

    def collect(self):
        return list(self.links), {SOURCE: {}}


class SerbiaCacheCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        HealthySourcePool.links = [uri("9.9.9.9")]
        for target, replacement in (("PrivateSourcePool", HealthySourcePool),
                                    ("load_regional_sources", lambda *args, **kwargs: ([], {"status": "available"})),
                                    ("_published_rechecks", lambda *args, **kwargs: [])):
            patcher = patch.object(regional, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def seed(self, entries):
        cache, history = [], {"schema": 1, "cursor": 0, "candidates": {}, "sources": {}}
        for link, observed, country in entries:
            candidate = regional._candidate(build, link, [SOURCE])
            cache.append({key: candidate[key] for key in ("id", "link", "protocol", "source_ids")})
            cache[-1].update(observed_at=observed, public_publish_allowed=True)
            record = {"last_seen": observed, "last_tested": observed, "source_ids": [SOURCE]}
            if country:
                record["last_exit_country"] = country
            history["candidates"][candidate["id"]] = record
        regional._write_private(self.state / regional.CANDIDATE_CACHE_NAME,
                                {"schema": 1, "unverified_inputs": True, "entries": cache})
        regional._write_private(self.state / regional.HISTORY_NAME, history)

    def collect(self, preferred="RS", now=NOW):
        return regional.collect_regional(build, [uri("1.1.1.1")], self.state, now=now,
                                         limit=4, preferred_country=preferred)

    def test_healthy_new_sources_do_not_hide_still_fresh_observed_serbian_exit(self):
        known = uri("8.8.8.8")
        observed = NOW - 3600
        self.seed([(known, observed, "RS")])
        links, manifest = self.collect()
        self.assertIn(known, links)
        self.assertIn(HealthySourcePool.links[0], links)
        self.assertEqual(manifest["summary"]["discovery"]["source_failures"], 0)
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 1)
        self.assertEqual(manifest["summary"]["candidate_cache"]["used"], 1)
        self.assertTrue(manifest["unverified_inputs"])
        cached_node = next(node for node in manifest["nodes"] if node["link"] == known)
        self.assertEqual(cached_node["input_observed_at"], observed)
        for field in ("services", "qualified", "exit_country", "exit_country_evidence", "validated_at"):
            self.assertNotIn(field, cached_node)
        frozen = Path(manifest["manifest_path"])
        regional.validate_manifest_membership(build, [cached_node], frozen,
            expected_digest=hashlib.sha256(frozen.read_bytes()).hexdigest(), now=NOW)

    def test_replay_keeps_original_observation_age_until_expiry(self):
        known = uri("8.8.8.8")
        observed = NOW - regional.MAX_CANDIDATE_CACHE_AGE + 1
        self.seed([(known, observed, "RS")])
        first, _ = self.collect()
        self.assertIn(known, first)
        cache = json.loads((self.state / regional.CANDIDATE_CACHE_NAME).read_text())
        self.assertEqual(next(row for row in cache["entries"] if row["link"] == known)["observed_at"], observed)
        second, manifest = self.collect(now=NOW + 2)
        self.assertNotIn(known, second)
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 0)

    def test_labels_unknown_history_and_non_serbian_observations_do_not_trigger_healthy_replay(self):
        entries = [(uri("8.8.8.8", "Serbia-RS-🇷🇸"), NOW - 60, None),
                   (uri("8.8.4.4", "Serbia-RS-🇷🇸"), NOW - 60, "DE"),
                   (uri("9.9.9.10"), NOW - 60, None)]
        self.seed(entries)
        links, manifest = self.collect()
        self.assertTrue(all(link not in links for link, _, _ in entries))
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 0)

    def test_primary_policy_does_not_replay_hints_when_sources_are_healthy(self):
        known = uri("8.8.8.8")
        self.seed([(known, NOW - 60, "RS")])
        links, manifest = self.collect(preferred=None)
        self.assertNotIn(known, links)
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 0)

    def test_fresh_duplicates_are_single_inputs_and_may_refresh_from_real_source_observation(self):
        known = uri("8.8.8.8")
        self.seed([(known, NOW - 60, "RS")])
        HealthySourcePool.links = [known, known]
        links, manifest = self.collect()
        self.assertEqual(links.count(known), 1)
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 0)
        self.assertEqual(next(node for node in manifest["nodes"] if node["link"] == known)["input_observed_at"], NOW)

    def test_private_connection_alias_cannot_be_replayed_as_public_rs_input(self):
        known = uri("8.8.8.8")
        self.seed([(known, NOW - 60, "RS")])
        private = known.split("#", 1)[0] + "&fp=chrome#private-fixture"
        regional._write_private(self.state / "managed-pool.json",
                                {"schema": 1, "servers": [{"uri": private}]})
        links, manifest = self.collect()
        self.assertNotIn(known, links)
        managed = next(node for node in manifest["nodes"] if node["link"] == private)
        self.assertFalse(managed["public_publish_allowed"])
        self.assertEqual(manifest["summary"]["candidate_cache"]["offered"], 0)


if __name__ == "__main__":
    unittest.main()
