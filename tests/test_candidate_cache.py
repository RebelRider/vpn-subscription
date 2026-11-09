import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import build, regional_pool as regional


NOW = 2_000_000_000
UUID = "11111111-1111-4111-8111-111111111111"
SOURCE = "a" * 24


def uri(address="1.1.1.1", label="public", path=""):
    return f"vless://{UUID}@{address}:443?security=tls&sni=example.com" + ("&path=%2F" + path if path else "") + "#" + label


def write_private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class Pool:
    links = []
    outage = False
    partial = False

    def __init__(self, *args, **kwargs):
        self.sources = {SOURCE: {}}
        self.link_sources = {link: {SOURCE} for link in self.links}
        self.stats = {"fetched_sources": 0 if self.outage else 1,
                      "source_failures": int(self.outage or self.partial)}

    def add(self, *args, **kwargs):
        pass

    def collect(self):
        return ([] if self.outage else list(self.links)), {SOURCE: {"error": "TimeoutError"} if self.outage else {"candidates": len(self.links)}}


class CandidateCacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name)
        self.pool = patch.object(regional, "PrivateSourcePool", Pool)
        self.catalog = patch.object(regional, "load_regional_sources", return_value=([], {"status": "unavailable"}))
        self.rechecks = patch.object(regional, "_published_rechecks", return_value=[])
        for setting in (self.pool, self.catalog, self.rechecks):
            setting.start()
            self.addCleanup(setting.stop)
        self.addCleanup(self.directory.cleanup)
        Pool.links, Pool.outage, Pool.partial = [], False, False

    def collect(self, state=None, now=NOW, preferred_country=None):
        return regional.collect_regional(build, [uri()], state or self.state, now=now,
                                         preferred_country=preferred_country)

    def cached(self, state=None):
        return json.loads(((state or self.state) / regional.CANDIDATE_CACHE_NAME).read_text())

    def test_source_outage_reuses_public_inputs_but_never_service_passes(self):
        explorer = uri("8.8.8.8")
        Pool.links = [explorer]
        self.collect()
        path = self.state / regional.CANDIDATE_CACHE_NAME
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        original_stamp = self.cached()["entries"][0]["observed_at"]
        Pool.outage = True
        links, manifest = self.collect(now=NOW + 3600)
        self.assertIn(explorer, links)
        cache = manifest["summary"]["candidate_cache"]
        self.assertEqual(cache["used"], 1)
        self.assertEqual(cache["oldest_used_age_seconds"], 3600)
        self.assertEqual(self.cached()["entries"][0]["observed_at"], original_stamp)
        self.assertTrue(manifest["unverified_inputs"])
        self.assertNotIn("services", json.dumps(self.cached()))
        self.assertNotIn("qualified", json.dumps(manifest))
        self.assertTrue(regional.validate_manifest_membership(build, [{"link": explorer}],
                       manifest["manifest_path"], expected_digest=manifest["manifest_digest"], now=NOW + 3600))

    def test_partial_collection_replenishes_without_refreshing_replayed_age(self):
        first, second = uri("8.8.8.8"), uri("8.8.4.4")
        Pool.links = [first]
        self.collect()
        Pool.links, Pool.partial = [second], True
        links, manifest = self.collect(now=NOW + 100)
        self.assertTrue({first, second} <= set(links))
        self.assertEqual(manifest["summary"]["candidate_cache"]["used"], 1)
        stamps = {entry["link"]: entry["observed_at"] for entry in self.cached()["entries"]}
        self.assertEqual(stamps, {first: NOW, second: NOW + 100})

    def test_cache_expiration_does_not_slide_when_replayed(self):
        explorer = uri("8.8.8.8")
        Pool.links = [explorer]
        self.collect()
        Pool.outage = True
        self.assertIn(explorer, self.collect(now=NOW + regional.MAX_CANDIDATE_CACHE_AGE - 1)[0])
        self.assertNotIn(explorer, self.collect(now=NOW + regional.MAX_CANDIDATE_CACHE_AGE + 1)[0])
        self.assertEqual(self.cached()["entries"], [])

    def test_corruption_wrong_mode_oversize_and_symlink_fail_closed(self):
        path = self.state / regional.CANDIDATE_CACHE_NAME
        for damage in ("json", "mode", "oversize", "symlink"):
            with self.subTest(damage=damage):
                if path.exists() or path.is_symlink():
                    path.unlink()
                target = self.state / "unrelated.txt"
                target.write_text("preserve this unrelated file")
                if damage == "json":
                    path.write_text("{")
                elif damage == "oversize":
                    path.write_bytes(b"x" * (regional.MAX_CANDIDATE_CACHE_BYTES + 1))
                elif damage == "symlink":
                    path.symlink_to(target)
                else:
                    path.write_text("{}")
                if not path.is_symlink():
                    path.chmod(0o644 if damage == "mode" else 0o600)
                Pool.outage = True
                links, manifest = self.collect()
                self.assertEqual(links, [uri()])
                self.assertEqual(manifest["summary"]["candidate_cache"]["status"], "invalid-or-unavailable")
                self.assertEqual(target.read_text(), "preserve this unrelated file")

    def test_managed_private_alias_is_evicted_and_cannot_be_authorized(self):
        public = "trojan://private-test-value@8.8.8.8:443?sni=example.com"
        Pool.links = [public]
        self.collect()
        private = public + "&fp=chrome"
        write_private(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": private}]})
        Pool.outage = True
        links, manifest = self.collect(now=NOW + 1)
        self.assertNotIn(public, links)
        self.assertEqual(self.cached()["entries"], [])
        self.assertNotIn("private-test-value", json.dumps(manifest["summary"]))
        with self.assertRaises(ValueError):
            regional.validate_manifest_membership(build, [{"link": private}], manifest["manifest_path"], now=NOW + 1)

    def test_forged_cached_pass_is_not_replayed(self):
        Pool.links = [uri("8.8.8.8")]
        self.collect()
        value = self.cached()
        value["entries"][0]["services"] = {"chatgpt": {"passed": 5}}
        write_private(self.state / regional.CANDIDATE_CACHE_NAME, value)
        Pool.outage = True
        self.assertEqual(self.collect()[0], [uri()])

    def test_first_serbia_outage_uses_fresh_public_main_manifest_and_own_new_manifest(self):
        explorers = [uri("8.8.8.8", "Serbia"), uri("8.8.4.4", "unknown")]
        Pool.links = explorers
        _, main = self.collect()
        serbia = self.state / "serbia"
        Pool.outage = True
        links, manifest = self.collect(serbia, now=NOW + 120, preferred_country="RS")
        self.assertTrue(set(explorers) <= set(links))
        self.assertEqual(Path(manifest["manifest_path"]).parent, serbia)
        self.assertNotEqual(manifest["manifest_digest"], main["manifest_digest"])
        self.assertGreater(manifest["summary"]["candidate_cache"]["fallback_main_manifest"], 0)
        self.assertTrue(all(entry["observed_at"] == NOW for entry in self.cached(serbia)["entries"]))
        self.assertTrue(regional.validate_manifest_membership(build, [{"link": explorers[0]}],
                       manifest["manifest_path"], expected_digest=manifest["manifest_digest"], now=NOW + 120))

    def test_main_manifest_refresh_does_not_extend_replayed_source_age_in_serbia(self):
        explorer = uri("8.8.8.8", "Serbia")
        Pool.links = [explorer]
        self.collect()
        Pool.outage = True
        self.collect(now=NOW + 5 * 3600)
        serbia = self.state / "serbia"
        links, _ = self.collect(serbia, now=NOW + 5 * 3600 + 120, preferred_country="RS")
        self.assertIn(explorer, links)
        copied = next(entry for entry in self.cached(serbia)["entries"] if entry["link"] == explorer)
        self.assertEqual(copied["observed_at"], NOW)

    def test_main_fallback_rejects_stale_or_unsafe_manifest_and_private_entries(self):
        public = uri("8.8.8.8", "Serbia")
        private = "trojan://private-test-value@8.8.4.4:443?sni=example.com"
        write_private(self.state / "managed-pool.json", {"schema": 1, "servers": [{"uri": private}]})
        Pool.links = [public, private]
        self.collect()
        Pool.outage = True
        links, _ = self.collect(self.state / "serbia", preferred_country="RS")
        self.assertIn(public, links)
        self.assertNotIn(private, links)
        for name, age, mode in (("expired", regional.MAX_AGE + 1, 0o600), ("unsafe", 0, 0o644)):
            with self.subTest(name=name):
                (self.state / regional.MANIFEST_NAME).chmod(mode)
                links, _ = self.collect(self.state / name, now=NOW + age, preferred_country="RS")
                self.assertEqual(links, [uri()])

    def test_cache_is_bounded_and_preserves_serbia_hints_beside_new_diverse_inputs(self):
        serbian = uri("8.8.8.8", "Serbia")
        Pool.links = [serbian]
        self.collect()
        Pool.links = [uri(f"9.{index // 65536}.{index // 256 % 256}.{index % 256}", path="a" * 1000)
                      for index in range(1, 2501)]
        rare = ["hy2://public@8.8.4.4:443?sni=example.com", "socks://user:public@1.0.0.1:1080"]
        Pool.links.extend(rare)
        self.collect(now=NOW + 1)
        path = self.state / regional.CANDIDATE_CACHE_NAME
        entries = self.cached()["entries"]
        self.assertLessEqual(len(entries), regional.MAX_CACHED_CANDIDATES)
        self.assertLessEqual(path.stat().st_size, regional.MAX_CANDIDATE_CACHE_BYTES)
        self.assertIn(serbian, [entry["link"] for entry in entries])
        self.assertTrue(set(rare) <= {entry["link"] for entry in entries})


if __name__ == "__main__":
    unittest.main()
