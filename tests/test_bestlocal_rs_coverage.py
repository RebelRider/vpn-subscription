"""Production policy invariants for increased Serbia exploration coverage."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import build, regional_pool

UUID = "11111111-1111-4111-8111-111111111111"


def link(ip, comment="public"):
    return f"vless://{UUID}@{ip}:443?security=tls&sni=example.com#{comment}"


class FakePool:
    def __init__(self, *_args, **_kwargs):
        self.sources = {}
        self.link_sources = {}
        self.stats = {"fetched_sources": 2}

    def add(self, *args, **kwargs):
        return True

    def collect(self):
        return [link(f"8.8.1.{i}", "Serbia") for i in range(1, 201)], {}


class CountryCoverageTests(unittest.TestCase):
    def test_serbia_uses_90_exploration_and_10_cloud_inputs(self):
        best50 = [link(f"1.1.1.{i}") for i in range(1, 51)]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(regional_pool, "PrivateSourcePool", FakePool), \
                patch.object(regional_pool, "_published_rechecks", return_value=[]), \
                patch.object(regional_pool, "load_regional_sources", return_value=([], {})):
            nodes, manifest = regional_pool.collect_regional(
                build, best50, Path(directory), limit=90, preferred_country="RS",
                best50_sha="a" * 40)
            self.assertEqual(len(nodes), 100)
            self.assertEqual(sum(x["origin"] == "best50" for x in manifest["nodes"]), 10)
            self.assertEqual(sum(x["origin"] == "regional-exploration" for x in manifest["nodes"]), 90)
            self.assertEqual(manifest["best50_digest"], hashlib.sha256("\n".join(best50).encode()).hexdigest())
            self.assertEqual(manifest["best50_sha"], "a" * 40)
            self.assertTrue(manifest["unverified_inputs"])
            self.assertTrue(all(x["public_publish_allowed"] for x in manifest["nodes"]))

    def test_primary_keeps_unchanged_50_plus_50_budget(self):
        best50 = [link(f"1.1.2.{i}") for i in range(1, 51)]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(regional_pool, "PrivateSourcePool", FakePool), \
                patch.object(regional_pool, "_published_rechecks", return_value=[]), \
                patch.object(regional_pool, "load_regional_sources", return_value=([], {})):
            nodes, manifest = regional_pool.collect_regional(build, best50, Path(directory))
            self.assertEqual(len(nodes), 100)
            self.assertEqual(sum(x["origin"] == "best50" for x in manifest["nodes"]), 50)
            self.assertEqual(sum(x["origin"] == "regional-exploration" for x in manifest["nodes"]), 50)


if __name__ == "__main__":
    unittest.main()
