"""Real URI rendering boundaries; synthetic service evidence is only a fixture."""
import copy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from test_local_publication import m as local, evidence


class PinnedPublication(unittest.TestCase):
    def setUp(self):
        self.build = local.load_build_module()

    def node(self, host="proxy.example.com"):
        node = evidence()
        node["link"] = f"trojan://public-test-password@{host}:443?sni=tls.example.com"
        node["id"] = self.build.normalized_fingerprint(self.build.parse_vless(node["link"]))
        node["tested_server_ip"] = "8.8.8.8"
        return node

    def test_renderer_pins_tested_transport_but_preserves_provenance(self):
        node = self.node()
        now = datetime.now(timezone.utc).isoformat()
        status = {"generated_at": now, "upstream_generated_at": now,
                  "algorithm": "bestlocal-strict-services-v6", "nodes": [node],
                  "input": {"nodes": 1}, "exit_geography": {"affects_qualification": False},
                  "stability": {"rounds": 5, "minimum_successes": 5, "qualified": 1}}
        with tempfile.TemporaryDirectory() as directory:
            text, meta = Path(directory) / "sub.txt", Path(directory) / "status.json"
            local.write_subscription(text, [node["link"]], status)
            local.write_status(meta, status)
            local.validate_generated_result(text, meta)
            links = [line for line in text.read_text().splitlines() if line and not line.startswith("#")]
            actual = self.build.parse_vless(links[0])
            self.assertEqual(actual["server"], "8.8.8.8")
            self.assertEqual(actual["sni"], "tls.example.com")
            self.assertEqual(status["nodes"][0]["link"], node["link"])
            self.assertNotEqual(self.build.normalized_fingerprint(actual), node["id"])

    def test_aliases_of_one_tested_connection_are_not_published_twice(self):
        first, second = self.node(), self.node("other.example.com")
        self.assertNotEqual(first["id"], second["id"])
        with self.assertRaisesRegex(RuntimeError, "Duplicate or equivalent"):
            local.validate_publication_nodes(self.build, [first, second])

    def test_invalid_tested_transport_cannot_be_rendered(self):
        node = self.node(); node["tested_server_ip"] = "127.0.0.1"
        from publication_retention import rendered_links
        with self.assertRaises(ValueError):
            rendered_links(local._retention_context(), {"nodes": [node], "presentation_version": 2})
