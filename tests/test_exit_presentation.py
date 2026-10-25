import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import local_probe as local
from test_validator_integration import verified_node, verified_status


class ExitPresentationTests(unittest.TestCase):
    def test_public_ip_in_country_city_and_neutral_labels(self):
        self.assertEqual(local.presentation_label(2, "NL", "Haarlem", "51.158.161.241"),
                         "🇳🇱 NL | Haarlem | 2 | [51.158.161.241]")
        for country in (None, "ZZ", "XX"):
            self.assertEqual(local.presentation_label(2, country, "Unverified", "8.8.8.8"),
                             "🌐 | 2 | [8.8.8.8]")
        self.assertEqual(local.presentation_label(1, "US", None, "2606:4700:4700:0:0:0:0:1111"),
                         "🇺🇸 US | 1 | [2606:4700:4700::1111]")

    def test_invalid_private_multicast_and_non_ip_values_are_not_displayed(self):
        for value in (None, "", "127.0.0.1", "192.168.1.1", "224.0.0.1", "::1", "ff00::1",
                      "example.com", "8.8.8.8\nforged", True, 134744072):
            with self.subTest(value=value):
                self.assertEqual(local.presentation_label(1, "DE", None, value), "🇩🇪 DE | 1")

    def test_relabel_preserves_protocol_configuration_including_vmess(self):
        vmess = "vmess://" + base64.b64encode(json.dumps({
            "v": "2", "ps": "old", "add": "1.1.1.1", "port": "443",
            "id": "11111111-1111-4111-8111-111111111111", "aid": "0", "net": "ws",
            "host": "example.com", "path": "/ws", "tls": "tls", "sni": "example.com",
        }).encode()).decode()
        links = [vmess, "trojan://public@1.1.1.1:443?sni=example.com",
                 "ss://YWVzLTEyOC1nY206cHVibGlj@1.1.1.1:443",
                 "hysteria2://public@1.1.1.1:443?sni=example.com",
                 "socks://public:password@1.1.1.1:1080"]
        protocols = local.load_protocols()
        for link in links:
            with self.subTest(protocol=link.split(":")[0]):
                renamed = local.published_link(link, 1, "NL", "Haarlem", "8.8.8.8")
                self.assertEqual(protocols.parse_node(link)["normalized_key"],
                                 protocols.parse_node(renamed)["normalized_key"])
                self.assertEqual(renamed, local.published_link(renamed, 1, "NL", "Haarlem", "8.8.8.8"))

    def test_optional_failure_is_preserved_and_ip_database_supplies_country(self):
        link = "trojan://public@1.1.1.1:443?sni=example.com"
        reports = {link: {"exit_trace_reason": "proxy-request-timeout",
                          "exit_geo_attempts": [{"endpoint": "cloudflare", "reason": "proxy-request-timeout"}]}}
        metadata = local.exit_metadata_from_reports([link], reports)
        self.assertEqual(metadata[link]["exit_geo_status"], "trace-failed")
        self.assertEqual(metadata[link]["exit_geo_error"], "proxy-request-timeout")
        reports[link]["exit_trace"] = {"ip": "8.8.8.8", "loc": ""}
        status = verified_status([verified_node(link)])
        before = status["generated_at"], status["nodes"][0]["validated_at"]
        with patch.object(local, "_lookup_city_database", return_value={
                "8.8.8.8": {"db_country": "DE", "city": "Berlin"}}):
            local.apply_exit_geography(status, local.exit_metadata_from_reports([link], reports),
                                       strict_country_gate=False)
        self.assertEqual(status["nodes"][0]["exit_country"], "DE")
        self.assertEqual(status["nodes"][0]["exit_country_source"], "dbip-exit-ip")
        self.assertEqual(before, (status["generated_at"], status["nodes"][0]["validated_at"]))
        with tempfile.TemporaryDirectory() as directory:
            output, proof = Path(directory)/"subscription.txt", Path(directory)/"status.json"
            local.write_subscription(output, [link], status)
            local.write_status(proof, status)
            local.validate_generated_result(output, proof)
            self.assertIn("%5B8.8.8.8%5D", output.read_text())


if __name__ == "__main__":
    unittest.main()
