"""Temporal ranking and connection identity; no network or live processes."""
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import build
from scripts import local_probe as local


UUID = "11111111-1111-4111-8111-111111111111"
VLESS = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com"
TROJAN = "trojan://public-test@8.8.8.8:443?type=ws&path=%2Fws&host=example.com&sni=example.com"


def node(link, latency=300, rank=1):
    return {"id": build.normalized_fingerprint(build.parse_vless(link)), "link": link, "rank": rank,
            "exit_country": "DE", "validated_at": datetime.now(timezone.utc).isoformat(),
            "median_latency": latency, "latency_samples_ms": [latency] * 5,
            "services": {name: {"passed": 5, "attempts": 5, "reasons": ["ok"] * 5,
                                "evidence": [{"outcome": "pass", "reason": "ok", "http_status": 200,
                                              "http_reason": "ok", "curl_exit": 0, "cf_challenge": False,
                                              "geo_restricted": False} for _ in range(5)]}
                         for name in ("chatgpt", "youtube", "instagram")}}


class ConnectionIdentityTests(unittest.TestCase):
    def test_fingerprint_variants_are_one_connection_but_keep_essential_semantics(self):
        native, chrome = TROJAN, TROJAN + "&fp=chrome&security=tls"
        self.assertNotEqual(build.normalized_fingerprint(build.parse_vless(native)),
                            build.normalized_fingerprint(build.parse_vless(chrome)))
        self.assertEqual(local.connection_identity(build, native), local.connection_identity(build, chrome))
        for changed in (native.replace("public-test", "another-account"), native.replace("8.8.8.8", "8.8.4.4"),
                        native.replace("%2Fws", "%2Fother"), native.replace("sni=example.com", "sni=example.org"),
                        native + "&alpn=h2", native.replace("host=example.com", "host=example.org")):
            with self.subTest(change=changed.split(":", 1)[0]):
                self.assertNotEqual(local.connection_identity(build, native), local.connection_identity(build, changed))

    def test_five_validated_entries_collapse_only_equivalent_trojan_variants(self):
        links = [VLESS, VLESS.replace("1.1.1.1", "1.0.0.1"), VLESS.replace("1.1.1.1", "9.9.9.9"),
                 TROJAN, TROJAN + "&fp=chrome&security=tls"]
        status = {"nodes": [node(link, rank=index) for index, link in enumerate(links, 1)],
                  "stability": {"qualified": 5, "rounds": 5, "minimum_successes": 5}}
        selected = local.finalize_local_selection(links, status, build=build)
        self.assertEqual(selected, links[:4])
        self.assertEqual(status["stability"]["qualified"], 4)
        self.assertEqual(status["selection"]["equivalent_connections_removed"], 1)
        self.assertEqual([item["rank"] for item in status["nodes"]], [1, 2, 3, 4])

    def test_publication_rejects_id_mismatch_and_all_duplicate_forms(self):
        first = node(VLESS)
        local.validate_publication_nodes(build, [first])
        mismatch = {**first, "id": "f" * 64}
        with self.assertRaisesRegex(RuntimeError, "identity"):
            local.validate_publication_nodes(build, [mismatch])
        for values in ([first, node(VLESS + "#other-name", rank=2)],
                       [node(TROJAN), node(TROJAN + "&fp=chrome&security=tls", rank=2)]):
            with self.assertRaisesRegex(RuntimeError, "Duplicate"):
                local.validate_publication_nodes(build, values)
        missing = dict(first)
        del missing["id"]
        with self.assertRaisesRegex(RuntimeError, "identity"):
            local.validate_publication_nodes(build, [missing])


class TemporalStabilityTests(unittest.TestCase):
    @staticmethod
    def candidates(latencies, reliabilities=None):
        reliabilities = reliabilities or [0.8] * len(latencies)
        values = [(chr(97 + index), {"median_ms": value, "p95_ms": value}, index, reliability)
                  for index, (value, reliability) in enumerate(zip(latencies, reliabilities))]
        return values, {value[0]: value[0] for value in values}

    def test_nearby_latency_jitter_keeps_previous_order(self):
        values, identities = self.candidates([403, 402, 390])
        ranked = local.rank_local_qualifiers(values, identities, ["a", "b"])
        self.assertEqual([value[0] for value in ranked], ["a", "b", "c"])
        values, identities = self.candidates([402, 403, 390])
        self.assertEqual([value[0] for value in local.rank_local_qualifiers(values, identities, ["a", "b"])],
                         ["a", "b", "c"])

    def test_material_improvement_and_stability_band_override_order(self):
        values, identities = self.candidates([450, 300, 200])
        self.assertEqual([value[0] for value in local.rank_local_qualifiers(values, identities, ["a", "b"])],
                         ["c", "b", "a"])
        values, identities = self.candidates([200, 450], [0.70, 0.90])
        self.assertEqual([value[0] for value in local.rank_local_qualifiers(values, identities, ["a", "b"])], ["b", "a"])
        values, identities = self.candidates([250, 225])
        self.assertEqual([value[0] for value in local.rank_local_qualifiers(values, identities, ["a", "b"])], ["a", "b"])

    def test_only_definitive_outcomes_change_bounded_temporal_estimate(self):
        legacy = {"runs": 100, "passes": 99}
        self.assertEqual(local.update_definitive_history(legacy, "inconclusive"), 0.5)
        self.assertEqual(legacy["definitive_history"], [])
        self.assertAlmostEqual(local.update_definitive_history(legacy, "pass"), 2 / 3)
        snapshot = list(legacy["definitive_history"])
        self.assertAlmostEqual(local.update_definitive_history(legacy, "inconclusive"), 2 / 3)
        self.assertEqual(legacy["definitive_history"], snapshot)
        self.assertEqual(local.update_definitive_history(legacy, "fail"), 0.5)
        for _ in range(30):
            local.update_definitive_history(legacy, "pass")
        self.assertEqual(legacy["definitive_history"], [True] * 20)
        self.assertAlmostEqual(local.update_definitive_history(legacy, "fail"), 20 / 22)

    def test_history_boolean_window_is_validated_and_legacy_metrics_preserved(self):
        now = time.time()
        key = "a" * 64
        record = {"last_seen": now, "runs": 100, "passes": 90, "qualified": True,
                  "definitive_history": [True, False, True]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.json"
            path.write_text(json.dumps({key: record}))
            self.assertEqual(local.load_local_reliability(path, now)[key], record)
            for malformed in ([True] * 21, [1], "pass", [None]):
                path.write_text(json.dumps({key: {**record, "definitive_history": malformed}}))
                recovered = local.load_local_reliability(path, now)[key]
                self.assertNotIn("definitive_history", recovered)
                self.assertEqual((recovered["runs"], recovered["passes"]), (100, 90))

    def test_stable_history_never_waives_current_service_or_latency_gates(self):
        current = node(VLESS, latency=500)
        current["historical_reliability"] = 21 / 22
        status = {"nodes": [current], "stability": {"qualified": 1, "rounds": 5, "minimum_successes": 5}}
        self.assertEqual(local.finalize_local_selection([VLESS], status, build=build), [])

        current = node(VLESS)
        current["historical_reliability"] = 21 / 22
        current["services"]["instagram"]["passed"] = 4
        status = {"nodes": [current], "stability": {"qualified": 1, "rounds": 5, "minimum_successes": 5}}
        self.assertEqual(local.finalize_local_selection([VLESS], status, build=build), [])

    def test_previous_order_is_bounded_optional_and_reads_only_immutable_local_blob(self):
        commit, blob = b"a" * 40, b"b" * 40
        status = {"algorithm": "bestlocal-strict-services-v6", "nodes": [{"id": "1" * 64}, {"id": "2" * 64}]}
        raw = json.dumps(status).encode()
        with patch.object(local.subprocess, "check_output", side_effect=[commit, blob, str(len(raw)).encode(), raw]) as git:
            self.assertEqual(local._previous_published_order(), ["1" * 64, "2" * 64])
        commands = [call.args[0] for call in git.call_args_list]
        self.assertTrue(all(command[0] == "git" and "fetch" not in command for command in commands))
        self.assertEqual(commands[-1], ["git", "cat-file", "blob", blob.decode()])
        for nodes in ([{"id": "1" * 64}] * 13, [{"id": "1" * 64}] * 2, [{"id": "bad"}]):
            raw = json.dumps({**status, "nodes": nodes}).encode()
            with patch.object(local.subprocess, "check_output", side_effect=[commit, blob, str(len(raw)).encode(), raw]):
                self.assertEqual(local._previous_published_order(), [])
        with patch.object(local.subprocess, "check_output", side_effect=OSError):
            self.assertEqual(local._previous_published_order(), [])


if __name__ == "__main__":
    unittest.main()
