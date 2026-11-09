"""Presentation dates and names without external services or client changes."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import local_probe as local
from scripts import subscription_presentation as presentation
from scripts import subscription_state as state
from scripts import publication_retention as retention
from test_validator_integration import verified_node, verified_status, BEST50


def epoch(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


class SubscriptionPresentationTests(unittest.TestCase):
    def test_moscow_minutes_with_fixed_english_months_across_midnight_and_leap_day(self):
        cases = (("2026-10-31T01:15:00+03:00", "31Oct2026 01:15"),
                 ("2028-02-29T20:59:59Z", "29Feb2028 23:59"),
                 ("2028-02-29T23:59:59Z", "01Mar2028 02:59"),
                 ("2026-11-01T00:01:00-03:00", "01Nov2026 06:01"),
                 ("2026-10-31T21:00:00Z", "01Nov2026 00:00"))
        for stamp, date in cases:
            now = epoch(stamp) + 1
            with self.subTest(stamp=stamp), patch.object(presentation.time, "strftime", create=True,
                                                        side_effect=AssertionError("locale dependency")):
                self.assertEqual(presentation.title({"generated_at": stamp}, now=now),
                                 f"#profile-title: BL VPN [{date}]")

    def test_bad_naive_future_and_nonfinite_dates_never_use_clock_as_validation(self):
        now = epoch("2026-11-01T00:00:00Z")
        for value in (None, "bad", "", "2026-10-31T23:00:00", "2026-11-01T00:00:01Z",
                      "1970-01-01T00:00:00Z", True, float("nan"), 0):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                presentation.title({"generated_at": value}, now=now)
        for now in (float("nan"), float("inf"), True, -1):
            with self.subTest(now=now), self.assertRaises(RuntimeError):
                presentation.title({"generated_at": "2026-10-30T00:00:00Z"}, now=now)

    def test_stale_requires_more_than_72_hours_since_published_validation(self):
        stamp = "2026-10-30T00:00:00Z"
        generated = epoch(stamp)
        status = {"generated_at": stamp}
        self.assertNotIn("STALE", presentation.title(status, now=generated + 72 * 3600 - .001))
        self.assertNotIn("STALE", presentation.title(status, now=generated + 72 * 3600))
        self.assertIn("STALE", presentation.title(status, now=generated + 72 * 3600 + .001))
        recent = {"generated_at": "2026-11-01T23:00:00Z", "retained_nodes": [{"validated_at": stamp}]}
        self.assertNotIn("STALE", presentation.title(recent, now=generated + 72 * 3600 - .001))
        self.assertNotIn("STALE", presentation.title(recent, now=generated + 72 * 3600))
        recent["retained_nodes"][0]["validated_at"] = "invalid"
        self.assertNotIn("STALE", presentation.title(recent, now=generated + 72 * 3600))

    def test_annotation_keeps_original_date_connections_and_six_hour_writer_guard(self):
        stamp = "2026-10-30T12:34:56Z"
        status = {"algorithm": "bestlocal-strict-services-v6", "generated_at": stamp,
                  "nodes": [{}], "stability": {"qualified": 1}}
        original = "#profile-title: Best Local VPN\n# generated: 2026-10-30 12:34:56 UTC\n" + BEST50 + "\n"
        now = epoch(stamp) + 7 * 3600
        self.assertFalse(state.has_fresh_validation(status, now))
        marked = state.apply_presentation(original, status, now)
        self.assertIn("#profile-title: BL VPN [30Oct2026 15:34]", marked)
        self.assertEqual(state.connection_lines(marked), state.connection_lines(original))
        self.assertIn("# generated: 2026-10-30 12:34:56 UTC", marked)
        self.assertEqual(marked, state.apply_presentation(marked, status, now))
        stale = state.apply_presentation(marked, status, epoch(stamp) + 72 * 3600 + .001)
        self.assertIn("#profile-title: BL VPN [STALE]", stale)
        self.assertLessEqual(len(stale.splitlines()[0].split(": ", 1)[1]), 25)
        self.assertEqual(stale, state.apply_presentation(stale, status, epoch(stamp) + 72 * 3600 + .001))
        malformed = state.apply_presentation(original, {**status, "generated_at": "bad"}, now)
        self.assertIn(state.STALE_TITLE, malformed)
        self.assertIn("# generated: 2026-10-30 12:34:56 UTC", malformed)

    def test_names_have_exact_spacing_safe_optional_geography_and_compressed_addresses(self):
        self.assertEqual(local.presentation_label(1, "DE", "Frankfurt am Main", "47.245.182.206"),
                         "🇩🇪 DE, Frankfurt am Main  |1|   [47.245.182.206]")
        self.assertEqual(local.presentation_label(2, "US", "", "2606:4700:4700:0::1111"),
                         "🇺🇸 US  |2|   [2606:4700:4700::1111]")
        self.assertEqual(local.presentation_label(3, "ZZ", "Unknown", "8.8.8.8"), "🌐  |3|   [8.8.8.8]")
        self.assertEqual(local.presentation_label(4, "DE", "Berlin\nforged", "server.example.com"),
                         "🇩🇪 DE, Berlin forged  |4|")
        for bad in (True, 0, -1, 1.0):
            with self.assertRaises(ValueError):
                local.presentation_label(bad, "DE")

    def test_new_render_versions_labels_and_rejects_wrong_or_duplicate_titles(self):
        status = verified_status([verified_node(BEST50)])
        chat = status["nodes"][0]["services"]["chatgpt"]
        chat["reasons"] = ["browser-functional-access"] * 5
        for evidence in chat["evidence"]:
            evidence.update(reason="browser-functional-access", http_reason="cloudflare-challenge-inconclusive",
                            http_outcome="inconclusive", http_status=403, cf_challenge=True,
                            browser={"passed": True, "checked_at": status["generated_at"], "http_status": 200,
                                     "actionable": True, "restriction_free": True, "composer": True,
                                     "application_json": True, "cold_session": True})
        status["exit_geography"] = {"affects_qualification": False}
        with tempfile.TemporaryDirectory() as directory:
            output, metadata = Path(directory) / "subscription", Path(directory) / "status"
            local.write_subscription(output, [BEST50], status)
            self.assertEqual(status["presentation_version"], 2)
            local.write_status(metadata, status)
            original = output.read_text()
            local.validate_generated_result(output, metadata)
            for wrong in (original.replace("#profile-title: BL VPN [", "#profile-title: Wrong ["),
                          original + "#profile-title: duplicate\n"):
                output.write_text(wrong)
                with self.assertRaisesRegex(RuntimeError, "title"):
                    local.validate_generated_result(output, metadata)
            output.write_text(original)
            bad = deepcopy(status)
            bad["generated_at"] = "bad"
            with self.assertRaises(RuntimeError):
                local.write_subscription(output, [BEST50], bad)
            self.assertEqual(output.read_text(), original)

    def test_legacy_immutable_snapshot_uses_original_names_and_new_order_stays_contiguous(self):
        nodes = [verified_node(BEST50, rank=1), verified_node(BEST50, rank=2)]
        for item in nodes:
            item.update(exit_country="DE", exit_city="Berlin", exit_ip="8.8.8.8")
        old = {"nodes": nodes}
        legacy = retention.rendered_links(local._retention_context(), old)
        self.assertEqual(legacy, [local.published_link(BEST50, n, "DE", "Berlin", "8.8.8.8",
                                                   presentation_version=1) for n in (1, 2)])
        self.assertIn("%7C%201%20%7C", legacy[0])
        old["presentation_version"] = 2
        current = retention.rendered_links(local._retention_context(), old)
        self.assertEqual(current, retention.rendered_links(local._retention_context(), old))
        from urllib.parse import unquote
        self.assertEqual([unquote(link.split("#", 1)[1]) for link in current],
                         [f"🇩🇪 DE, Berlin  |{n}|   [8.8.8.8]" for n in (1, 2)])


if __name__ == "__main__":
    unittest.main()
