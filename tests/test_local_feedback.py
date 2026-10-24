import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import local_feedback as feedback


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("feedback_test_build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
NOW = 2_000_000_000


def identifier(index):
    return format(index, "064x")


def health(records=None, **changes):
    result = {"schema": 1, "policy": feedback.POLICY, "generated_at": NOW,
              "recent_results": records or {}, "diagnostics": []}
    result.update(changes)
    return json.dumps(result).encode()


def candidates(count):
    schemes = ("vless", "vmess", "trojan", "ss", "hy2", "socks")
    return [{"link": f"{schemes[index % len(schemes)]}://validated-{index}",
             "normalized": identifier(index + 1), "score": 10000 - index,
             "country": "US", "infrastructure": "one-validated-provider",
             "endpoint_family": f"family-{index}", "metrics": {"median_latency_ms": index + 1}}
            for index in range(count)]


class FeedbackParserTests(unittest.TestCase):
    def test_fresh_strict_health_parses_recent_and_diagnostics(self):
        records, summary = feedback.parse_health(health(
            {identifier(1): {"last_seen": NOW - 100, "qualified": False}},
            diagnostics=[{"id": identifier(2), "qualified": True, "ignored_external_payload": "not propagated"}],
        ), now=NOW)
        self.assertEqual(summary["status"], "fresh")
        self.assertEqual(records[identifier(1)], {"last_seen": NOW - 100, "qualified": False})
        self.assertEqual(records[identifier(2)], {"last_seen": NOW, "qualified": True})

    def test_optional_valid_outcomes_are_retained_without_changing_legacy_records(self):
        records, _ = feedback.parse_health(health({
            identifier(1): {"last_seen": NOW, "qualified": False, "outcome": "inconclusive"},
            identifier(2): {"last_seen": NOW, "qualified": False, "outcome": "fail"},
            identifier(3): {"last_seen": NOW, "qualified": True, "outcome": "pass"},
            identifier(4): {"last_seen": NOW, "qualified": False},
        }), now=NOW)
        self.assertEqual(records[identifier(1)]["outcome"], "inconclusive")
        self.assertEqual(records[identifier(2)]["outcome"], "fail")
        self.assertEqual(records[identifier(3)]["outcome"], "pass")
        self.assertNotIn("outcome", records[identifier(4)])

    def test_malformed_and_contradictory_optional_outcomes_are_ignored(self):
        for value in ([], {}, 1, True, "unknown", "pass"):
            records, _ = feedback.parse_health(health({identifier(1): {
                "last_seen": NOW, "qualified": False, "outcome": value}}), now=NOW)
            self.assertEqual(records[identifier(1)], {"last_seen": NOW, "qualified": False})

    def test_only_rich_diagnostics_infer_inconclusive_and_definitive_outcomes(self):
        diagnostics = [
            {"id": identifier(1), "qualified": False,
             "services": {"chatgpt": {"evidence": [{"outcome": "inconclusive", "cf_challenge": True}]}}},
            {"id": identifier(2), "qualified": False, "engine_errors": {"dns-failed": 2}},
            {"id": identifier(3), "qualified": False, "rejection_reasons": ["service-requirements-failed"]},
            {"id": identifier(4), "qualified": True, "services": {"chatgpt": {"evidence": []}}},
        ]
        records, _ = feedback.parse_health(health(diagnostics=diagnostics), now=NOW)
        self.assertEqual(records[identifier(1)]["outcome"], "inconclusive")
        self.assertEqual(records[identifier(2)]["outcome"], "fail")
        self.assertNotIn("outcome", records[identifier(3)])
        self.assertEqual(records[identifier(4)]["outcome"], "pass")

    def test_missing_corrupt_oversize_schema_and_policy_fail_closed(self):
        for raw in (b"", b"broken", b"[]", b"[" * 2000 + b"]" * 2000, b"x" * (feedback.MAX_BYTES + 1),
                    health(schema=True), health(schema=2), health(policy="old-weak-policy"),
                    health(recent_results=[]), health(diagnostics={})):
            with self.subTest(raw=raw[:80]):
                records, summary = feedback.parse_health(raw, now=NOW)
                self.assertFalse(records)
                self.assertNotEqual(summary["status"], "fresh")

    def test_stale_future_and_nonfinite_health_rejected(self):
        for epoch in (NOW - feedback.MAX_HEALTH_AGE - 1, NOW + 1, float("nan"), float("inf"), True):
            records, summary = feedback.parse_health(health(generated_at=epoch), now=NOW)
            self.assertFalse(records)
            self.assertNotEqual(summary["status"], "fresh")

    def test_malformed_and_future_records_are_ignored(self):
        records, summary = feedback.parse_health(health({
            "../../bad": {"last_seen": NOW, "qualified": False},
            identifier(1): {"last_seen": NOW + 1, "qualified": False},
            identifier(2): {"last_seen": NOW, "qualified": "false"},
            identifier(3): {"last_seen": float("nan"), "qualified": True},
            identifier(4): {"last_seen": NOW, "qualified": True},
        }), now=NOW)
        self.assertEqual(set(records), {identifier(4)})
        self.assertEqual(summary["invalid_records"], 4)

    def test_id_and_blob_budgets(self):
        too_many = {identifier(i): {"last_seen": NOW, "qualified": False} for i in range(feedback.MAX_IDS + 1)}
        self.assertFalse(feedback.parse_health(health(too_many), now=NOW)[0])
        combined = {identifier(i): {"last_seen": NOW, "qualified": False} for i in range(feedback.MAX_IDS)}
        self.assertFalse(feedback.parse_health(health(combined, diagnostics=[{"id": identifier(6000), "qualified": True}]), now=NOW)[0])

    def test_git_blob_is_pinned_before_size_and_read(self):
        oid = "a" * 40
        raw = health()
        outputs = [subprocess.CompletedProcess([], 0, oid.encode() + b"\n"),
                   subprocess.CompletedProcess([], 0, str(len(raw)).encode() + b"\n"),
                   subprocess.CompletedProcess([], 0, raw)]
        with patch.object(feedback.subprocess, "run", side_effect=outputs) as run:
            self.assertEqual(feedback.read_regional_health(ROOT), raw)
        self.assertEqual(run.call_args_list[1].args[0], ["git", "cat-file", "-s", oid])
        self.assertEqual(run.call_args_list[2].args[0], ["git", "cat-file", "blob", oid])

    def test_unavailable_git_feedback_does_not_stop_primary(self):
        with patch.object(feedback, "read_regional_health", side_effect=subprocess.TimeoutExpired("git", 5)):
            records, summary = feedback.load_regional_feedback(ROOT, now=NOW)
        self.assertEqual(records, {})
        self.assertEqual(summary["status"], "unavailable")

    def test_real_local_git_health_read_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            raw = health({identifier(1): {"last_seen": NOW, "qualified": False}})
            oid = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=raw, stdout=subprocess.PIPE, check=True).stdout.decode().strip()
            tree = subprocess.run(["git", "-C", str(repo), "mktree"], input=f"100644 blob {oid}\tlocal-health.json\n".encode(), stdout=subprocess.PIPE, check=True).stdout.decode().strip()
            root = subprocess.run(["git", "-C", str(repo), "mktree"], input=f"040000 tree {tree}\toutput\n".encode(), stdout=subprocess.PIPE, check=True).stdout.decode().strip()
            with patch.dict("os.environ", {"GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com", "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com"}):
                commit = subprocess.run(["git", "-C", str(repo), "commit-tree", root, "-m", "fixture"], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
            subprocess.run(["git", "-C", str(repo), "update-ref", "refs/remotes/origin/regional", commit], check=True)
            records, summary = feedback.load_regional_feedback(repo, now=NOW)
            self.assertEqual(summary["status"], "fresh")
            self.assertEqual(set(records), {identifier(1)})


class FeedbackRankingTests(unittest.TestCase):
    def test_inconclusive_candidates_are_not_twelve_hour_demoted(self):
        ranked = candidates(4)
        records = {ranked[0]["normalized"]: {"last_seen": NOW - 1, "qualified": False, "outcome": "inconclusive"},
                   ranked[1]["normalized"]: {"last_seen": NOW - 1, "qualified": False, "outcome": "fail"}}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        self.assertEqual([item["link"] for item in ordered], [ranked[i]["link"] for i in (0, 2, 3, 1)])
        self.assertEqual(summary["inconclusive"], 1)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["applied"], 1)
        self.assertEqual(ordered[0]["score"], ranked[0]["score"])
        self.assertEqual(ordered[0]["_local_feedback_group"], 1)

    def test_explicit_recent_strict_pass_retains_same_bounded_bonus(self):
        ranked = candidates(4)
        records = {ranked[3]["normalized"]: {"last_seen": NOW - 1, "qualified": True, "outcome": "pass"}}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        self.assertEqual(ordered[0]["link"], ranked[3]["link"])
        self.assertAlmostEqual(ordered[0]["score"], ranked[3]["score"] * 1.05)
        self.assertEqual((summary["passed"], summary["rejected"], summary["inconclusive"]), (1, 0, 0))

    def test_fifty_rejected_are_replaced_by_next_fifty_validated(self):
        ranked = candidates(100)
        original = copy.deepcopy(ranked)
        records = {item["normalized"]: {"last_seen": NOW - 60, "qualified": False} for item in ranked[:50]}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        chosen = build.select_diverse(ordered, 50)
        self.assertEqual({item["link"] for item in chosen}, {item["link"] for item in ranked[50:]})
        self.assertEqual(summary["rejected"], 50)
        self.assertEqual(ranked, original)

    def test_insufficient_alternatives_still_exhausts_untested_first(self):
        ranked = candidates(70)
        records = {item["normalized"]: {"last_seen": NOW - 1, "qualified": False} for item in ranked[:50]}
        ordered, _ = feedback.apply_feedback(ranked, records, now=NOW)
        chosen = build.select_diverse(ordered, 50)
        self.assertEqual({item["link"] for item in chosen[:20]}, {item["link"] for item in ranked[50:]})
        self.assertEqual(len(chosen), 50)
        self.assertTrue(set(item["link"] for item in chosen).issubset(item["link"] for item in ranked))

    def test_expired_rejections_are_eligible_again_at_twelve_hours(self):
        ranked = candidates(10)
        records = {ranked[0]["normalized"]: {"last_seen": NOW - feedback.REJECT_COOLDOWN, "qualified": False}}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        self.assertEqual([item["link"] for item in ordered], [item["link"] for item in ranked])
        self.assertEqual(summary["expired"], 1)
        self.assertEqual(summary["applied"], 0)

    def test_recent_local_pass_and_score_order_inside_groups(self):
        ranked = candidates(6)
        records = {ranked[4]["normalized"]: {"last_seen": NOW - 60, "qualified": True},
                   ranked[1]["normalized"]: {"last_seen": NOW - 60, "qualified": False}}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        self.assertEqual([item["link"] for item in ordered], [ranked[i]["link"] for i in (4, 0, 2, 3, 5, 1)])
        self.assertEqual((summary["passed"], summary["rejected"]), (1, 1))
        self.assertAlmostEqual(ordered[0]["score"], ranked[4]["score"] * 1.05)
        self.assertEqual(ordered[0]["_local_feedback_group"], 1)

    def test_local_pass_bonus_is_bounded_and_preserves_provider_diversity(self):
        ranked = candidates(100)
        for index, item in enumerate(ranked):
            item["infrastructure"] = "local-pass-provider" if index < 50 else f"untested-provider-{index}"
            item["country"] = ("US", "DE", "GB", "NL", "PL")[index % 5]
        records = {item["normalized"]: {"last_seen": NOW - 1, "qualified": True} for item in ranked[:50]}
        ordered, _ = feedback.apply_feedback(ranked, records, now=NOW)
        reapplied, _ = feedback.apply_feedback(ordered, records, now=NOW)
        self.assertEqual([item["score"] for item in reapplied], [item["score"] for item in ordered])
        chosen = build.select_diverse(ordered, 50)
        local_provider_count = sum(item["infrastructure"] == "local-pass-provider" for item in chosen)
        self.assertGreaterEqual(local_provider_count, 1)
        self.assertLessEqual(local_provider_count, 3)
        self.assertEqual(len(chosen), 50)

    def test_unvalidated_unknown_and_short_ids_cannot_add_candidates(self):
        ranked = candidates(6)
        records = {identifier(9999): {"last_seen": NOW, "qualified": True},
                   ranked[0]["normalized"][:32]: {"last_seen": NOW, "qualified": True}}
        ordered, summary = feedback.apply_feedback(ranked, records, now=NOW)
        self.assertEqual([item["link"] for item in ordered], [item["link"] for item in ranked])
        self.assertEqual(summary["unmatched"], 2)
        self.assertEqual(summary["applied"], 0)

    def test_absent_feedback_preserves_existing_diversity_selection(self):
        ranked = candidates(100)
        baseline = build.select_diverse(ranked, 50)
        ordered, _ = feedback.apply_feedback(ranked, {}, now=NOW)
        self.assertEqual([item["link"] for item in build.select_diverse(ordered, 50)], [item["link"] for item in baseline])


class DiagnosticClassifierTests(unittest.TestCase):
    def test_strict_qualified_pass_is_authoritative(self):
        self.assertEqual(feedback.classify_diagnostic({"qualified": True, "engine_errors": {"timeout": 1}}), "pass")

    def test_challenge_http_rate_limit_and_unavailable_browser_take_precedence(self):
        for uncertain in (
            {"browser_check": {"reason": "browser-check-unavailable"}},
            {"control": {"reason": "positive-control-failed"}},
            {"services": {"chatgpt": {"evidence": [{"cf_challenge": True}]}}},
            {"services": {"chatgpt": {"evidence": [{"http_status": 403}]}}},
            {"services": {"chatgpt": {"evidence": [{"http_status": 429}]}}},
            {"services": {"chatgpt": {"evidence": [{"http_status": 503}]}}},
            {"services": {"chatgpt": {"reasons": ["cloudflare-challenge-inconclusive"]}}},
        ):
            diagnostic = {"qualified": False, "engine_errors": {"timeout": 2}, **uncertain}
            self.assertEqual(feedback.classify_diagnostic(diagnostic), "inconclusive")

    def test_definitive_dns_tls_protocol_socket_and_timeout_failures(self):
        for reason in ("invalid-or-unsafe-config", "server-dns-failed", "protocol-authentication-failed",
                       "protocol-handshake-failed", "routing-no-route", "destination-certificate-invalid",
                       "destination-tls-failed", "socks-connection-failed", "socket-error",
                       "proxy-request-timeout", "candidate-deadline-or-dns-timeout", "latency-not-below-500ms"):
            self.assertEqual(feedback.classify_diagnostic({"qualified": False, "rejection_reasons": [reason]}), "fail", reason)
        for code in (5, 6, 7, 28, 35, 60, 97):
            self.assertEqual(feedback.classify_diagnostic({"qualified": False,
                "services": {"chatgpt": {"evidence": [{"curl_exit": code}]}}}), "fail")

    def test_resolved_chatgpt_challenge_does_not_hide_another_service_failure(self):
        diagnostic = {"qualified": False, "services": {
            "chatgpt": {"evidence": [{"outcome": "pass", "reason": "browser-functional-access",
                "cf_challenge": True, "http_status": 403,
                "http_reason": "cloudflare-challenge-inconclusive", "http_outcome": "inconclusive"}]},
            "youtube": {"evidence": [{"outcome": "fail", "reason": "proxy-request-timeout", "curl_exit": 28}]},
        }}
        self.assertEqual(feedback.classify_diagnostic(diagnostic), "fail")

    def test_unknown_or_malformed_diagnostics_remain_inconclusive(self):
        for value in (None, [], "failed", {}, {"qualified": False},
                      {"qualified": False, "services": []},
                      {"qualified": False, "outcome": [], "engine_errors": {"timeout": "not-a-count"}},
                      {"qualified": False, "rejection_reasons": ["service-requirements-failed"]}):
            self.assertEqual(feedback.classify_diagnostic(value), "inconclusive")


if __name__ == "__main__":
    unittest.main()
