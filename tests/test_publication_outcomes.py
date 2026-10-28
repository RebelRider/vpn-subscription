from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from scripts import local_probe as local
from scripts import service_probe


class PublicationOutcomeTests(unittest.TestCase):
    def test_queue_deferral_remains_inconclusive_and_preserves_safe_admission_diagnostics(self):
        result = {"qualified": False, "reason": "browser-queue-deferred-inconclusive",
                  "rounds": [], "browser_started": False, "queued_wait_ms": 45000,
                  "unsafe": "must-not-be-copied"}
        diagnostic = service_probe.browser_diagnostic(result, None)
        self.assertEqual(diagnostic["reason"], "browser-queue-deferred-inconclusive")
        self.assertIs(diagnostic["browser_started"], False)
        self.assertEqual(diagnostic["queued_wait_ms"], 45000)
        self.assertNotIn("unsafe", diagnostic)

    def status(self, count=0):
        return {"generated_at": "2026-10-28T17:00:00+00:00",
                "stability": {"qualified": count}, "publication": {"enabled": True}}

    def test_completed_empty_run_and_successful_health_are_distinct_from_upload_failure(self):
        for outcome in ("published", "unchanged", "superseded"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                proof = Path(directory)/"status.json"
                status = self.status()
                with patch.object(local, "publish_regional_health", return_value=outcome), \
                        patch.object(local, "publish_regional_result") as publish:
                    local.publish_validation_results(Path(directory)/"retained.txt", proof, status, "tested")
                publish.assert_not_called()
                saved = json.loads(proof.read_text())
                self.assertEqual(saved["publication"]["subscription_status"], "retained")
                self.assertEqual(saved["publication"]["health_status"], outcome)
                self.assertEqual(saved["generated_at"], status["generated_at"])

    def test_empty_health_upload_failure_is_persisted_without_fabricating_success(self):
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory)/"status.json"
            with patch.object(local, "publish_regional_health", side_effect=RuntimeError("offline")):
                local.publish_validation_results(Path(directory)/"retained.txt", proof, self.status(), "tested")
            self.assertEqual(json.loads(proof.read_text())["publication"], {
                "enabled": True, "subscription_status": "retained", "health_status": "failed"})

    def test_missing_health_confirmation_does_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory)/"status.json"
            with patch.object(local, "publish_regional_health", return_value=None):
                local.publish_validation_results(Path(directory)/"retained.txt", proof, self.status(), "tested")
            self.assertEqual(json.loads(proof.read_text())["publication"]["health_status"], "failed")

    def test_verified_subscription_is_retained_when_later_health_upload_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory)/"status.json"
            with patch.object(local, "publish_regional_result"), \
                    patch.object(local, "publish_regional_health", side_effect=RuntimeError("offline")), \
                    self.assertRaises(RuntimeError):
                local.publish_validation_results(Path(directory)/"subscription.txt", proof, self.status(1), "tested")
            self.assertEqual(json.loads(proof.read_text())["publication"], {
                "enabled": True, "subscription_status": "published", "health_status": "failed"})

    def test_subscription_failure_never_marks_health_or_subscription_success(self):
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory)/"status.json"
            with patch.object(local, "publish_regional_result", side_effect=RuntimeError("offline")), \
                    patch.object(local, "publish_regional_health") as health, self.assertRaises(RuntimeError):
                local.publish_validation_results(Path(directory)/"subscription.txt", proof, self.status(1), "tested")
            health.assert_not_called()
            self.assertEqual(json.loads(proof.read_text())["publication"]["subscription_status"], "failed")

    def test_unexpected_error_or_interruption_cannot_leave_a_prepublication_success_marker(self):
        for error in (OSError("offline"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                proof = Path(directory)/"status.json"
                status = self.status(1)
                def fail_before_verification(*_args):
                    self.assertNotEqual(json.loads(proof.read_text())["publication"].get("subscription_status"), "published")
                    raise error
                with patch.object(local, "publish_regional_result", side_effect=fail_before_verification), \
                        self.assertRaises(type(error)):
                    local.publish_validation_results(Path(directory)/"subscription.txt", proof, status, "tested")
                self.assertEqual(json.loads(proof.read_text())["publication"]["subscription_status"], "failed")


if __name__ == "__main__":
    unittest.main()
