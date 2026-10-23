import asyncio
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("primary_test_build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

UUID = "11111111-1111-4111-8111-111111111111"
LINK = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com#public"


class PrimaryPolicyTests(unittest.TestCase):
    def test_malformed_unsupported_private_and_unsafe_vless_are_rejected(self):
        for link in (LINK.replace(UUID, "broken"), LINK.replace("1.1.1.1", "127.0.0.1"), LINK + "&x=bad\n", LINK.replace("security=tls", "security=unknown"), LINK + "&type=unknown", LINK + "&allowInsecure=1", LINK + "&security=none", LINK.replace("#public", "&sni=example.org")):
            # Put added parameters before the presentation fragment.
            link = link.replace("#public&", "&")
            with self.subTest(link=link), self.assertRaises(ValueError):
                build.parse_vless(link)
        node = build.parse_vless(LINK)
        self.assertEqual(node["uuid"], UUID)
        self.assertEqual(node["protocol"], "vless")

    def test_actual_private_dns_endpoint_rejected(self):
        infos = [(2, 1, 6, "", ("10.0.0.2", 0))]
        with patch.object(build.socket, "getaddrinfo", return_value=infos):
            self.assertEqual(build.resolve_endpoint_ip("proxy.example.com"), "")

    def test_http_redirect_error_and_challenge_never_count_as_success(self):
        body = b"<html><title>ChatGPT</title>" + b"x" * 3000
        for status in ("301", "302", "403", "429", "500"):
            self.assertFalse(build.validate_primary_response("https://chatgpt.com/", status, body, len(body)))
        challenge = body + b"cf-chl- verify you are human"
        self.assertFalse(build.validate_primary_response("https://chatgpt.com/", "200", challenge, len(challenge)))
        self.assertTrue(build.validate_primary_response("https://chatgpt.com/", "200", body, len(body)))

    def test_primary_endpoint_evidence_and_payload_integrity(self):
        self.assertTrue(build.validate_primary_response("https://www.gstatic.com/generate_204", "204", b"", 0))
        self.assertFalse(build.validate_primary_response("https://www.gstatic.com/generate_204", "200", b"captive portal", 14))
        trace = b"h=www.cloudflare.com\nip=1.1.1.1\nloc=DE\n"
        self.assertTrue(build.validate_primary_response("https://www.cloudflare.com/cdn-cgi/trace", "200", trace, len(trace)))
        self.assertFalse(build.validate_primary_response("https://www.cloudflare.com/cdn-cgi/trace", "200", b"unrelated intermediary", 22))
        self.assertFalse(build.validate_primary_response("https://speed.cloudflare.com/__down?bytes=1000000", "200", b"short", 5))
        self.assertTrue(build.validate_primary_response("https://speed.cloudflare.com/__down?bytes=1000000", "200", b"x", 1000000))

    def test_different_endpoint_is_not_collapsed_to_same_account(self):
        first = build.parse_vless(LINK)
        second = build.parse_vless(LINK.replace('1.1.1.1', '8.8.8.8'))
        self.assertNotEqual(build.normalized_fingerprint(first), build.normalized_fingerprint(second))

    def test_grpc_service_names_remain_distinct(self):
        first = build.parse_vless(LINK.replace("#public", "&type=grpc&serviceName=one"))
        second = build.parse_vless(LINK.replace("#public", "&type=grpc&serviceName=two"))
        self.assertNotEqual(build.normalized_fingerprint(first), build.normalized_fingerprint(second))

    def run_pipeline(self, directory, final_results):
        node = build.parse_vless(LINK)
        node.update(country="US", infrastructure="infra-one", endpoint_family="family-one")
        class Pool:
            def __init__(self, *_args, **_kwargs):
                self.stats = {"fetched_sources": 1}
            def collect(self):
                return [LINK], {"public-source": {"candidates": 1}}
            def feedback(self, *_args):
                pass
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build, "OUT", Path(directory)))
            stack.enter_context(patch.object(build, "SourcePool", Pool))
            stack.enter_context(patch.object(build, "load_regional_sources", return_value=([], {"status": "fixture", "active": 0})))
            stack.enter_context(patch.object(build, "load_regional_feedback", return_value=({}, {"status": "fixture", "records": 0})))
            stack.enter_context(patch.object(build, "classify_countries_batch", AsyncMock(return_value=[node])))
            stack.enter_context(patch.object(build, "run_first_pass", AsyncMock(return_value=[(LINK, 100.0)])))
            stack.enter_context(patch.object(build, "run_final_pass", AsyncMock(return_value=final_results)))
            stack.enter_context(patch.object(build, "load_history", return_value={}))
            stack.enter_context(patch.object(build, "save_history"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return asyncio.run(build.main_async())

    def test_one_genuinely_qualified_node_can_publish_up_to50_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_pipeline(directory, {LINK: [100.0] * 5}), 0)
            status = json.loads((Path(directory) / "status.json").read_text())
            self.assertEqual(status["published"]["best50"], 1)
            self.assertEqual(status["final_stable"], 1)
            self.assertGreater(status["valid_until"], status["generated_at"])
            published = (Path(directory) / "best50.txt").read_text()
            self.assertEqual(len([line for line in published.splitlines() if line.startswith("vless://")]), 1)

    def test_zero_qualified_preserves_last_good_subscription_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "best50.txt").write_text("last-known-good\n")
            (path / "status.json").write_text('{"generated_at":123}\n')
            self.assertEqual(self.run_pipeline(directory, {LINK: []}), 1)
            self.assertEqual((path / "best50.txt").read_text(), "last-known-good\n")
            self.assertEqual(json.loads((path / "status.json").read_text())["generated_at"], 123)


if __name__ == "__main__":
    unittest.main()
