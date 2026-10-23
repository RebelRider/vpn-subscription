import asyncio
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bestlocal_service_probe", ROOT / "scripts" / "service_probe.py")
probe = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(probe)

LINK = "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls"
NODE = {"uuid": "123e4567-e89b-12d3-a456-426614174000", "server": "example.com", "port": 443,
        "sni": "example.com", "security": "tls"}


def response(service, **changes):
    if service == "chatgpt":
        body = json.dumps({"openai": {"id": "openai", "name": "openai", "type": "oauth",
                                     "signinUrl": "https://chatgpt.com/api/auth/signin/openai",
                                     "callbackUrl": "https://chatgpt.com/api/auth/callback/openai"}}).encode()
    elif service == "youtube":
        body = json.dumps({"provider_name": "YouTube", "type": "video", "title": "YouTube API test",
                           "html": '<iframe src="https://www.youtube.com/embed/M7lc1UVf-VE?feature=oembed"></iframe>'}).encode()
    elif service == "instagram":
        body = (b'<html><link rel="canonical" href="https://www.instagram.com/accounts/login/">'
                b'<script src="https://static.cdninstagram.com/rsrc.php/script.js"></script>'
                b'"PolarisLoginPage.react"' + b" " * 1200 + b"</html>")
    elif service == "trace":
        body = b"fl=123\nip=8.8.8.8\nloc=DE\ntls=TLSv1.3\n"
    else:
        body = b""
    result = {"status": 204 if service == "latency" else 200,
              "url": probe.SERVICE_URLS.get(service, probe.LATENCY_URL if service == "latency" else probe.TRACE_URL),
              "body": body, "content_type": "text/html" if service == "instagram" else "application/json",
              "latency_ms": 150.0}
    result.update(changes)
    return result


def report(samples):
    return {"services": {name: {"passed": 3, "attempts": 3, "reasons": ["ok"] * 3} for name in probe.SERVICE_URLS},
            "latency_samples_ms": samples, "median_ms": None, "p95_ms": None,
            "rejection_reasons": [], "qualified": False}


def build_stub():
    return SimpleNamespace(
        SING_BOX="/test/sing-box", parse_vless=Mock(return_value=copy.deepcopy(NODE)),
        vless_to_singbox=Mock(return_value={"type": "vless", "tag": "candidate", "server": "example.com",
                                          "server_port": 443, "uuid": NODE["uuid"],
                                          "tls": {"enabled": True}}),
        _register_owned_probe_process=Mock(), _stop_owned_probe_process=AsyncMock(),
    )


class ResponseValidationTests(unittest.TestCase):
    def test_real_application_shapes_pass(self):
        for service in probe.SERVICE_URLS:
            with self.subTest(service=service):
                self.assertEqual(probe.validate_response(service, response(service)), (True, "ok"))

    def test_captive_200_does_not_pass_any_service(self):
        for service in probe.SERVICE_URLS:
            with self.subTest(service=service):
                self.assertFalse(probe.validate_response(service, response(service, body=b"<html>Log in for free Internet Instagram ChatGPT YouTube</html>", content_type="text/html"))[0])

    def test_challenge_and_rate_limit_are_inconclusive(self):
        for service in probe.SERVICE_URLS:
            for status in (403, 429):
                with self.subTest(service=service, status=status):
                    passed, reason = probe.validate_response(service, response(service, status=status))
                    self.assertFalse(passed)
                    self.assertIn("inconclusive", reason)
            self.assertFalse(probe.validate_response(service, response(service, body=b"Just a moment cf-chl-widget captcha"))[0])

    def test_malformed_json_and_unrelated_provider_rejected(self):
        self.assertFalse(probe.validate_response("chatgpt", response("chatgpt", body=b"{"))[0])
        self.assertFalse(probe.validate_response("chatgpt", response("chatgpt", body=b'{"google":{"id":"google","type":"oauth"}}'))[0])
        payload = json.loads(response("chatgpt")["body"])
        payload["openai"]["callbackUrl"] = "https://example.com/api/auth/callback/openai"
        self.assertFalse(probe.validate_response("chatgpt", response("chatgpt", body=json.dumps(payload).encode()))[0])

    def test_malformed_provider_field_fails_closed(self):
        payload = json.loads(response("chatgpt")["body"])
        payload["openai"]["type"] = ["oauth"]
        self.assertFalse(probe.validate_response("chatgpt", response("chatgpt", body=json.dumps(payload).encode()))[0])

    def test_wrong_video_and_wrong_host_rejected(self):
        payload = json.loads(response("youtube")["body"])
        payload["html"] = '<iframe src="https://www.youtube.com/embed/wrong"></iframe>'
        self.assertFalse(probe.validate_response("youtube", response("youtube", body=json.dumps(payload).encode()))[0])
        self.assertFalse(probe.validate_response("youtube", response("youtube", url="https://youtube.com.evil.example/oembed"))[0])
        payload["html"] = '<iframe src="https://www.youtube.com:invalid/embed/M7lc1UVf-VE"></iframe>'
        self.assertFalse(probe.validate_response("youtube", response("youtube", body=json.dumps(payload).encode()))[0])

    def test_brand_strings_are_insufficient_for_instagram(self):
        body = b"Instagram login" + b" " * 2000
        self.assertFalse(probe.validate_response("instagram", response("instagram", body=body))[0])
        self.assertFalse(probe.validate_response("instagram", response("instagram", body=response("instagram")["body"], url="https://www.instagram.com/challenge/"))[0])
        generic_app_shell = response("instagram")["body"].replace(b"PolarisLoginPage", b"PolarisErrorPage")
        self.assertFalse(probe.validate_response("instagram", response("instagram", body=generic_app_shell))[0])

    def test_latency_requires_empty_204(self):
        self.assertTrue(probe.validate_response("latency", response("latency"))[0])
        self.assertFalse(probe.validate_response("latency", response("latency", body=b"blocked"))[0])
        self.assertFalse(probe.validate_response("latency", response("latency", status=200))[0])

    def test_exact_threshold_nan_and_missing_samples_rejected(self):
        for samples in ([499, 500, 501], [100, float("nan"), 100], [100, float("inf"), 100], [-1, 100, 100], [100]):
            with self.subTest(samples=samples):
                self.assertFalse(probe.summarize_report(report(samples), 3)["qualified"])
        result = probe.summarize_report(report([480, 499, 499]), 3)
        self.assertTrue(result["qualified"])
        self.assertEqual(result["median_ms"], 499)
        self.assertEqual(result["p95_ms"], 499)

    def test_all_service_rounds_required(self):
        result = report([100, 100, 100])
        result["services"]["instagram"]["passed"] = 2
        self.assertFalse(probe.summarize_report(result, 3)["qualified"])

    def test_public_exit_trace_required(self):
        self.assertEqual(probe.parse_exit_trace(b"ip=8.8.8.8\nloc=DE\n"), {"ip": "8.8.8.8", "loc": "DE"})
        self.assertIsNone(probe.parse_exit_trace(b"ip=127.0.0.1\nloc=DE\n"))
        self.assertIsNone(probe.parse_exit_trace(b"ip=8.8.8.8\nloc=unknown\n"))


class IsolationTests(unittest.TestCase):
    def test_only_auth_loopback_socks_to_pinned_vless_on_en0(self):
        build = build_stub()
        config = probe.make_config(build, NODE, "8.8.8.8", "en0", 38291, "random-user", "random-pass")
        self.assertEqual(len(config["outbounds"]), 1)
        self.assertEqual(config["outbounds"][0]["type"], "vless")
        self.assertEqual(config["outbounds"][0]["server"], "8.8.8.8")
        self.assertEqual(config["outbounds"][0]["tls"]["server_name"], "example.com")
        self.assertEqual(config["outbounds"][0]["bind_interface"], "en0")
        self.assertEqual(config["route"], {"default_interface": "en0", "final": "candidate"})
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][0]["users"], [{"username": "random-user", "password": "random-pass"}])
        self.assertNotIn('"tun"', json.dumps(config))
        self.assertNotIn('"direct"', json.dumps(config))

    def test_curl_cannot_bypass_proxy_or_disable_tls(self):
        command = probe._curl_command(probe.LATENCY_URL, 38291, "user", "secret")
        self.assertEqual(command[command.index("--proxy") + 1], "socks5h://127.0.0.1:38291")
        self.assertEqual(command[command.index("--noproxy") + 1], "")
        self.assertEqual(command[command.index("--proto") + 1], "=https")
        self.assertIn("--socks5-basic", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--location", command)
        self.assertEqual(command[1], "--disable")

    def test_insecure_tls_configuration_rejected(self):
        build = build_stub()
        build.vless_to_singbox.return_value["tls"]["insecure"] = True
        with self.assertRaises(ValueError):
            probe.make_config(build, NODE, "8.8.8.8", "en0", 38291, "user", "pass")

    def test_supported_non_vless_protocols_use_same_isolated_checks(self):
        for protocol in sorted(probe.ALLOWED_OUTBOUND_TYPES - {"vless"}):
            with self.subTest(protocol=protocol):
                build = build_stub()
                build.vless_to_singbox.return_value["type"] = protocol
                if protocol != "vmess":
                    del build.vless_to_singbox.return_value["uuid"]
                    build.vless_to_singbox.return_value["password"] = "protocol-password"
                config = probe.make_config(build, NODE, "8.8.8.8", "en0", 38291, "user", "pass")
                self.assertEqual(config["outbounds"][0]["type"], protocol)
                self.assertEqual(config["outbounds"][0]["bind_interface"], "en0")
                self.assertEqual(config["route"]["final"], "candidate")

    def test_direct_and_unknown_outbounds_rejected(self):
        for protocol in ("direct", "selector", "urltest", "wireguard", "tuic", "unknown"):
            build = build_stub()
            build.vless_to_singbox.return_value["type"] = protocol
            with self.assertRaises(ValueError):
                probe.make_config(build, NODE, "8.8.8.8", "en0", 38291, "user", "pass")


class AsyncProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_or_mixed_resolution_rejected(self):
        with self.assertRaises(ValueError):
            await probe._resolve_public_server("127.0.0.1", 443)
        with self.assertRaises(ValueError):
            await probe._resolve_public_server("224.1.1.1", 443)
        addresses = [(socket_family, 1, 6, "", (host, 443)) for socket_family, host in ((2, "8.8.8.8"), (2, "127.0.0.1"))]
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=addresses)):
            with self.assertRaises(ValueError):
                await probe._resolve_public_server("example.com", 443)

    async def test_redirects_never_leave_expected_https_service(self):
        first = response("chatgpt", status=302, location="https://example.org/blocked")
        with patch.object(probe, "_http_once", AsyncMock(return_value=first)) as request:
            result = await probe._request(None, "chatgpt", probe.SERVICE_URLS["chatgpt"], 12345, "user", "pass")
            self.assertEqual(result["error"], "unexpected-redirect")
            self.assertEqual(request.await_count, 1)

    async def test_full_candidate_success_and_same_proxy_trace(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service)
        with patch.object(probe, "_resolve_public_server", AsyncMock(return_value="8.8.8.8")), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)) as requests:
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertTrue(result["qualified"])
        self.assertEqual(result["exit_trace"], {"ip": "8.8.8.8", "loc": "DE"})
        self.assertEqual(len(requests.await_args_list), 13)
        self.assertEqual(len({args.args[3:] for args in requests.await_args_list}), 1)
        for service in result["services"].values():
            self.assertEqual((service["attempts"], service["passed"]), (3, 3))
        build._stop_owned_probe_process.assert_awaited_once_with(child)

    async def test_one_failed_service_rejects_and_other_services_still_attempted(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service, **({"status": 429} if service == "instagram" else {}))
        with patch.object(probe, "_resolve_public_server", AsyncMock(return_value="8.8.8.8")), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)):
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertFalse(result["qualified"])
        self.assertTrue(all(service["attempts"] == 1 for service in result["services"].values()))
        self.assertEqual(result["services"]["instagram"]["reasons"], ["rate-limited-inconclusive"])
        build._stop_owned_probe_process.assert_awaited_once_with(child)

    async def test_cancellation_reaps_only_owned_child(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        ready = asyncio.Event()
        async def wait_start(*args):
            ready.set()
            await asyncio.Event().wait()
        with patch.object(probe, "_resolve_public_server", AsyncMock(return_value="8.8.8.8")), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", side_effect=wait_start):
            task = asyncio.create_task(probe._validate_one(build, LINK, 3, "en0"))
            await ready.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(build._stop_owned_probe_process.await_count >= 1)
        self.assertTrue(all(call.args == (child,) for call in build._stop_owned_probe_process.await_args_list))

    async def test_bounded_concurrency_and_policy_flags(self):
        active, maximum = 0, 0
        async def validate(*args):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(.001)
            active -= 1
            return {"qualified": False}
        with patch.object(probe, "_validate_one", side_effect=validate):
            result = await probe.validate_candidates(None, [str(i) for i in range(12)] + ["0"], rounds=3)
        self.assertEqual(len(result), 12)
        self.assertLessEqual(maximum, 4)
        for kwargs in ({"rounds": 1}, {"rounds": 6}, {"interface": "utun4"}, {"interface": "en0;route"}):
            with self.assertRaises(ValueError):
                await probe.validate_candidates(None, [], **kwargs)

    async def test_bounded_http_parser_uses_curl_measured_time(self):
        build = build_stub()
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/2 204 \r\ncontent-type: text/plain\r\n\r\n\nBESTLOCAL_TIME_TOTAL:0.123456")
        reader.feed_eof()
        child = SimpleNamespace(stdout=reader, returncode=0, wait=AsyncMock())
        with patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)):
            result = await probe._http_once(build, probe.LATENCY_URL, 12345, "user", "pass")
        self.assertEqual(result["body"], b"")
        self.assertAlmostEqual(result["latency_ms"], 123.456)
        self.assertTrue(probe.validate_response("latency", result)[0])
        build._stop_owned_probe_process.assert_awaited_once_with(child)

    async def test_large_decompressed_response_terminates_owned_curl(self):
        build = build_stub()
        reader = asyncio.StreamReader()
        reader.feed_data(b"x" * (probe.MAX_RESPONSE_BYTES + probe.MAX_HEADERS_BYTES + 1))
        reader.feed_eof()
        child = SimpleNamespace(stdout=reader, returncode=0, wait=AsyncMock())
        with patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)):
            result = await probe._http_once(build, probe.LATENCY_URL, 12345, "user", "pass")
        self.assertEqual(result["error"], "response-too-large")
        build._stop_owned_probe_process.assert_awaited_once_with(child)


if __name__ == "__main__":
    unittest.main()
