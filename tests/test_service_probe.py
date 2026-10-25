import asyncio
import copy
from collections import Counter
from datetime import datetime, timedelta, timezone
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
    elif service == "exit-ip":
        body = b'{"ip":"8.8.8.8"}'
    else:
        body = b""
    result = {"status": 204 if service == "latency" else 200,
              "url": probe.SERVICE_URLS.get(service, probe.LATENCY_URL if service == "latency" else
                                             probe.EXIT_IP_URL if service == "exit-ip" else probe.TRACE_URL),
              "body": body, "content_type": "text/html" if service == "instagram" else "application/json",
              "latency_ms": 150.0}
    result.update(changes)
    return result


def report(samples):
    return {"services": {name: {"passed": 3, "attempts": 3, "reasons": ["ok"] * 3} for name in probe.SERVICE_URLS},
            "latency_samples_ms": samples, "median_ms": None, "p95_ms": None,
            "rejection_reasons": [], "qualified": False}


def browser_round(checked_at):
    return {"passed": True, "reason": "ok", "checked_at": checked_at,
            "http_status": 200, "composer": True, "application_json": True,
            "actionable": True, "restriction_free": True}


def build_stub():
    return SimpleNamespace(
        SING_BOX="/test/sing-box", parse_vless=Mock(return_value=copy.deepcopy(NODE)),
        vless_to_singbox=Mock(return_value={"type": "vless", "tag": "candidate", "server": "example.com",
                                          "server_port": 443, "uuid": NODE["uuid"],
                                          "tls": {"enabled": True}}),
        _register_owned_probe_process=Mock(), _stop_owned_probe_process=AsyncMock(),
    )


class ResponseValidationTests(unittest.TestCase):
    def test_inert_html_bundles_and_video_titles_are_not_active_restrictions(self):
        original = response("instagram")
        inert = b'<script type="application/json">{"errors":{"challenge_required":"unused","login_required":"unused","cf-chl-":"unused","access denied":"label"}}</script>'
        hidden = b'<div hidden>Verify you are human</div><div style="display: none">Access denied</div>'
        self.assertEqual(probe.validate_response("instagram", {**original, "body": original["body"] + inert + hidden}), (True, "ok"))
        video = response("youtube")
        data = json.loads(video["body"]);data["title"] = "Access denied — YouTube API example"
        self.assertEqual(probe.validate_response("youtube", {**video, "body": json.dumps(data).encode()}), (True, "ok"))

    def test_visible_restriction_cannot_hide_behind_real_app_markers(self):
        original = response("instagram")
        for blocker in (b'<h1>Verify you are human</h1>', b'<div role="alert">Access denied</div>', b'<h1>Unusual traffic</h1>'):
            with self.subTest(blocker=blocker):
                self.assertFalse(probe.validate_response("instagram", {**original, "body": original["body"] + blocker})[0])

    def test_real_content_from_unrelated_paths_cannot_qualify(self):
        for name in probe.SERVICE_URLS:
            original = response(name)
            url = original["url"].split("/", 3)[:3]
            self.assertFalse(probe.validate_response(name, {**original, "url": "/".join(url) + "/help/examples"})[0])
        self.assertFalse(probe.validate_response("latency", response("latency", url="https://www.gstatic.com/unrelated"))[0])

    def test_summary_requires_all_named_services_and_numeric_measurements(self):
        for services in ({}, {"chatgpt": {"passed": 3, "attempts": 3}}):
            candidate = report([100, 100, 100]);candidate["services"] = services
            self.assertFalse(probe.summarize_report(candidate, 3)["qualified"])
        self.assertFalse(probe.summarize_report(report([True, True, True]), 3)["qualified"])

    def test_cloudflare_evidence_precedes_http_denial(self):
        for changes in ({"status": 403, "body": b"<html>Just a moment cf-chl-widget</html>"},
                        {"status": 403, "cf_mitigated": "challenge"}):
            item = probe.service_evidence("chatgpt", response("chatgpt", **changes))
            self.assertEqual(item["outcome"], "inconclusive")
            self.assertEqual(item["reason"], "cloudflare-challenge-inconclusive")
            self.assertTrue(item["cf_challenge"])
            self.assertFalse(item["geo_restricted"])
            self.assertEqual(item["http_status"], 403)

    def test_geographic_restriction_requires_specific_evidence(self):
        denial = probe.service_evidence("chatgpt", response("chatgpt", status=403, body=b"Forbidden"))
        self.assertFalse(denial["geo_restricted"])
        explicit = probe.service_evidence("chatgpt", response("chatgpt", status=403,
            body=b'{"error":{"code":"unsupported_country_region_territory"}}'))
        self.assertEqual(explicit["outcome"], "fail")
        self.assertEqual(explicit["reason"], "geographic-restriction")
        self.assertTrue(explicit["geo_restricted"])
        self.assertFalse(explicit["cf_challenge"])

    def test_chatgpt_probe_method_changes_remain_inconclusive(self):
        for changes in ({"body": b"{}"}, {"body": b"[]"},
                        {"body": b"<html>ChatGPT application</html>", "content_type": "text/html"},
                        {"status": 404}, {"status": 410}):
            item = probe.service_evidence("chatgpt", response("chatgpt", **changes))
            self.assertEqual(item["outcome"], "inconclusive")
            self.assertEqual(item["http_reason"], item["reason"])
            self.assertFalse(probe.validate_response("chatgpt", response("chatgpt", **changes))[0])

    def test_browser_failure_metadata_uses_closed_reason_allowlist(self):
        diagnostic = probe.browser_diagnostic({"qualified": False, "rounds": [
            {"passed": False, "reason": "cloudflare-challenge-inconclusive", "http_status": 403,
             "composer": False, "application_json": False, "body": "private-token"}]}, None)
        self.assertEqual(diagnostic["reason"], "cloudflare-challenge-inconclusive")
        self.assertEqual(diagnostic["first_failed_http_status"], 403)
        self.assertIs(diagnostic["first_failed_composer"], False)
        self.assertIs(diagnostic["first_failed_application_json"], False)
        self.assertNotIn("private-token", json.dumps(diagnostic))
        self.assertEqual(probe.browser_diagnostic({"reason": "private-token", "rounds": []}, None)["reason"], "browser-proof-inconclusive")

    def test_error_messages_are_reduced_to_enums_without_credentials(self):
        secret = b"vless://private-token@example.com:443 "
        self.assertEqual(probe.classify_error(secret + b"no route to host"), "routing-no-route")
        self.assertEqual(probe.classify_error(secret + b"authentication failed"), "protocol-authentication-failed")
        self.assertEqual(probe.classify_error(secret + b"x509: invalid certificate"), "tls-certificate-invalid")
        self.assertNotIn("private-token", probe.classify_error(secret))

    def test_browser_proof_requires_every_fresh_round(self):
        checked = datetime.now(timezone.utc).isoformat()
        valid = {"qualified": True, "rounds": [browser_round(checked)] * 3}
        self.assertEqual(len(probe.fresh_browser_rounds(valid, 3)), 3)
        self.assertIsNone(probe.fresh_browser_rounds(valid, 3, 12345))
        self.assertIsNone(probe.fresh_browser_rounds({**valid, "control": True, "proxy_port": 12345}, 3, 12345))
        self.assertIsNone(probe.fresh_browser_rounds({**valid, "control": False, "proxy_port": 12346}, 3, 12345))
        for bad in ({"qualified": True}, {**valid, "qualified": "true"},
                    {**valid, "rounds": valid["rounds"][:1]},
                    {**valid, "rounds": [{"passed": True, "checked_at": "2020-01-01T00:00:00+00:00"}] * 3},
                    {**valid, "rounds": [{"passed": True, "checked_at": "2026-01-01T00:00:00"}] * 3},
                    {**valid, "rounds": [{"passed": False, "checked_at": checked}] * 3}):
            self.assertIsNone(probe.fresh_browser_rounds(bad, 3))

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
        self.assertIsNone(probe.parse_exit_trace(b"ip=224.0.0.1\nloc=DE\n"))

    def test_exit_ip_echo_requires_exact_https_json_endpoint_and_public_unicast_ip(self):
        for ip in ("8.8.8.8", "2001:4860:4860::8888"):
            self.assertEqual(probe.validate_response("exit-ip", response("exit-ip", body=json.dumps({"ip": ip}).encode())), (True, "ok"))
        for body in (b'{', b'[]', b'{"ip":8}', b'{"ip":"127.0.0.1"}', b'{"ip":"192.168.1.1"}',
                     b'{"ip":"224.0.0.1"}', b'{"ip":"ff02::1"}', b'{"ip":"fe80::1%en0"}',
                     b'{"ip":"8.8.8.8","other":"unexpected"}', b' ' * 1025):
            with self.subTest(body=body[:60]):
                self.assertFalse(probe.validate_response("exit-ip", response("exit-ip", body=body))[0])
        for url in ("http://api64.ipify.org?format=json", "https://api64.ipify.org.evil.test?format=json",
                    "https://api64.ipify.org/other?format=json", "https://api64.ipify.org?format=text",
                    "https://api64.ipify.org?format=json&callback=x", "https://api64.ipify.org?format=json#x"):
            self.assertFalse(probe.validate_response("exit-ip", response("exit-ip", url=url))[0])
        self.assertFalse(probe.validate_response("exit-ip", response("exit-ip", content_type="text/html"))[0])
        self.assertFalse(probe.validate_response("exit-ip", response("exit-ip", status=403))[0])
        self.assertFalse(probe.validate_response("exit-ip", response("exit-ip", cf_mitigated="challenge"))[0])


class ExitMetadataTests(unittest.IsolatedAsyncioTestCase):
    async def test_primary_success_uses_exact_same_candidate_proxy_once(self):
        build = build_stub()
        with patch.object(probe, "_request", AsyncMock(return_value=response("trace"))) as request:
            result = await probe.observe_exit_metadata(build, 12345, "owned-user", "owned-pass")
        request.assert_awaited_once_with(build, "trace", probe.TRACE_URL, 12345, "owned-user", "owned-pass")
        self.assertEqual(result["exit_trace"], {"ip": "8.8.8.8", "loc": "DE"})
        self.assertEqual(result["exit_trace_source"], "cloudflare-trace")
        self.assertEqual(result["exit_geo_attempts"], [{"endpoint": "cloudflare-trace", "reason": "ok", "http_status": 200}])

    async def test_timeout_or_error_uses_one_fallback_with_same_proxy_credentials(self):
        build = build_stub()
        for first in (asyncio.TimeoutError(), {"error": "proxy-request-timeout"}, response("trace", body=b"not a trace")):
            with self.subTest(first=type(first).__name__), \
                    patch.object(probe, "_request", AsyncMock(side_effect=[first, response("exit-ip")])) as request:
                result = await probe.observe_exit_metadata(build, 12345, "owned-user", "owned-pass")
            self.assertEqual(result["exit_trace"], {"ip": "8.8.8.8", "loc": ""})
            self.assertEqual(result["exit_trace_source"], "ipify-exit-ip")
            self.assertEqual(request.await_count, 2)
            self.assertEqual([call.args[3:] for call in request.await_args_list], [(12345, "owned-user", "owned-pass")] * 2)
            self.assertEqual(request.await_args_list[1].args[1:3], ("exit-ip", probe.EXIT_IP_URL))

    async def test_metadata_timeout_bound_cancels_each_request_and_limits_attempts(self):
        cancelled = 0
        async def never_finishes(*args):
            nonlocal cancelled
            try:
                await asyncio.Event().wait()
            finally:
                cancelled += 1
        self.assertLessEqual(probe.EXIT_METADATA_TIMEOUT, 4)
        with patch.object(probe, "EXIT_METADATA_TIMEOUT", .01), \
                patch.object(probe, "_request", AsyncMock(side_effect=never_finishes)) as request:
            result = await asyncio.wait_for(probe.observe_exit_metadata(None, 12345, "user", "pass"), .5)
        self.assertEqual(request.await_count, 2)
        self.assertEqual(cancelled, 2)
        self.assertIsNone(result["exit_trace"])
        self.assertEqual(result["exit_trace_reason"], "proxy-request-timeout")

    async def test_external_cancellation_propagates_without_retry(self):
        started = asyncio.Event()
        async def request(*args):
            started.set()
            await asyncio.Event().wait()
        with patch.object(probe, "_request", AsyncMock(side_effect=request)) as mocked:
            task = asyncio.create_task(probe.observe_exit_metadata(None, 12345, "user", "pass"))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        mocked.assert_awaited_once()

    async def test_metadata_deadlines_reap_both_owned_curl_children(self):
        build = build_stub()
        children = [SimpleNamespace(stdout=asyncio.StreamReader(), stderr=None, returncode=None,
                                    wait=AsyncMock()) for _ in range(2)]
        with patch.object(probe, "EXIT_METADATA_TIMEOUT", .01), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(side_effect=children)) as launch:
            result = await asyncio.wait_for(probe.observe_exit_metadata(build, 12345, "owned-user", "owned-pass"), .5)
        self.assertEqual(launch.await_count, 2)
        self.assertEqual([call.args[0] for call in build._stop_owned_probe_process.await_args_list], children)
        self.assertEqual([call.args[0] for call in build._register_owned_probe_process.call_args_list], children)
        for call in launch.await_args_list:
            command = call.args
            self.assertEqual(command[command.index("--proxy") + 1], "socks5h://127.0.0.1:12345")
            self.assertEqual(command[command.index("--proxy-user") + 1], "owned-user:owned-pass")
        self.assertIsNone(result["exit_trace"])
        self.assertEqual(result["exit_trace_reason"], "proxy-request-timeout")

    async def test_failed_metadata_keeps_qualification_and_safe_attempt_diagnostics(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service) if service in probe.SERVICE_URLS or service == "latency" else {"error": "private-user-password"}
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)):
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertTrue(result["qualified"])
        self.assertEqual(result["rejection_reasons"], [])
        self.assertIsNone(result["exit_trace"])
        self.assertEqual(len(result["exit_geo_attempts"]), 2)
        self.assertEqual(result["exit_trace_reason"], "exit-metadata-request-failed")
        self.assertNotIn("private-user-password", json.dumps(result["exit_geo_attempts"]))

    async def test_metadata_redirects_do_not_add_requests_or_follow_another_host(self):
        for service, url in (("trace", probe.TRACE_URL), ("exit-ip", probe.EXIT_IP_URL)):
            with patch.object(probe, "_http_once", AsyncMock(return_value=response(service, status=302, location="https://example.com/"))) as request:
                result = await probe._request(None, service, url, 12345, "user", "pass")
            request.assert_awaited_once()
            self.assertFalse(probe.validate_response(service, result)[0])


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
        self.assertEqual(config["inbounds"][0]["type"], "mixed")
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
    async def test_second_public_address_recovers_transport_after_first_process_cleanup(self):
        build = build_stub()
        children = [SimpleNamespace(returncode=None), SimpleNamespace(returncode=None)]
        started = 0
        async def create(*args, **kwargs):
            nonlocal started
            if started:
                build._stop_owned_probe_process.assert_awaited_once_with(children[0])
            child = children[started]
            started += 1
            return child
        async def request(_build, service, *args):
            return {"error": "socks-connection-failed", "curl_exit": 97} if started == 1 else response(service)
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8", "9.9.9.9"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(side_effect=create)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)):
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertTrue(result["qualified"])
        self.assertEqual(result["attempted_address_count"], 2)
        self.assertEqual([item["https_response"] for item in result["endpoint_attempts"]], [False, True])
        self.assertEqual([call.args[0] for call in build._stop_owned_probe_process.await_args_list], children)
        self.assertNotIn("8.8.8.8", json.dumps(result["endpoint_attempts"]))
        self.assertNotIn("9.9.9.9", json.dumps(result["endpoint_attempts"]))

    async def test_cloudflare_http_response_does_not_rotate_public_addresses(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return (response(service, status=403, cf_mitigated="challenge") if service == "chatgpt"
                    else {"error": "proxy-request-timeout"})
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8", "9.9.9.9"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)) as create, \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)):
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["attempted_address_count"], 1)
        self.assertTrue(result["endpoint_attempts"][0]["https_response"])
        create.assert_awaited_once()

    async def test_address_retry_is_bounded_to_two(self):
        failed = probe.empty_report(LINK)
        failed["rejection_reasons"] = ["proxy-start-or-network-failure"]
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8", "9.9.9.9", "1.1.1.1"])), \
                patch.object(probe, "_validate_address", AsyncMock(return_value=failed)) as validate:
            result = await probe._validate_one(build_stub(), LINK, 3, "en0")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["attempted_address_count"], 2)
        self.assertEqual(validate.await_count, 2)

    async def test_cancellation_during_second_address_reaps_both_owned_processes(self):
        build = build_stub()
        children = [SimpleNamespace(returncode=None), SimpleNamespace(returncode=None)]
        ready = asyncio.Event()
        async def wait_start(port, username, password, process):
            if process is children[1]:
                build._stop_owned_probe_process.assert_awaited_once_with(children[0])
                ready.set()
                await asyncio.Event().wait()
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8", "9.9.9.9"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(side_effect=children)), \
                patch.object(probe, "_wait_authenticated", side_effect=wait_start), \
                patch.object(probe, "_request", AsyncMock(return_value={"error": "socks-connection-failed"})):
            task = asyncio.create_task(probe._validate_one(build, LINK, 3, "en0"))
            await ready.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(all(any(call.args == (child,) for call in build._stop_owned_probe_process.await_args_list)
                            for child in children))

    async def test_all_public_addresses_remain_available_for_retry(self):
        infos = [(2, 1, 6, "", ("9.9.9.9", 443)), (2, 1, 6, "", ("8.8.8.8", 443)),
                 (2, 1, 6, "", ("9.9.9.9", 443))]
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=infos)):
            self.assertEqual(await probe._resolve_public_servers("example.com", 443), ["8.8.8.8", "9.9.9.9"])

    async def test_stderr_is_bounded_and_only_classified_counts_survive(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"secret-password authentication failed\n" * 10000)
        reader.feed_eof()
        counters = Counter()
        await probe.drain_error_classes(reader, counters)
        self.assertIn("protocol-authentication-failed", counters)
        self.assertEqual(counters["diagnostic-output-truncated"], 1)
        self.assertNotIn("secret-password", json.dumps(counters))
        self.assertTrue(all(0 < count <= 999 for count in counters.values()))

    async def test_browser_proof_rescues_only_challenged_chatgpt_rounds(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        checked = datetime.now(timezone.utc).isoformat()
        browser = {"qualified": True, "rounds": [browser_round(checked)] * 3}
        async def browser_check(_build, port, *args):
            return {**browser, "proxy_port": port, "control": False}
        async def request(_build, service, *args):
            return response(service, **({"status": 403, "cf_mitigated": "challenge"} if service == "chatgpt" else {}))
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                patch.object(probe, "check_chatgpt", AsyncMock(side_effect=browser_check)) as fallback:
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertTrue(result["qualified"])
        fallback.assert_awaited_once()
        self.assertEqual(fallback.await_args.args[-1], 3)
        self.assertTrue(all(item["http_status"] == 403 and item["cf_challenge"] for item in result["services"]["chatgpt"]["evidence"]))
        self.assertTrue(all(item["http_reason"] == "cloudflare-challenge-inconclusive" and item["browser"]["passed"] is True
                            for item in result["services"]["chatgpt"]["evidence"]))
        self.assertEqual(result["services"]["chatgpt"]["passed"], 3)

    async def test_incomplete_browser_proof_never_passes(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service, **({"status": 403, "cf_mitigated": "challenge"} if service == "chatgpt" else {}))
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                patch.object(probe, "check_chatgpt", AsyncMock(return_value={"qualified": True})):
            result = await probe._validate_one(build, LINK, 3, "en0")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["services"]["chatgpt"]["passed"], 0)

    async def test_browser_is_not_attempted_for_bad_other_service_or_latency_or_geography(self):
        for changes in ({"youtube": {"status": 403}}, {"latency": {"status": 200}},
                        {"latency": {"latency_ms": float("nan")}},
                        {"chatgpt": {"status": 403, "body": b"unsupported_country_region_territory"}},
                        {"chatgpt": {"status": 429}},
                        {"chatgpt": {"status": 429, "cf_mitigated": "challenge"}}):
            build, child = build_stub(), SimpleNamespace(returncode=None)
            async def request(_build, service, *args):
                delta = {"status": 403} if service == "chatgpt" else {}
                return response(service, **{**delta, **changes.get(service, {})})
            with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                    patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                    patch.object(probe, "_wait_authenticated", AsyncMock()), \
                    patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                    patch.object(probe, "check_chatgpt", AsyncMock()) as fallback:
                result = await probe._validate_one(build, LINK, 3, "en0")
            self.assertFalse(result["qualified"])
            fallback.assert_not_awaited()

    async def test_changed_chatgpt_endpoint_needs_working_browser_proof(self):
        for chatgpt_changes in ({"body": b"{}"}, {"status": 404}, {"status": 401},
                                {"body": b"<html>application</html>", "content_type": "text/html"}):
            for browser_success in (False, True):
                build, child = build_stub(), SimpleNamespace(returncode=None)
                checked = datetime.now(timezone.utc).isoformat()
                async def request(_build, service, *args):
                    return response(service, **(chatgpt_changes if service == "chatgpt" else {}))
                async def browser(_build, port, *args):
                    return ({"qualified": True, "rounds": [browser_round(checked)] * 5,
                             "proxy_port": port, "control": False} if browser_success else
                            {"qualified": False, "rounds": [{"passed": False, "reason": "browser-api-proof-missing",
                             "http_status": 200, "composer": True, "application_json": False}]})
                with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                        patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                        patch.object(probe, "_wait_authenticated", AsyncMock()), \
                        patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                        patch.object(probe, "check_chatgpt", AsyncMock(side_effect=browser)) as fallback:
                    result = await probe._validate_one(build, LINK, 5, "en0")
                fallback.assert_awaited_once()
                self.assertEqual(result["qualified"], browser_success)
                if browser_success:
                    self.assertTrue(all(item["http_reason"].endswith("inconclusive")
                                        for item in result["services"]["chatgpt"]["evidence"]))
                    self.assertEqual(result["services"]["chatgpt"]["passed"], 5)
                else:
                    self.assertEqual(result["services"]["chatgpt"]["passed"], 0)
                    self.assertEqual(result["browser_check"]["reason"], "browser-api-proof-missing")
                    self.assertEqual(result["browser_check"]["first_failed_http_status"], 200)

    async def test_browser_first_sample_outlier_uses_strict_final_median(self):
        for samples in ([700, 100, 110, 120, 130], [500, 100, 110, 120, 130], [500] * 5):
            build, child = build_stub(), SimpleNamespace(returncode=None)
            checked = datetime.now(timezone.utc).isoformat()
            sequence = iter(samples)
            async def request(_build, service, *args):
                changes = {"status": 403, "cf_mitigated": "challenge"} if service == "chatgpt" else {}
                if service == "latency":
                    changes["latency_ms"] = next(sequence)
                return response(service, **changes)
            async def browser(_build, port, *args):
                return {"qualified": True, "rounds": [browser_round(checked)] * 5,
                        "proxy_port": port, "control": False}
            with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
                    patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                    patch.object(probe, "_wait_authenticated", AsyncMock()), \
                    patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                    patch.object(probe, "check_chatgpt", AsyncMock(side_effect=browser)) as fallback:
                result = await probe._validate_one(build, LINK, 5, "en0")
            fallback.assert_awaited_once()
            self.assertEqual(result["latency_samples_ms"], samples)
            self.assertEqual(result["qualified"], samples != [500] * 5)
            self.assertEqual(result["median_ms"], 500 if samples == [500] * 5 else 120)

    async def test_browser_queue_deadline_preserves_http_proofs_and_is_inconclusive(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service, **({"status": 403, "cf_mitigated": "challenge"} if service == "chatgpt" else {}))
        async def queued(*args):
            await asyncio.Event().wait()
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8", "9.9.9.9"])), \
                patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                patch.object(probe, "_wait_authenticated", AsyncMock()), \
                patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                patch.object(probe, "check_chatgpt", AsyncMock(side_effect=queued)), \
                patch.object(probe, "MAX_CANDIDATE_SECONDS", 0.03):
            result = await probe._validate_one(build, LINK, 5, "en0")
        self.assertFalse(result["qualified"])
        self.assertEqual(result["validation_outcome"], "inconclusive")
        self.assertIn("browser-queue-or-runtime-deadline-inconclusive", result["rejection_reasons"])
        self.assertEqual(result["services"]["youtube"]["passed"], 1)
        self.assertEqual(result["services"]["instagram"]["passed"], 1)
        self.assertTrue(result["services"]["chatgpt"]["evidence"][0]["cf_challenge"])
        self.assertEqual(result["latency_samples_ms"], [150.0])
        self.assertEqual(result["attempted_address_count"], 1)
        self.assertTrue(result["endpoint_attempts"][0]["https_response"])
        build._stop_owned_probe_process.assert_awaited_once_with(child)

    async def test_browser_adapter_errors_are_inconclusive(self):
        # Missing/browser dependency errors never become a successful proof.
        with patch.dict("sys.modules", {"browser_probe": SimpleNamespace(check_chatgpt=AsyncMock(side_effect=RuntimeError("secret")))}):
            result = await probe.check_chatgpt(build_stub(), 12345, "user", "secret", 3)
        self.assertFalse(result["qualified"])
        self.assertNotIn("secret", json.dumps(result))

    async def test_public_dual_stack_prefers_physical_ipv4_path(self):
        loop = asyncio.get_running_loop()
        infos = [(10, 1, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
                 (2, 1, 6, "", ("91.198.174.192", 443))]
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=infos)):
            self.assertEqual(await probe._resolve_public_server("example.com", 443), "91.198.174.192")

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
            self.assertEqual(result["error"], "service-redirect-restriction-inconclusive")
            self.assertEqual(result["status"], 302)
            self.assertEqual(probe.service_evidence("chatgpt", result)["outcome"], "inconclusive")
            self.assertEqual(request.await_count, 1)

    async def test_full_candidate_success_and_same_proxy_trace(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return response(service)
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
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
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
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
        with patch.object(probe, "_resolve_public_servers", AsyncMock(return_value=["8.8.8.8"])), \
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
        with self.assertRaises(ValueError):
            await probe.validate_candidates(None, ["unused"] * 151)

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
