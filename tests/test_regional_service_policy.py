"""Policy extension regressions; simulations never assert live server access."""
import copy
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from test_service_probe import probe, response, build_stub, browser_round, LINK


def spotify(**changes):
    body = (b'<html><link rel="canonical" href="https://www.spotify.com/rs-sr/">'
            b'<script src="https://www.spotify.com/static/app.js"></script>'
            b'<script id="__NEXT_DATA__" type="application/json">{}</script>'
            + b' ' * 1100 + b'</html>')
    return {"url": probe.SPOTIFY_URL, "status": 200, "body": body,
            "content_type": "text/html", "latency_ms": 120, **changes}


def geo():
    return {"country": "RS", "checked_at": datetime.now(timezone.utc).isoformat(),
            "observations": [{"source": source, "ip": "8.8.8.8", "country": "RS"}
                             for source in ("cloudflare-trace", "country-is", "cloudflare-trace")]}


class PolicyResponses(unittest.TestCase):
    def test_observed_wrong_country_is_definitive_but_unknown_country_is_not(self):
        from local_feedback import classify_diagnostic
        self.assertEqual(classify_diagnostic({"qualified": False,
            "rejection_reasons": ["observed-exit-country-mismatch"]}), "fail")
        self.assertEqual(classify_diagnostic({"qualified": False,
            "rejection_reasons": ["required-exit-country-unconfirmed-inconclusive"]}), "inconclusive")

    def test_spotify_requires_application_not_generic_http_200(self):
        self.assertEqual(probe.validate_response("spotify", spotify()), (True, "ok"))
        player = spotify(url="https://open.spotify.com/", body=(
            b'<link rel="canonical" href="https://open.spotify.com">'
            b'<script src="https://open.spotifycdn.com/cdn/build/web-player/app.js"></script>'
            b'<script id="appServerConfig">{}</script><script id="initialState">{}</script>'
            b'<script id="__CDN_FILE_URLS__">{}</script>' + b' ' * 1200))
        self.assertEqual(probe.validate_response("spotify", player), (True, "ok"))
        for changes in ({"body": b"Spotify" * 300}, {"status": 302},
                        {"url": "https://www.spotify.com/us/error"},
                        {"url": "https://example.org/"}, {"content_type": "text/plain"},
                        {"body": spotify()["body"] + b"<h1>Not available in your country</h1>"},
                        {"body": spotify()["body"] + b"<h1>Verify you are human</h1>"},
                        {"status": 429}):
            with self.subTest(fields=list(changes)):
                self.assertFalse(probe.validate_response("spotify", spotify(**changes))[0])

    def test_geo_proof_is_actual_public_egress_and_independent_current_quorum(self):
        proof = geo()
        self.assertTrue(probe.valid_exit_country_evidence(proof))
        ipv6 = copy.deepcopy(proof)
        ipv6["observations"][1]["ip"] = "2001:4860:4860::8888"
        self.assertTrue(probe.valid_exit_country_evidence(ipv6))
        altered = []
        for key, value in (("country", "DE"), ("observations", proof["observations"][:1]),
                           ("checked_at", (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()),
                           ("checked_at", (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()),
                           ("checked_at", "2026-11-09T01:00:00")):
            altered.append({**proof, key: value})
        for field, value in (("ip", "127.0.0.1"), ("country", "DE"), ("source", "source-label")):
            bad = copy.deepcopy(proof); bad["observations"][1][field] = value; altered.append(bad)
        for bad in altered + [None, {}, {"country": "RS", "ip": "8.8.8.8"}]:
            self.assertFalse(probe.valid_exit_country_evidence(bad))

    def test_country_endpoint_parses_only_public_ip_and_iso_country(self):
        self.assertEqual(probe.parse_exit_country(b'{"ip":"8.8.8.8","country":"RS"}'),
                         {"ip": "8.8.8.8", "loc": "RS"})
        for body in (b'{}', b'null', b'{"ip":"10.0.0.1","country":"RS"}',
                     b'{"ip":"8.8.8.8","country":"ZZ"}', b'<' * 4097):
            self.assertIsNone(probe.parse_exit_country(body))


class FourServicePath(unittest.IsolatedAsyncioTestCase):
    async def test_fourth_service_never_becomes_latency_or_bypasses_geo(self):
        build, child = build_stub(), SimpleNamespace(returncode=None)
        async def request(_build, service, *args):
            return spotify() if service == "spotify" else response(service)
        async def browser(_build, port, _user, _password, rounds):
            return {"qualified": True, "control": False, "proxy_port": port,
                    "rounds": [browser_round(datetime.now(timezone.utc).isoformat()) for _ in range(rounds)]}
        for proof, expected in ((geo(), True), (None, False)):
            with patch.object(probe.asyncio, "create_subprocess_exec", AsyncMock(return_value=child)), \
                    patch.object(probe, "_wait_authenticated", AsyncMock()), \
                    patch.object(probe, "_request", AsyncMock(side_effect=request)), \
                    patch.object(probe, "check_chatgpt", AsyncMock(side_effect=browser)), \
                    patch.object(probe, "observe_required_exit_country", AsyncMock(return_value=proof)):
                result = await probe._validate_address(build, LINK, 3, "en0", "8.8.8.8",
                    required_services=tuple(probe.ALL_SERVICE_URLS), required_exit_country="RS")
            self.assertEqual(result["qualified"], expected)
            self.assertEqual(result["median_ms"], 150 if expected else None)
            self.assertEqual(result["services"]["spotify"]["passed"], 3 if expected else 0)
            self.assertEqual(result["tested_server_ip"], "8.8.8.8")

    async def test_geo_observations_use_same_owned_proxy_and_fail_on_disagreement(self):
        def result(service, country="RS"):
            if service == "trace":
                return response("trace", body=f"ip=8.8.8.8\nloc={country}\n".encode())
            return {"url": probe.EXIT_COUNTRY_URL, "status": 200, "content_type": "application/json",
                    "body": json.dumps({"ip": "8.8.8.8", "country": country}).encode()}
        for country, expected in (("RS", True), ("DE", False)):
            with patch.object(probe, "_request", AsyncMock(side_effect=[result("trace"), result("exit-country", country), result("trace")])) as req:
                value = await probe.observe_required_exit_country(None, 12345, "owned-user", "owned-pass", "RS")
            self.assertEqual(probe.valid_exit_country_evidence(value), expected)
            self.assertTrue(all(call.args[3:] == (12345, "owned-user", "owned-pass") for call in req.await_args_list))

    async def test_incomplete_service_policy_cannot_remove_existing_requirements(self):
        for names in (("spotify",), ("chatgpt", "youtube"), ("youtube", "instagram", "spotify")):
            with self.assertRaises(ValueError):
                await probe.validate_candidates(None, [], required_services=names)
