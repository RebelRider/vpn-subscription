"""Adapter-selection regressions; no real browser, compiler or network is used."""
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_probe
import service_probe


PORT = 23456


def native_evidence(rounds=5, **changes):
    value = {
        "available": True,
        "qualified": True,
        "control": False,
        "proxy_port": PORT,
        "rounds": [
            {"passed": True, "reason": "ok", "checked_at": datetime.now(timezone.utc).isoformat(),
             "http_status": 200, "composer": True, "actionable": True,
             "restriction_free": True, "application_json": True,
             "api_kind": "chatgpt-model-catalog"}
            for _ in range(rounds)
        ],
    }
    value.update(changes)
    return value


class NativeAdapterIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, value, *, platform="darwin", **options):
        """Even an unexpected fallback cannot start a real browser."""
        module = ModuleType("native_webkit_probe")
        module.check_chatgpt = AsyncMock(return_value=value)
        build = SimpleNamespace()
        with patch.dict(sys.modules, {"native_webkit_probe": module}), \
                patch.object(browser_probe.sys, "platform", platform), \
                patch.object(browser_probe, "find_node", return_value=None) as find_node:
            result = await browser_probe.check_chatgpt(
                build, PORT, "owned-user", "owned-password", rounds=5,
                prefer_native=True, **options,
            )
        return result, module.check_chatgpt, find_node, build

    async def test_complete_native_proof_qualifies_without_chromium(self):
        result, native, chromium, build = await self.invoke(native_evidence())
        self.assertTrue(result["qualified"])
        self.assertEqual(len(result["rounds"]), 5)
        self.assertEqual(result["proxy_port"], PORT)
        self.assertIs(result["control"], False)
        native.assert_awaited_once_with(build, PORT, "owned-user", "owned-password", rounds=5, control=False)
        chromium.assert_not_called()

    async def test_incomplete_or_invalid_positive_proof_fails_closed(self):
        cases = [native_evidence(rounds=4)]
        for field in ("composer", "actionable", "application_json", "restriction_free", "http_status", "api_kind"):
            value = native_evidence()
            value["rounds"][0].pop(field)
            cases.append(value)
        for value in cases:
            with self.subTest(missing=value["rounds"][0]):
                result, native, chromium, _ = await self.invoke(value)
                self.assertFalse(result["qualified"])
                native.assert_awaited_once()
                chromium.assert_not_called()

    async def test_challenge_remains_inconclusive_without_chromium_retry(self):
        value = native_evidence(qualified=False)
        value["rounds"] = [{"passed": False, "reason": "cloudflare-challenge-inconclusive",
                            "checked_at": datetime.now(timezone.utc).isoformat(),
                            "http_status": 403, "restriction_free": False}]
        result, native, chromium, _ = await self.invoke(value)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["rounds"][0]["reason"], "cloudflare-challenge-inconclusive")
        native.assert_awaited_once()
        chromium.assert_not_called()

    async def test_missing_application_proof_does_not_fall_back(self):
        result, native, chromium, _ = await self.invoke(native_evidence(qualified=False, rounds=0))
        self.assertFalse(result["qualified"])
        native.assert_awaited_once()
        chromium.assert_not_called()

    async def test_malformed_native_result_does_not_trigger_an_engine_retry(self):
        for value in (None, [], {"available": 0, "qualified": True, "rounds": []}):
            with self.subTest(value=value):
                result, _, chromium, _ = await self.invoke(value)
                self.assertFalse(result["qualified"])
                chromium.assert_not_called()

    async def test_existing_direct_calls_keep_headless_default(self):
        module = ModuleType("native_webkit_probe")
        module.check_chatgpt = AsyncMock()
        with patch.dict(sys.modules, {"native_webkit_probe": module}), \
                patch.object(browser_probe.sys, "platform", "darwin"), \
                patch.object(browser_probe, "find_node", return_value=None) as chromium:
            result = await browser_probe.check_chatgpt(SimpleNamespace(), PORT, "user", "password")
        self.assertFalse(result["qualified"])
        module.check_chatgpt.assert_not_awaited()
        chromium.assert_called_once()

    async def test_only_explicit_unavailability_falls_back(self):
        result, native, chromium, _ = await self.invoke(
            {"available": False, "qualified": False, "rounds": [], "reason": "browser-runtime-unavailable"}
        )
        self.assertFalse(result["qualified"])
        self.assertEqual(result["reason"], "browser-runtime-unavailable")
        native.assert_awaited_once()
        chromium.assert_called_once()

    async def test_non_macos_does_not_invoke_native(self):
        result, native, chromium, _ = await self.invoke(native_evidence(), platform="linux")
        self.assertFalse(result["qualified"])
        native.assert_not_awaited()
        chromium.assert_called_once()

    async def test_native_candidate_proof_cannot_be_rebound_from_another_route(self):
        for changes in ({"proxy_port": PORT + 1}, {"control": True}, {"proxy_port": None}, {"control": None}):
            with self.subTest(changes=changes):
                result, _, chromium, _ = await self.invoke(native_evidence(**changes))
                self.assertFalse(result["qualified"])
                chromium.assert_not_called()

    async def test_visible_browser_refusal_precedes_native_selection(self):
        native = AsyncMock()
        module = ModuleType("native_webkit_probe")
        module.check_chatgpt = native
        with patch.dict(sys.modules, {"native_webkit_probe": module}), \
                patch.object(browser_probe.sys, "platform", "darwin"), \
                patch.object(browser_probe, "find_node") as chromium:
            with self.assertRaises(ValueError):
                await browser_probe.check_chatgpt(SimpleNamespace(), PORT, "user", "password",
                                                   prefer_native=True, headless=False)
        native.assert_not_awaited()
        chromium.assert_not_called()

    async def test_proxy_authentication_and_port_validation_precede_native_selection(self):
        native = AsyncMock()
        module = ModuleType("native_webkit_probe")
        module.check_chatgpt = native
        with patch.dict(sys.modules, {"native_webkit_probe": module}), \
                patch.object(browser_probe.sys, "platform", "darwin"), \
                patch.object(browser_probe, "find_node") as chromium:
            result = await browser_probe.check_chatgpt(SimpleNamespace(), PORT, "user", "", prefer_native=True)
            self.assertFalse(result["qualified"])
            self.assertEqual(result["reason"], "browser-proxy-authentication-missing")
            with self.assertRaises(ValueError):
                await browser_probe.check_chatgpt(SimpleNamespace(), 80, "user", "password", prefer_native=True)
        native.assert_not_awaited()
        chromium.assert_not_called()


class NativeServiceSelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_service_flag_requires_literal_true(self):
        for flag in (True, False, 1, "true", None, Mock()):
            build = SimpleNamespace(_local_native_webkit=flag)
            with self.subTest(flag=flag), \
                    patch.object(browser_probe, "check_chatgpt", new_callable=AsyncMock,
                                 return_value={"qualified": False}) as check:
                result = await service_probe.check_chatgpt(build, PORT, "user", "password", 5)
                self.assertFalse(result["qualified"])
                check.assert_awaited_once_with(build, PORT, "user", "password", rounds=5,
                                              control=False, prefer_native=flag is True)

    async def test_unmarked_fake_build_keeps_existing_headless_adapter(self):
        build = SimpleNamespace()
        with patch.object(browser_probe, "check_chatgpt", new_callable=AsyncMock,
                          return_value={"qualified": False}) as check:
            await service_probe.check_chatgpt(build, PORT, "user", "password", 5)
            check.assert_awaited_once_with(build, PORT, "user", "password", rounds=5,
                                          control=False, prefer_native=False)


if __name__ == "__main__":
    unittest.main()
