import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import AsyncMock, patch

from scripts import source_discovery as discovery

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pipeline_recovery_build", ROOT / "scripts/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
NOW = 2_000_000_000
UUID = "11111111-1111-4111-8111-111111111111"
LINK = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com"
SEED = "https://raw.githubusercontent.com/public/feed/main/config.txt"


class SourceRecoveryTests(unittest.TestCase):
    def test_malformed_cached_types_recover_with_configured_seeds(self):
        cases = [[], None, {"sources": {"x": 1}}, {"sources": {}, "repositories": []},
                 {"sources": {}, "last_discovery": "corrupt"},
                 {"sources": {}, "api_retry_at": float("nan")},
                 {"sources": {"x": {"url": SEED, "origin": [], "failures": float("inf")}}},
                 {"sources": {"x": {"url": SEED, "functional_ema": 10 ** 1000}}}]
        for state in cases:
            with self.subTest(state_type=type(state).__name__), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.json"
                path.write_text(json.dumps(state))
                pool = discovery.SourcePool([{"url": SEED}], path, now=NOW)
                pool.state["last_discovery"] = NOW
                with patch.object(pool, "get", return_value=(LINK.encode(), {})):
                    links, _ = pool.collect()
                self.assertEqual(links, [LINK])
                self.assertEqual(next(iter(pool.sources.values()))["origin"], "seed")
                self.assertEqual(json.loads(path.read_text())["version"], 1)

    def test_nested_corrupt_json_resets_without_poisoning_next_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("[" * 2000 + "]" * 2000)
            pool = discovery.SourcePool([{"url": SEED}], path, now=NOW)
            pool.save()
            self.assertEqual(len(discovery.SourcePool([{"url": SEED}], path, now=NOW).sources), 1)

    def test_valid_metadata_is_preserved_and_records_are_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            sources = {str(i): {"url": f"https://example.com/sub-{i}.txt", "origin": "public-feed-link",
                                "first_seen": NOW - 100, "last_fetch": NOW - 20,
                                "failures": 3, "functional_ema": .6, "next_fetch": NOW + 100}
                       for i in range(discovery.MAX_SOURCES + 10)}
            path.write_text(json.dumps({"version": 1, "sources": sources,
                                        "repositories": {f"owner/repo-{i}": NOW - i for i in range(220)},
                                        "last_qualified": 49, "discovery_round": 8}))
            pool = discovery.SourcePool([{"url": SEED}], path, now=NOW)
            self.assertEqual(len(pool.sources), discovery.MAX_SOURCES)
            self.assertEqual(len(pool.state["repositories"]), 200)
            self.assertEqual(pool.state["last_qualified"], 49)
            self.assertEqual(pool.state["discovery_round"], 8)
            item = next(item for item in pool.sources.values() if item["origin"] != "seed")
            self.assertEqual((item["failures"], item["functional_ema"], item["next_fetch"]), (3, .6, NOW + 100))
            self.assertIn(SEED, [item["url"] for item in pool.sources.values()])

    def test_request_budget_defers_without_marking_any_feed_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": SEED}, {"url": SEED.replace("config.txt", "second.txt")}],
                                        Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            pool.requests = 110
            links, _ = pool.collect()
            self.assertEqual(links, [])
            self.assertEqual(pool.stats["source_failures"], 0)
            self.assertEqual(pool.stats["deferred_sources"], 2)
            self.assertTrue(all(item["failures"] == 0 and item["last_fetch"] == 0 for item in pool.sources.values()))

    def test_policy_wait_budget_defers_one_source_and_continues_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": SEED}, {"url": SEED.replace("config.txt", "second.txt")}],
                                        Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            with patch.object(pool, "get", side_effect=[discovery.SourceBudgetExhausted(False), (LINK.encode(), {})]):
                links, _ = pool.collect()
            self.assertEqual(links, [LINK])
            self.assertEqual(pool.stats["source_failures"], 0)
            self.assertEqual(pool.stats["deferred_sources"], 1)
            self.assertTrue(all(item["failures"] == 0 for item in pool.sources.values()))

    def test_budget_during_robots_lookup_is_not_converted_to_source_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": "https://example.com/subscription.txt"}], Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            with patch.object(pool, "get", side_effect=discovery.SourceBudgetExhausted()):
                pool.collect()
            self.assertEqual(pool.stats["source_failures"], 0)
            self.assertEqual(next(iter(pool.sources.values()))["failures"], 0)

    def test_actual_rate_limit_still_sets_failure_backoff(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": SEED}], Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            with patch.object(pool, "get", side_effect=discovery.RateLimited(NOW + 3600)):
                pool.collect()
            item = next(iter(pool.sources.values()))
            self.assertEqual(item["failures"], 1)
            self.assertEqual(item["next_fetch"], NOW + 3600)

    def test_transient_robots_policy_is_cached_and_retains_retry_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json", now=NOW)
            with patch.object(pool, "get", side_effect=discovery.RateLimited(NOW + 10 * 3600)) as get:
                for _ in range(2):
                    with self.assertRaises(discovery.SourcePolicyUnavailable) as failure:
                        pool.allowed("https://example.com/subscription.txt")
                    self.assertEqual(failure.exception.retry_at, NOW + 10 * 3600)
            self.assertEqual(get.call_count, 1)

    def test_robots_failure_defers_source_but_explicit_policy_deny_and_404_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": "https://example.com/subscription.txt"}], Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            with patch.object(pool, "get", side_effect=RuntimeError("source HTTP 503")):
                links, _ = pool.collect()
            self.assertEqual(links, [])
            self.assertGreaterEqual(next(iter(pool.sources.values()))["next_fetch"], NOW + 1800)
            self.assertIsInstance(pool.robots["https://example.com"], discovery.SourcePolicyUnavailable)
            for response, expected in ((RuntimeError("source HTTP 404"), True),
                                       ((b"User-agent: *\nDisallow: /\n", {}), False)):
                pool.robots = {}
                arguments = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
                with patch.object(pool, "get", **arguments):
                    self.assertIs(pool.allowed("https://example.com/subscription.txt"), expected)

    def test_source_and_api_retry_deadlines_honor_server_policy_up_to_twenty_four_hours(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([{"url": SEED}], Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            with patch.object(pool, "get", side_effect=discovery.RateLimited(NOW + 10 * 3600)):
                pool.collect()
            self.assertEqual(next(iter(pool.sources.values()))["next_fetch"], NOW + 10 * 3600)
            pool.state["last_discovery"] = 0
            with patch.object(pool, "get", side_effect=discovery.SourcePolicyUnavailable(NOW + 10 * 3600, now=NOW)):
                pool.discover()
            self.assertEqual(pool.state["api_retry_at"], NOW + 10 * 3600)
            self.assertEqual(discovery.SourcePolicyUnavailable(NOW + 100 * 86400, now=NOW).retry_at, NOW + 86400)

    def test_retry_after_delta_and_http_date_formats_are_bounded_and_respected(self):
        future = format_datetime(datetime.fromtimestamp(NOW + 10 * 3600, timezone.utc), usegmt=True)
        self.assertEqual(discovery.rate_limit_retry_at({"retry-after": future}, now=NOW), NOW + 10 * 3600)
        self.assertEqual(discovery.rate_limit_retry_at({"retry-after": "7200"}, now=NOW), NOW + 7200)
        self.assertEqual(discovery.rate_limit_retry_at({"retry-after": "999999999999999"}, now=NOW), NOW + 86400)
        self.assertEqual(discovery.rate_limit_retry_at({"retry-after": future, "x-ratelimit-reset": str(NOW + 12 * 3600)}, now=NOW), NOW + 12 * 3600)
        past = format_datetime(datetime.fromtimestamp(NOW - 3600, timezone.utc), usegmt=True)
        self.assertEqual(discovery.rate_limit_retry_at({"retry-after": past}, now=NOW), NOW + 60)
        for value in ("invalid", "-10", "0" * 200, [], "Fri, 1 Jan 2038 00:00:00"):
            self.assertEqual(discovery.rate_limit_retry_at({"retry-after": value}, now=NOW), NOW + 3600)

    def test_duplicates_do_not_consume_candidate_budget_and_sources_stay_fair(self):
        with tempfile.TemporaryDirectory() as directory:
            seeds = [{"url": SEED.replace("config.txt", f"source-{i}.txt")} for i in range(3)]
            pool = discovery.SourcePool(seeds, Path(directory) / "state.json", now=NOW)
            pool.state["last_discovery"] = NOW
            first = [f"vless://first-{i}" for i in range(3)]
            second = [f"vless://second-{i}" for i in range(3)]
            def fetch(url, **_kwargs):
                return "\n".join(second if url.endswith("source-2.txt") else first).encode(), {}
            with patch.object(discovery, "MAX_CANDIDATES", 4), patch.object(pool, "get", side_effect=fetch):
                links, _ = pool.collect()
            self.assertEqual(len(links), 4)
            self.assertEqual(len(set(links)), 4)
            self.assertEqual(sum(link in first for link in links), 2)
            self.assertEqual(sum(link in second for link in links), 2)

    def test_retired_catalog_source_is_not_reimported_until_seven_days(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            pool = discovery.SourcePool([], path, now=NOW)
            self.assertTrue(pool.add(SEED, "grok-research"))
            key, item = next(iter(pool.sources.items()))
            item.update(first_seen=NOW - 8 * 86400, empty_runs=3)
            pool.save()
            self.assertNotIn(key, pool.sources)
            self.assertEqual(pool.state["retired_sources"][key], NOW + 7 * 86400)
            restored = discovery.SourcePool([], path, now=NOW + 1)
            self.assertFalse(restored.add(SEED, "grok-research"))
            self.assertFalse(restored.add(SEED, "github-search"))
            restored.save()
            expired = discovery.SourcePool([], path, now=NOW + 7 * 86400 + 1)
            self.assertTrue(expired.add(SEED, "grok-research"))
            self.assertEqual(next(iter(expired.sources.values()))["origin"], "grok-research")

    def test_configured_seed_bypasses_discovered_source_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            key = hashlib.sha256(SEED.encode()).hexdigest()[:24]
            path.write_text(json.dumps({"sources": {}, "retired_sources": {key: NOW + 86400}}))
            pool = discovery.SourcePool([{"url": SEED}], path, now=NOW)
            self.assertIn(key, pool.sources)
            self.assertEqual(pool.sources[key]["origin"], "seed")

    def test_retirement_cache_is_typed_bounded_and_expiring(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            retired = {format(i, "024x"): NOW + 10 ** 100 for i in range(discovery.MAX_RETIRED_SOURCES + 20)}
            retired.update({"malformed-key": NOW + 1, "f" * 24: float("nan"), "e" * 24: "forever", "d" * 24: NOW - 1})
            path.write_text(json.dumps({"sources": {}, "retired_sources": retired}))
            pool = discovery.SourcePool([], path, now=NOW)
            self.assertEqual(len(pool.state["retired_sources"]), discovery.MAX_RETIRED_SOURCES)
            self.assertTrue(all(NOW < until <= NOW + 7 * 86400 for until in pool.state["retired_sources"].values()))


class CanonicalIdentityTests(unittest.TestCase):
    def test_delimiter_collision_cannot_merge_different_grpc_connections(self):
        first = build.parse_vless(LINK + "&type=grpc&path=/a%7C&serviceName=x")
        second = build.parse_vless(LINK + "&type=grpc&path=/a&serviceName=%7Cx")
        self.assertNotEqual(build.vless_to_singbox(first), build.vless_to_singbox(second))
        self.assertNotEqual(build.normalized_fingerprint(first), build.normalized_fingerprint(second))

    def test_ignored_uri_fields_and_none_alias_have_same_actual_identity(self):
        plain = LINK.replace("security=tls", "security=none")
        first = build.parse_vless(plain)
        second = build.parse_vless(plain.replace("security=none", "security=") + "&path=/unused&serviceName=unused#different-label")
        self.assertEqual(build.vless_to_singbox(first), build.vless_to_singbox(second))
        self.assertEqual(build.normalized_fingerprint(first), build.normalized_fingerprint(second))

    def test_identity_hashes_actual_engine_configuration_for_every_protocol(self):
        links = [LINK, "trojan://password@1.1.1.1:443?sni=example.com", "socks://user:password@1.1.1.1:1080"]
        for link in links:
            node = build.parse_vless(link)
            expected = hashlib.sha256(json.dumps(build.vless_to_singbox(node, tag="node"), sort_keys=True).encode()).hexdigest()
            self.assertEqual(build.normalized_fingerprint(node), expected)


class FinalistRecoveryTests(unittest.TestCase):
    def test_unseen_alternatives_enter_final_tests_before_five_hundred_local_rejects(self):
        links = [LINK.replace(":443?", f":{443 + index}?") for index in range(551)]
        nodes = [dict(build.parse_vless(link), country="US", infrastructure=f"infra-{index}", endpoint_family=f"family-{index}")
                 for index, link in enumerate(links)]
        records = {build.normalized_fingerprint(node): {"last_seen": NOW - 60, "qualified": False} for node in nodes[:500]}
        catalog_additions = []
        class Pool:
            def __init__(self, *_args, **_kwargs):
                self.stats = {"fetched_sources": 1}
            def collect(self):
                return links, {"public-source": {"candidates": len(links)}}
            def feedback(self, *_args):
                pass
            def add(self, url, origin):
                catalog_additions.append((url, origin))
                return True
        tested = []
        async def final(candidates):
            tested.extend(candidates)
            return {link: [100.0] * 5 for link in candidates}
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build, "OUT", Path(directory)))
            stack.enter_context(patch.object(build, "SourcePool", Pool))
            stack.enter_context(patch.object(build, "classify_countries_batch", AsyncMock(return_value=nodes)))
            stack.enter_context(patch.object(build, "run_first_pass", AsyncMock(return_value=[(link, float(index + 1)) for index, link in enumerate(links[:550])])))
            stack.enter_context(patch.object(build, "run_final_pass", side_effect=final))
            stack.enter_context(patch.object(build, "load_history", return_value={}))
            stack.enter_context(patch.object(build, "save_history"))
            stack.enter_context(patch.object(build, "now_ts", return_value=NOW))
            stack.enter_context(patch.object(build, "load_regional_feedback", return_value=(records, {"status": "fresh"})))
            stack.enter_context(patch.object(build, "load_regional_sources", return_value=([SEED], {"status": "fresh", "sources": 1})))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(asyncio.run(build.main_async()), 0)
            self.assertEqual(len(tested), 500)
            self.assertEqual(set(tested[:50]), set(links[500:550]))
            self.assertNotIn(links[550], tested)
            published = [line for line in (Path(directory) / "best50.txt").read_text().splitlines() if line and not line.startswith("#")]
            published_ids = {build.normalized_fingerprint(build.parse_vless(link)) for link in published}
            self.assertEqual(published_ids, {build.normalized_fingerprint(node) for node in nodes[500:550]})
            self.assertTrue(all(link.split("#")[0] in tested for link in published))
            status = json.loads((Path(directory) / "status.json").read_text())
            self.assertEqual(status["finalist_local_feedback"]["rejected"], 500)
            self.assertEqual(catalog_additions, [(SEED, "grok-research")])
            self.assertEqual(status["source_catalog"], {"status": "fresh", "sources": 1})


if __name__ == "__main__":
    unittest.main()
