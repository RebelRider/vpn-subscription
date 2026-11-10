"""Controlled public-input tools: no actual network, inference or VPN processes."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import qwen_discovery_tools as tools

NOW = 1794300000.0
FEED = "https://raw.githubusercontent.com/example/public/main/servers.txt"
LINK = "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com#Serbia"
HY = "hy2://published-public@8.8.8.8:443?sni=example.com#RS"
SS = "ss://YWVzLTEyOC1nY206cHVibGlj@8.8.4.4:8388#RS"


class Pool:
    def __init__(self, responses=None, allowed=True):
        self.responses = responses or {}; self.permitted = allowed; self.calls = []
    def allowed(self, url):
        return self.permitted
    def get(self, url, **kwargs):
        self.calls.append(url)
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result, {}


class DiscoveryToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def worker(self, pool=None, **kwargs):
        return tools.DiscoveryTools(self.path, self.path / "state", now=NOW, pool=pool or Pool(), **kwargs)

    def test_successful_empty_natural_query_broadens_without_bypassing_outage(self):
        from urllib.parse import urlsplit, parse_qs
        class SearchPool(Pool):
            def get(self, url, **kwargs):
                self.calls.append(url)
                if urlsplit(url).hostname != "api.github.com":
                    raise OSError("web unavailable")
                query = parse_qs(urlsplit(url).query)["q"][0]
                matches = ([{"private": False, "full_name": "example/public", "description": "public proxy feeds"}]
                           if query.startswith("Serbia vless in:") else [])
                return json.dumps({"items": matches}).encode(), {}
        pool = SearchPool()
        result = self.worker(pool).execute({"action": "search", "query": "Serbia public proxy subscription VLESS hysteria2"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["results"][0]["url"], "https://github.com/example/public")
        self.assertEqual(len([url for url in pool.calls if urlsplit(url).hostname == "api.github.com"]), 2)

    def test_exact_actions_reject_model_paths_code_and_invented_configurations(self):
        worker = self.worker()
        for action in ({"action": "shell", "command": "echo unsafe"}, {"action": "finish", "sources": [FEED]},
                       {"action": "fetch", "url": FEED, "path": ".github/workflows/build.yml"},
                       {"action": "search", "query": LINK}, {"action": "search", "query": "bad\nquery"},
                       {"action": "search", "query": ""}, {"action": "fetch", "url": "http://example.com/x"}):
            with self.subTest(action=action), self.assertRaises(ValueError):
                worker.execute(action)
        self.assertEqual(worker.execute({"action": "finish"})["candidate_count"], 0)
        self.assertFalse(worker.public_metadata()["candidates"])

    def test_actual_extraction_is_protocol_agnostic_deduplicated_and_private(self):
        raw = (LINK + "\n" + LINK.replace("#Serbia", "#another") + "\n" + HY + "\n" + SS + "\n"
               + LINK.replace("1.1.1.1", "127.0.0.1") + "\nvless://malformed").encode()
        worker = self.worker(Pool({FEED: raw}))
        result = worker.execute({"action": "fetch", "url": FEED})
        self.assertEqual(result["candidate_count"], 3)
        self.assertEqual(set(result["protocols"]), {"vless", "hysteria2", "shadowsocks"})
        self.assertTrue(result["serbia_hint_unverified"])
        public = worker.public_metadata(); serialized = json.dumps(public)
        for secret in (LINK, HY, SS, "11111111-1111-4111-8111-111111111111", "published-public"):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, result["text"])
        self.assertEqual(public["sources"][0]["body_sha256"], hashlib.sha256(raw).hexdigest())
        cache = worker.state_dir / tools.PRIVATE_CACHE
        self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o600)
        saved = json.loads(cache.read_text())
        self.assertTrue(saved["unverified_inputs"])
        self.assertEqual(len(saved["candidates"]), 3)
        self.assertFalse(any("qualified" in row for row in saved["candidates"]))

    def test_url_privacy_and_private_endpoints_fail_closed(self):
        for url in ("https://127.0.0.1/a", "https://[::1]/a", "https://u:p@example.com/a",
                    "https://example.com/feed?token=secret", "https://example.com/private/sub.txt",
                    "https://example.com/11111111-1111-4111-8111-111111111111/sub.txt",
                    "https://example.com/feed?opaque=secret", "https://example.com/a?format=token%3Dsecret"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                tools.privacy_url(url)
        self.assertEqual(tools.privacy_url(FEED), FEED)

    def test_search_and_fetch_cooldowns_survive_new_worker_and_empty_inputs(self):
        calls = []
        def search(query):
            calls.append(query); return []
        worker = self.worker(Pool({FEED: b"no configurations"}), search_provider=search)
        worker.execute({"action": "search", "query": "Serbia public proxy"})
        worker.execute({"action": "fetch", "url": FEED})
        state = worker.snapshot()
        next_worker = self.worker(Pool({FEED: AssertionError("must not refetch")}), state=state, search_provider=search)
        self.assertEqual(next_worker.execute({"action": "search", "query": "Serbia public proxy"})["status"], "cooldown")
        self.assertEqual(next_worker.execute({"action": "fetch", "url": FEED})["status"], "cooldown")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(next_worker.snapshot()["events"]), 2)

    def test_request_budget_and_context_size_are_bounded(self):
        urls = [FEED + "-" + str(i) for i in range(8)]
        pool = Pool({url: ("public description " * 10000).encode() for url in urls})
        worker = self.worker(pool, max_requests=4)
        outputs = [worker.execute({"action": "fetch", "url": url}) for url in urls]
        self.assertEqual(len(pool.calls), 4)
        self.assertLessEqual(sum(len(row.get("text", "")) for row in outputs), tools.MAX_CONTEXT_CHARS)
        self.assertTrue(any(row["status"] == "request-budget" for row in outputs))

    def test_github_repository_fetch_returns_actual_bounded_data_files(self):
        repo = "https://github.com/example/public"
        pool = Pool({"https://api.github.com/repos/example/public": json.dumps({"private": False, "default_branch": "main"}).encode(),
                     "https://api.github.com/repos/example/public/git/trees/main?recursive=1": json.dumps({"tree": [
                         {"type": "blob", "path": "servers.txt", "size": 100},
                         {"type": "blob", "path": ".github/workflows/build.yml", "size": 100},
                         {"type": "blob", "path": "big.txt", "size": tools.MAX_FETCH_BYTES + 1}]}).encode()})
        result = self.worker(pool).execute({"action": "fetch", "url": repo})
        self.assertEqual(result["status"], "repository-index")
        self.assertEqual(result["links"], [FEED])
        self.assertEqual(result["candidate_count"], 0)

    def test_search_filters_duplicate_and_credential_urls(self):
        worker = self.worker(search_provider=lambda query: [{"url": FEED}, {"url": FEED},
                                                           {"url": "https://example.com/x?token=private"}])
        result = worker.execute({"action": "search", "query": "Сербия прокси"})
        self.assertEqual([row["url"] for row in result["results"]], [FEED])
        self.assertEqual(len(worker.seed_queries()), 3)

    def test_persistent_cache_keeps_identity_and_never_promotes_cached_inputs(self):
        worker = self.worker(Pool({FEED: LINK.encode()}))
        worker.execute({"action": "fetch", "url": FEED})
        restored = self.worker()
        self.assertEqual(len(restored.candidates), 1)
        self.assertEqual(restored.execute({"action": "finish"})["candidate_count"], 0)
        self.assertFalse(restored.public_metadata()["candidates"])
        self.assertFalse(restored.proposal()["sources"])

    def test_policy_denial_and_network_errors_are_safe_without_candidates(self):
        for pool in (Pool({FEED: LINK.encode()}, allowed=False), Pool({FEED: OSError("token=never-show")})):
            result = self.worker(pool).execute({"action": "fetch", "url": FEED})
            self.assertEqual(result["candidate_count"], 0)
            self.assertNotIn("never-show", json.dumps(result))

    def test_existing_registry_and_production_inputs_are_not_new_discoveries(self):
        (self.path / "output").mkdir()
        (self.path / "output/best50.txt").write_text(LINK + "\n")
        with patch("source_catalog.load_regional_sources", return_value=([FEED], {"active": 1})):
            worker = self.worker(Pool({FEED: LINK.encode()}))
        result = worker.execute({"action": "fetch", "url": FEED})
        self.assertTrue(result["known_source"])
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["new_candidate_count"], 0)
        self.assertFalse(worker.proposal()["sources"])
        self.assertFalse(worker.public_metadata()["sources"])
        self.assertFalse(worker.public_metadata()["candidates"])

    def test_known_feed_with_new_configuration_and_new_feed_with_old_configuration(self):
        import build
        identity = build.normalized_fingerprint(build.parse_vless(LINK))
        worker = self.worker(Pool({FEED: (LINK + "\n" + HY).encode()}), known_sources=[FEED], known_candidate_ids=[identity])
        worker.execute({"action": "fetch", "url": FEED})
        data = worker.public_metadata()
        self.assertEqual(len(data["sources"]), 1)
        self.assertEqual([row["protocol"] for row in data["candidates"]], ["hysteria2"])
        new_url = FEED + "-new"
        second = self.worker(Pool({new_url: LINK.encode()}), known_candidate_ids=[identity])
        second.execute({"action": "fetch", "url": new_url})
        self.assertEqual([row["url"] for row in second.public_metadata()["sources"]], [new_url])
        self.assertFalse(second.public_metadata()["candidates"])

    def test_quoted_json_credentials_and_embedded_uuids_are_scrubbed(self):
        secret = "do-not-copy-this-secret"
        text = json.dumps({"password": secret, "private_key": secret, "uuid": "11111111-1111-4111-8111-111111111111",
                           "authorization": "Bearer " + secret})
        worker = self.worker(Pool({FEED: text.encode()}))
        result = worker.execute({"action": "fetch", "url": FEED})
        self.assertNotIn(secret, result["text"])
        self.assertNotIn("11111111-1111-4111-8111-111111111111", result["text"])

    def test_successful_empty_http_response_is_distinct_from_outage(self):
        for raw, successes in ((b"no proxy configurations", 1), (OSError("offline"), 0)):
            worker = self.worker(Pool({FEED: raw}))
            worker.execute({"action": "fetch", "url": FEED})
            self.assertEqual(worker.coverage()["requests"], 1)
            self.assertEqual(worker.coverage()["successful_requests"], successes)

    def test_long_public_github_names_are_not_mistaken_for_credential_paths(self):
        url = "https://raw.githubusercontent.com/publicuser/public-v2ray-configurations-2026/main/sub.txt"
        self.assertEqual(tools.privacy_url(url), url)


if __name__ == "__main__":
    unittest.main()
