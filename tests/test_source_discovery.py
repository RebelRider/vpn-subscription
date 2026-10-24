import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import source_discovery as discovery

UUID = "11111111-1111-4111-8111-111111111111"
LINK = f"vless://{UUID}@1.1.1.1:443?security=tls&sni=example.com#public"


class DormantSourceRecoveryTests(unittest.TestCase):
    NOW = 2_000_000_000

    @staticmethod
    def dormant(url, retry_at):
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        return key, {"url": url, "origin": "public-feed-link",
                     "retired_at": retry_at - discovery.RETIREMENT_COOLDOWN,
                     "retry_at": retry_at}

    def test_one_off_discovered_source_returns_without_parent_or_manual_add(self):
        parent = "https://raw.githubusercontent.com/public/parent/main/config.txt"
        child = "https://raw.githubusercontent.com/one-off/public/main/subscription.txt"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            pool = discovery.SourcePool([{"url": parent}], path, now=self.NOW)
            with patch.object(pool, "discover"), patch.object(pool, "get", return_value=(
                    (LINK + "\n" + child).encode(), {})):
                pool.collect()
            key, item = next((key, item) for key, item in pool.sources.items() if item["url"] == child)
            self.assertEqual(item["origin"], "public-feed-link")
            item.update(first_seen=self.NOW - 8 * 86400, failures=5,
                        last_success=self.NOW - 8 * 86400)
            for parent_key in [source for source, value in pool.sources.items() if value["url"] == parent]:
                del pool.sources[parent_key]
            pool.save()
            self.assertNotIn(key, pool.sources)
            self.assertEqual(pool.state["dormant_sources"][key]["url"], child)

            before = discovery.SourcePool([], path, now=self.NOW + discovery.RETIREMENT_COOLDOWN - 1)
            with patch.object(before, "discover"), patch.object(before, "get") as fetch:
                self.assertEqual(before.collect()[0], [])
                fetch.assert_not_called()

            restored = discovery.SourcePool([], path, now=self.NOW + discovery.RETIREMENT_COOLDOWN + 1)
            # No caller supplies the source URL again and its parent is gone.
            with patch.object(restored, "discover"), patch.object(restored, "get", return_value=(LINK.encode(), {})) as fetch:
                links, _ = restored.collect()
            self.assertEqual(links, [LINK])
            self.assertEqual([call.args[0] for call in fetch.call_args_list], [child])
            self.assertEqual(restored.stats["dormant_reprobes"], 1)
            self.assertEqual(restored.sources[key]["failures"], 0)
            self.assertEqual(restored.sources[key]["last_success"], restored.now)
            self.assertNotIn(key, restored.state["dormant_sources"])
            self.assertNotIn(parent, [item["url"] for item in restored.sources.values()])

    def test_reprobe_preserves_normal_retry_after_and_failure_backoff(self):
        url = "https://raw.githubusercontent.com/public/returning/main/config.txt"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            pool = discovery.SourcePool([], path, now=self.NOW)
            key, record = self.dormant(url, self.NOW - 1)
            pool.state["dormant_sources"][key] = record
            deadline = self.NOW + 10 * 3600
            with patch.object(pool, "discover"), patch.object(pool, "get", side_effect=discovery.RateLimited(deadline)):
                self.assertEqual(pool.collect()[0], [])
            self.assertEqual(pool.sources[key]["failures"], 1)
            self.assertEqual(pool.sources[key]["next_fetch"], deadline)
            self.assertNotIn(key, pool.state["dormant_sources"])
            later = discovery.SourcePool([], path, now=self.NOW + 3600)
            with patch.object(later, "discover"), patch.object(later, "get") as fetch:
                self.assertEqual(later.collect()[0], [])
                fetch.assert_not_called()

    def test_never_successful_trial_ages_from_discovery_not_epoch_after_reload(self):
        url = "https://raw.githubusercontent.com/public/fresh/main/config.txt"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            pool = discovery.SourcePool([], path, now=self.NOW)
            pool.add(url, "public-feed-link")
            key, item = next(iter(pool.sources.items()))
            first_seen = self.NOW - 15 * 3600
            item.update(first_seen=first_seen, failures=5)
            pool.save()
            restored = discovery.SourcePool([], path, now=self.NOW)
            self.assertEqual(restored.sources[key]["last_success"], 0)
            restored.save()
            self.assertIn(key, restored.sources)
            self.assertNotIn(key, restored.state["dormant_sources"])
            # It still retires and receives a new retry deadline after the
            # genuine seven-day failure period, rather than avoiding rotation.
            old = discovery.SourcePool([], path, now=first_seen + 7 * 86400 + 1)
            old.save()
            self.assertNotIn(key, old.sources)
            self.assertEqual(old.state["dormant_sources"][key]["retired_at"], old.now)
            self.assertEqual(old.state["dormant_sources"][key]["retry_at"], old.now + discovery.RETIREMENT_COOLDOWN)

    def test_full_registry_admits_two_reprobes_and_leaves_fresh_discovery_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json", now=self.NOW)
            for index in range(discovery.MAX_SOURCES):
                pool.add(f"https://example.com/established-{index}.txt", "github-search")
                item = next(reversed(pool.sources.values()))
                item.update(first_seen=self.NOW - 2 * 86400, functional_ema=(index + 1) / 200)
            protected = {key for index, key in enumerate(pool.sources) if index >= discovery.MAX_SOURCES // 5}
            returning = [f"https://returning.example/source-{index}.txt" for index in range(3)]
            for index, url in enumerate(returning):
                key, record = self.dormant(url, self.NOW - (3 - index) * 100)
                pool.state["dormant_sources"][key] = record
            new = [f"https://new.example/source-{index}.txt" for index in range(3)]
            admitted = []
            def new_discovery():
                self.assertTrue(set(returning[:2]).issubset(item["url"] for item in pool.sources.values()))
                admitted.extend(pool.add(url, "github-search") for url in new)
            with patch.object(pool, "discover", side_effect=new_discovery), \
                 patch.object(pool, "allowed", return_value=True), \
                 patch.object(pool, "get", return_value=(LINK.encode(), {})) as fetch:
                pool.collect()
            self.assertEqual(pool.stats["dormant_reprobes"], 2)
            self.assertEqual(admitted, [True, True, False])
            self.assertEqual(pool.stats["exploration_replacements"], 4)
            self.assertEqual(len(pool.sources), discovery.MAX_SOURCES)
            self.assertTrue(protected.issubset(pool.sources))
            self.assertLessEqual(fetch.call_count, discovery.MAX_FETCH_SOURCES)
            self.assertIn(returning[2], [item["url"] for item in pool.state["dormant_sources"].values()])

    def test_dormant_restore_is_bounded_canonical_and_rejects_unsafe_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            records = {}
            for index in range(discovery.MAX_DORMANT_SOURCES + 20):
                url = f"https://example.com/dormant-{index}.txt"
                key, record = self.dormant(url, self.NOW + discovery.RETIREMENT_COOLDOWN - index)
                records[key] = record
            for index, url in enumerate(("https://127.0.0.1/private", "https://user:password@example.com/sub",
                                         "https://example.com/sub?token=secret")):
                key, record = self.dormant(url, self.NOW + discovery.RETIREMENT_COOLDOWN)
                records[key] = record
            for index, changes in enumerate(({"origin": []}, {"retired_at": self.NOW + 1},
                                             {"retry_at": float("nan")}, {"retired_at": True},
                                             {"retry_at": self.NOW + 30}, {"extra": "unsupported"})):
                key, record = self.dormant(f"https://example.com/invalid-{index}.txt", self.NOW + discovery.RETIREMENT_COOLDOWN)
                records[key] = {**record, **changes}
            records["not-a-source-key"] = {"url": "https://example.com/fake.txt"}
            path.write_text(json.dumps({"version": 1, "sources": {}, "dormant_sources": records}))
            pool = discovery.SourcePool([], path, now=self.NOW)
            self.assertEqual(len(pool.state["dormant_sources"]), discovery.MAX_DORMANT_SOURCES)
            self.assertEqual({item["url"] for item in pool.state["dormant_sources"].values()},
                             {f"https://example.com/dormant-{index}.txt" for index in range(discovery.MAX_DORMANT_SOURCES)})
            pool.save()
            self.assertNotIn("password", path.read_text())
            self.assertNotIn("secret", path.read_text())
            self.assertNotIn("127.0.0.1", path.read_text())


class DiscoveryTests(unittest.TestCase):
    def test_source_url_policy_and_canonical_dedup(self):
        self.assertEqual(discovery.canonical_url("https://github.com/owner/repo/blob/main/vless.txt#x"), "https://raw.githubusercontent.com/owner/repo/main/vless.txt")
        self.assertEqual(discovery.canonical_url("https://raw.githubusercontent.com/owner/repo/refs/heads/main/vless.txt"), "https://raw.githubusercontent.com/owner/repo/main/vless.txt")
        for url in ("http://example.com/sub.txt", "https://127.0.0.1/sub.txt", "https://192.168.1.1/sub.txt", "https://[::1]/sub.txt", "https://service.internal/sub.txt", "https://u:p@example.com/sub.txt", "https://example.com:8443/sub.txt", "https://example.com/sub?token=secret", "https://example.com/\nsub"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                discovery.canonical_url(url)

    def test_mixed_public_private_dns_fails_closed(self):
        infos = [(2, 1, 6, "", ("1.1.1.1", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with patch.object(discovery.socket, "getaddrinfo", return_value=infos), self.assertRaises(ValueError):
            discovery.public_addresses("source.example.com")

    def test_share_and_base64_extraction_is_bounded_and_multi_protocol(self):
        links = [LINK, "trojan://public-pass@1.1.1.1:443?security=tls", "socks://dGVzdDpwYXNz@1.1.1.1:1080"]
        text = "\n".join(links + [LINK])
        self.assertEqual(discovery.extract_links(discovery.decode_subscription(base64.b64encode(text.encode()))), links)
        self.assertFalse(discovery.extract_links("vless://" + "x" * 10000))
        self.assertEqual(len(discovery.extract_links("\n".join(f"vless://{i}" for i in range(5000)))), discovery.MAX_LINKS_PER_SOURCE)

    def test_unknown_repository_discovers_candidates_without_manual_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json", now=2_000_000_000)
            def get(url, max_bytes=discovery.MAX_SOURCE_BYTES):
                if "/search/repositories?" in url:
                    return json.dumps({"items": [{"full_name": "new/public-feed", "default_branch": "main", "private": False}]}).encode(), {}
                if "/git/trees/" in url:
                    return json.dumps({"tree": [{"path": "protocols/trojan.txt", "type": "blob", "size": len(LINK)}]}).encode(), {}
                return LINK.encode(), {}
            with patch.object(pool, "get", side_effect=get):
                links, stats = pool.collect()
            self.assertEqual(links, [LINK])
            self.assertEqual(pool.stats["discovered_sources"], 1)
            self.assertEqual(len(stats), 1)
            self.assertIn("github-search", next(iter(stats.values()))["origin"])
            self.assertNotIn(UUID, pool.path.read_text())

    def test_new_public_feed_links_are_auto_replenished(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            pool = discovery.SourcePool([{"url": "https://example.com/config.txt"}], path, now=2_000_000_000)
            pool.state["last_discovery"] = pool.now
            with patch.object(pool, "allowed", return_value=True), patch.object(pool, "get", return_value=((LINK + "\nhttps://new.example.org/subscription.txt").encode(), {})):
                links, _ = pool.collect()
            self.assertEqual(links, [LINK])
            self.assertIn("https://new.example.org/subscription.txt", [item["url"] for item in pool.sources.values()])
            pool.feedback([LINK], {LINK}, 1)
            item = next(item for item in pool.sources.values() if item["origin"] == "seed")
            self.assertGreater(item["functional_ema"], 0)
            self.assertEqual(item["last_functional_count"], 1)
            restored = discovery.SourcePool([], path, now=pool.now + 7201)
            self.assertEqual(restored.state["last_qualified"], 1)
            self.assertEqual(len(restored.sources), 2)

    def test_source_outage_backoff_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            seed = {"url": "https://raw.githubusercontent.com/public/feed/main/config.txt"}
            pool = discovery.SourcePool([seed], path, now=2_000_000_000)
            pool.state["last_discovery"] = pool.now
            with patch.object(pool, "get", side_effect=TimeoutError("should not be logged")):
                links, stats = pool.collect()
            self.assertEqual(links, [])
            item = next(iter(pool.sources.values()))
            self.assertEqual(item["next_fetch"], pool.now + 1800)
            self.assertEqual(item["failures"], 1)
            restored = discovery.SourcePool([seed], path, now=pool.now + 1801)
            restored.state["last_discovery"] = restored.now
            with patch.object(restored, "get", return_value=(LINK.encode(), {})):
                recovered, _ = restored.collect()
            self.assertEqual(recovered, [LINK])
            self.assertEqual(next(iter(restored.sources.values()))["failures"], 0)

    def test_immediate_replenishment_reuses_successful_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            seed = {"url": "https://raw.githubusercontent.com/public/feed/main/config.txt"}
            pool = discovery.SourcePool([seed], path, now=2_000_000_000)
            pool.state["last_discovery"] = pool.now
            with patch.object(pool, "get", return_value=(LINK.encode(), {})):
                first, _ = pool.collect()
            saved = json.loads(path.read_text())
            # Compatibility with the successful-fetch cooldown cached by the
            # previous implementation must not make expedited builds empty.
            next(iter(saved["sources"].values()))["next_fetch"] = pool.now + 1800
            path.write_text(json.dumps(saved))
            restored = discovery.SourcePool([seed], path, now=pool.now + 10)
            with patch.object(restored, "get", return_value=(LINK.encode(), {})) as fetch:
                second, _ = restored.collect()
            self.assertEqual(first, [LINK])
            self.assertEqual(second, first)
            self.assertEqual(fetch.call_count, 1)

    def test_rate_limit_stops_discovery_and_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json", now=2_000_000_000)
            with patch.object(pool, "get", side_effect=discovery.RateLimited(pool.now + 3600)) as get:
                pool.discover()
                pool.discover()
            self.assertEqual(get.call_count, 1)
            self.assertTrue(pool.stats["rate_limited"])
            pool.save()
            self.assertEqual(json.loads(pool.path.read_text())["api_retry_at"], pool.now + 3600)

    def test_existing_source_registry_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json")
            for i in range(discovery.MAX_SOURCES + 20):
                pool.add(f"https://example.org/sub-{i}.txt", "public-feed-link")
            self.assertEqual(len(pool.sources), discovery.MAX_SOURCES)

    def test_redirect_policy_is_checked_before_contacting_new_origin(self):
        response = Mock(status=302)
        response.getheaders.return_value = [("Location", "https://new.example.com/sub.txt")]
        connection = Mock()
        connection.getresponse.return_value = response
        infos = [(2, 1, 6, "", ("1.1.1.1", 443))]
        policy = Mock(return_value=False)
        with patch.object(discovery, "public_addresses", return_value=infos), \
                patch.object(discovery.http.client, "HTTPSConnection", return_value=connection) as create:
            with self.assertRaisesRegex(ValueError, "source policy"):
                discovery.safe_get("https://example.com/sub.txt", redirect_policy=policy)
        policy.assert_called_once_with("https://new.example.com/sub.txt")
        self.assertEqual(create.call_count, 1)
        connection.close.assert_called_once()

    def test_source_redirect_checks_policy_and_counts_target_request(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json")
            def fetch(url, **kwargs):
                self.assertTrue(kwargs["redirect_policy"]("https://new.example.com/sub.txt"))
                return b"public", {}
            with patch.object(pool, "_before_request") as before, \
                    patch.object(pool, "allowed", return_value=True) as allowed, \
                    patch.object(discovery, "safe_get", side_effect=fetch):
                pool.get("https://example.com/sub.txt")
            allowed.assert_called_once_with("https://new.example.com/sub.txt")
            self.assertEqual(before.call_count, 2)

    def test_robots_redirects_fail_closed_without_policy_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = discovery.SourcePool([], Path(directory) / "state.json")
            def fetch(url, **kwargs):
                self.assertFalse(kwargs["redirect_policy"]("https://new.example.com/robots.txt"))
                return b"User-agent: *\nDisallow: /", {}
            with patch.object(pool, "_before_request"), \
                    patch.object(pool, "allowed") as allowed, \
                    patch.object(discovery, "safe_get", side_effect=fetch):
                pool.get("https://example.com/robots.txt", robots_fetch=True)
            allowed.assert_not_called()

    def test_response_slow_drip_obeys_total_deadline(self):
        clock = [0.0]
        response = Mock(status=200)
        response.getheaders.return_value = []
        def read(size):
            self.assertLessEqual(size, 65536)
            clock[0] += 4
            return b"a"
        response.read1.side_effect = read
        connection = Mock()
        connection.getresponse.return_value = response
        infos = [(2, 1, 6, "", ("1.1.1.1", 443))]
        with patch.object(discovery.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(discovery, "public_addresses", return_value=infos), \
                patch.object(discovery.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(TimeoutError, "total deadline"):
                discovery.safe_get("https://example.com/sub.txt", timeout=5)
        self.assertEqual(response.read1.call_count, 2)
        connection.close.assert_called_once()

    def test_dns_deadline_does_not_wait_for_system_resolver(self):
        release = threading.Event()
        completed = threading.Event()
        def resolve(*args, **kwargs):
            release.wait(2)
            completed.set()
            return [(2, 1, 6, "", ("1.1.1.1", 443))]
        try:
            with patch.object(discovery.socket, "getaddrinfo", side_effect=resolve):
                with self.assertRaisesRegex(TimeoutError, "DNS deadline"):
                    discovery.public_addresses("example.com", timeout=.001)
        finally:
            release.set()
            self.assertTrue(completed.wait(1))

    def test_header_deadline_interrupts_only_owned_request_socket(self):
        connection = Mock()
        timer = Mock()
        callbacks = []
        def make_timer(wait, callback):
            callbacks.append(callback)
            return timer
        def headers():
            callbacks[0]()
            raise TimeoutError("header deadline")
        connection.getresponse.side_effect = headers
        infos = [(2, 1, 6, "", ("1.1.1.1", 443))]
        with patch.object(discovery.threading, "Timer", side_effect=make_timer), \
                patch.object(discovery, "public_addresses", return_value=infos), \
                patch.object(discovery.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(TimeoutError, "header deadline"):
                discovery.safe_get("https://example.com/sub.txt")
        connection.sock.shutdown.assert_called_once_with(discovery.socket.SHUT_RDWR)
        timer.cancel.assert_called_once()
        connection.close.assert_called_once()

    def test_candidate_cap_rotates_feed_slice_between_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = "\n".join(LINK.split("#")[0] + f"#node-{i}" for i in range(10)).encode()
            collected = []
            for run in range(2):
                pool = discovery.SourcePool([{"url": "https://raw.githubusercontent.com/public/feed/main/config.txt"}],
                                            Path(directory) / f"state-{run}.json", now=2_000_000_000 + run * 7200)
                pool.state["last_discovery"] = pool.now
                with patch.object(discovery, "MAX_CANDIDATES", 4), patch.object(pool, "get", return_value=(raw, {})):
                    links, _ = pool.collect()
                self.assertEqual(len(links), 4)
                collected.append(set(links))
            self.assertFalse(collected[0] & collected[1])


if __name__ == "__main__":
    unittest.main()
