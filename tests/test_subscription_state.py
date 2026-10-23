import importlib.util
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


state = load("test_subscription_state_module", "subscription_state.py")
local = load("test_subscription_state_local", "local_probe.py")
scheduler = load("test_subscription_state_scheduler", "regional_scheduler.py")


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def status(now, **changes):
    return {"algorithm": "bestlocal-strict-services-v6", "generated_at": stamp(now),
            "nodes": [{"link": "vless://retained"}], "stability": {"qualified": 1}, **changes}


TEXT = ("#profile-title: Best Local VPN\n# generated: 2026-10-20 12:34:56 UTC\n"
        "#profile-update-interval: 1\nvless://credential@example.com:443?security=reality#DE%20one\n"
        "trojan://password@example.net:443?sni=example.net#GB%20two\n")


class SubscriptionStateTests(unittest.TestCase):
    def test_stale_annotation_is_idempotent_and_preserves_exact_configuration_lines(self):
        for original in (TEXT, TEXT.replace("\n", "\r\n"), TEXT.rstrip("\n")):
            with self.subTest(ending=repr(original[-5:])):
                marked = state.mark_stale_text(original)
                self.assertEqual(marked, state.mark_stale_text(marked))
                self.assertEqual(state.connection_lines(marked), state.connection_lines(original))
                self.assertIn("# generated: 2026-10-20 12:34:56 UTC", marked)
                self.assertEqual(marked.count("#profile-title:"), 1)
                self.assertIn(state.STALE_TITLE, marked)
                self.assertIn(state.HEALTH_URL, marked)
                for line in original.splitlines(keepends=True):
                    if not line.startswith("#profile-title:"):
                        self.assertIn(line, marked)

    def test_empty_subscription_cannot_be_created_by_annotation(self):
        for original in ("", "# generated: retained\n# comments only\n"):
            with self.assertRaises(ValueError):
                state.mark_stale_text(original)

    def test_strict_freshness_requires_aware_recent_timestamp_and_matching_nonempty_nodes(self):
        now = int(time.time())
        self.assertTrue(state.is_fresh_strict_status(status(now), now))
        self.assertTrue(state.is_fresh_strict_status(status(now + 300), now))
        invalid = [status(now - 6 * 3600), status(now + 301), status(now, algorithm="legacy"),
                   status(now, generated_at="2026-10-20T12:00:00"), status(now, generated_at="bad"),
                   status(now, generated_at=float("nan")), status(now, generated_at=10 ** 400),
                   status(now, nodes=[]), status(now, nodes=["vless://retained"]),
                   status(now, stability={"qualified": True}), status(now, stability={"qualified": float("nan")}),
                   status(now, stability={"qualified": 10 ** 400}), status(now, stability={"qualified": 2}),
                   status(now, stability=[]), [], None]
        for item in invalid:
            with self.subTest(status=str(item)[:100]):
                self.assertFalse(state.is_fresh_strict_status(item, now))

    def test_bounded_malformed_status_is_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            for raw in (b"broken", b"[]", b"[" * 2000 + b"]" * 2000,
                        b"x" * (state.MAX_BYTES + 1)):
                path.write_bytes(raw)
                self.assertFalse(state.is_fresh_strict_status(state.read_status(path)))

    def test_older_zero_result_cannot_overwrite_newer_validated_publication(self):
        now = time.time()
        calls = []
        def fake_git(*args, **kwargs):
            calls.append(args)
            if args[:2] == ("worktree", "add"):
                worktree = Path(args[3])
                (worktree / "output").mkdir(parents=True)
                (worktree / "output/local-status.json").write_text(json.dumps(status(now)))
                (worktree / "output/best-local.txt").write_text(TEXT)
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(local, "STATE_DIR", Path(temporary)), \
                patch.object(local, "git_output", side_effect=fake_git), \
                patch.object(local, "write_status") as write, patch.object(local.subprocess, "run"):
            local.publish_regional_health({"generated_at": stamp(now - 10), "stability": {"qualified": 0}})
        write.assert_not_called()
        self.assertFalse(any(command[0] == "push" for command in calls))


class RegionalAnnotationTests(unittest.TestCase):
    def test_real_bare_git_fresh_skip_stale_publication_retry_and_idempotence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repo, remote = directory / "repo", directory / "remote.git"
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL, text=True).strip()
            git("init", "--bare", str(remote))
            git("init", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("remote", "add", "origin", str(remote))
            (repo / "output").mkdir()
            subscription = repo / "output/best-local.txt"
            subscription.write_text(TEXT)
            local_status = repo / "output/local-status.json"
            local_status.write_text(json.dumps(status(time.time())))
            git("add", ".")
            git("commit", "-m", "initial private fixture")
            git("push", "origin", "HEAD:regional")
            before = git("ls-remote", "origin", "refs/heads/regional")
            expired_runner = scheduler.Runner(repo, time.monotonic() + 30)
            initial_git = expired_runner.git
            def expire_after_checkout(*args, **kwargs):
                result = initial_git(*args, **kwargs)
                if args[:2] == ("worktree", "add"):
                    expired_runner.deadline = 0
                return result
            with patch.object(expired_runner, "git", side_effect=expire_after_checkout):
                self.assertFalse(state.mark_regional(repo, expired_runner))
            # An expired publishing budget must not suppress owned cleanup or
            # replace the successful freshness-skip return with a timeout.
            self.assertEqual(len(git("worktree", "list", "--porcelain").split("worktree ")) - 1, 1)
            self.assertEqual(git("ls-remote", "origin", "refs/heads/regional"), before)
            local_status.write_text(json.dumps(status(time.time() - 7 * 3600)))
            git("add", "output/local-status.json")
            git("commit", "-m", "fixture becomes stale")
            git("push", "origin", "HEAD:regional")
            original_status = local_status.read_text()
            runner = scheduler.Runner(repo, time.monotonic() + 30)
            original_git = runner.git
            failed_push = []
            def transient_push(*args, **kwargs):
                if "push" in args and not failed_push:
                    failed_push.append(True)
                    raise scheduler.CommandFailure("simulated GitHub outage", 1)
                return original_git(*args, **kwargs)
            with patch.object(runner, "git", side_effect=transient_push), patch.object(state.time, "sleep"):
                self.assertTrue(state.mark_regional(repo, runner))
            self.assertEqual(len(failed_push), 1)
            git("fetch", "origin", "regional")
            retained = git("show", "origin/regional:output/best-local.txt")
            self.assertIn(state.STALE_TITLE, retained)
            self.assertEqual(state.connection_lines(retained), state.connection_lines(TEXT))
            self.assertIn("# generated: 2026-10-20 12:34:56 UTC", retained)
            self.assertEqual(git("show", "origin/regional:output/local-status.json"), original_status.strip())
            published = git("ls-remote", "origin", "refs/heads/regional")
            self.assertFalse(state.mark_regional(repo))
            self.assertEqual(git("ls-remote", "origin", "refs/heads/regional"), published)
            self.assertEqual(len(git("worktree", "list", "--porcelain").split("worktree ")) - 1, 1)


if __name__ == "__main__":
    unittest.main()
