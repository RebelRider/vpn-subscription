import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import owned_temporary as owned


class OwnedTemporaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "owned"
        self.addCleanup(self.temporary.cleanup)

    def crash_directory(self, repo=None):
        code = ("import os,sys; from pathlib import Path; "
                "sys.path.insert(0," + repr(str(ROOT / "scripts")) + "); "
                "from owned_temporary import temporary_directory; "
                "context=temporary_directory(prefix='bestlocal-source-publish-',parent=Path(" + repr(str(self.root)) + "),repo="
                + (repr(str(repo)) if repo else "None") + "); "
                "directory=context.__enter__(); print(directory,flush=True); ")
        if repo:
            code += ("import subprocess; subprocess.run(['git','worktree','add','--detach',"
                     "str(Path(directory)/'checkout'),'HEAD'],cwd=" + repr(str(repo))
                     + ",check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); ")
        code += "os._exit(0)"
        path = Path(subprocess.check_output([sys.executable, "-c", code], text=True).strip())
        marker = path / owned.MARKER
        value = json.loads(marker.read_text())
        value["created_at"] = time.time() - 3 * 3600
        marker.write_text(json.dumps(value))
        return path

    def test_private_context_cleanup_on_success_and_failure(self):
        for failure in (False, True):
            try:
                with owned.temporary_directory(prefix="bestlocal-browser-", parent=self.root) as value:
                    path = Path(value)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                    for name in (owned.MARKER, owned.LEASE):
                        self.assertEqual(stat.S_IMODE((path / name).stat().st_mode), 0o600)
                    self.assertEqual(json.loads((path / owned.MARKER).read_text())["owner"], os.getuid())
                    (path / "owned-scratch").write_text("temporary")
                    if failure:
                        raise RuntimeError("original error")
            except RuntimeError as exc:
                self.assertEqual(str(exc), "original error")
            self.assertFalse(path.exists())

    def test_old_active_lease_survives_janitor_without_pid_assumptions(self):
        with owned.temporary_directory(prefix="bestlocal-service-", parent=self.root) as value:
            path = Path(value)
            result = owned.cleanup_owned_temporary(self.root, now=time.time() + 3 * 3600)
            self.assertEqual(result["active"], 1)
            self.assertEqual(result["removed"], 0)
            self.assertTrue(path.exists())
        self.assertFalse(path.exists())

    def test_crash_recovery_reclaims_marked_directory(self):
        path = self.crash_directory()
        self.assertTrue(path.exists())
        result = owned.cleanup_owned_temporary(self.root)
        self.assertEqual(result["removed"], 1)
        self.assertFalse(path.exists())

    def test_unmarked_symlink_malformed_and_unknown_directories_are_preserved(self):
        self.root.mkdir(mode=0o700)
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep").write_text("keep")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "bestlocal-browser-symlink").symlink_to(outside, target_is_directory=True)
        malformed = self.crash_directory()
        (malformed / owned.MARKER).write_text('{"schema":1}')
        unknown = self.crash_directory()
        marker = unknown / owned.MARKER
        value = json.loads(marker.read_text())
        value["kind"] = "not-owned-"
        marker.write_text(json.dumps(value))
        result = owned.cleanup_owned_temporary(self.root)
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["invalid"], 4)
        self.assertTrue((unrelated / "keep").exists())
        self.assertTrue(outside.exists())
        self.assertTrue(malformed.exists())
        self.assertTrue(unknown.exists())

    def test_new_and_future_metadata_are_not_reclaimed(self):
        path = self.crash_directory()
        marker = path / owned.MARKER
        for stamp in (time.time(), time.time() + 86400):
            value = json.loads(marker.read_text())
            value["created_at"] = stamp
            marker.write_text(json.dumps(value))
            result = owned.cleanup_owned_temporary(self.root)
            self.assertEqual(result["removed"], 0)
            self.assertTrue(path.exists())

    def test_registered_worktree_requires_exact_repo_and_preserves_unrelated_checkout(self):
        repo = Path(self.temporary.name) / "repo"
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, text=True, stderr=subprocess.DEVNULL).strip()
        git("init", "-b", "main")
        (repo / "keep.txt").write_text("keep")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
        unrelated = Path(self.temporary.name) / "unrelated-worktree"
        git("worktree", "add", "--detach", str(unrelated), "HEAD")
        path = self.crash_directory(repo)
        result = owned.cleanup_owned_temporary(self.root)
        self.assertEqual(result["removed"], 0)
        self.assertTrue((path / "checkout/keep.txt").exists())
        result = owned.cleanup_owned_temporary(self.root, repos=[repo])
        self.assertEqual(result["removed"], 1)
        self.assertFalse(path.exists())
        self.assertEqual((unrelated / "keep.txt").read_text(), "keep")
        listing = git("worktree", "list", "--porcelain")
        self.assertNotIn(str(path), listing)
        self.assertNotIn(str(path.resolve()), listing)
        self.assertIn(str(unrelated), listing)

    def test_enumeration_is_bounded(self):
        self.root.mkdir(mode=0o700)
        for index in range(5):
            (self.root / str(index)).mkdir()
        result = owned.cleanup_owned_temporary(self.root, maximum_entries=2)
        self.assertEqual(result["examined"], 2)
        self.assertTrue(result["limited"])

    def test_root_and_lease_symlinks_fail_closed(self):
        self.root.mkdir(mode=0o700)
        other = Path(self.temporary.name) / "other"
        other.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            owned.cleanup_owned_temporary(other)
        with self.assertRaises(ValueError):
            with owned.temporary_directory(prefix="bestlocal-browser-", parent=other):
                self.fail("symlink root must not be used")
        path = self.crash_directory()
        lease = path / owned.LEASE
        lease.unlink()
        lease.symlink_to(path / owned.MARKER)
        result = owned.cleanup_owned_temporary(self.root)
        self.assertEqual(result["removed"], 0)
        self.assertTrue(path.exists())

    def test_marker_symlink_fifo_hardlink_and_public_permissions_fail_closed(self):
        for replacement in ("symlink", "fifo", "hardlink", "public"):
            with self.subTest(replacement=replacement):
                path = self.crash_directory()
                marker = path / owned.MARKER
                original = marker.read_bytes()
                other = Path(self.temporary.name) / (replacement + "-outside.json")
                other.write_bytes(original)
                other.chmod(0o600)
                marker.unlink()
                if replacement == "symlink":
                    marker.symlink_to(other)
                elif replacement == "fifo":
                    os.mkfifo(marker, 0o600)
                elif replacement == "hardlink":
                    os.link(other, marker)
                else:
                    marker.write_bytes(original)
                    marker.chmod(0o644)
                result = owned.cleanup_owned_temporary(self.root)
                self.assertEqual(result["removed"], 0)
                self.assertGreaterEqual(result["invalid"], 1)
                self.assertTrue(path.exists())
                self.assertEqual(other.read_bytes(), original)

    def test_foreign_embedded_repository_or_worktree_is_never_deleted(self):
        repo = Path(self.temporary.name) / "authorized"
        foreign = Path(self.temporary.name) / "foreign"
        for directory in (repo, foreign):
            directory.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=directory, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (directory / "keep.txt").write_text(directory.name)
            subprocess.run(["git", "add", "."], cwd=directory, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                            "commit", "-m", "fixture"], cwd=directory, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for location in ("checkout", "unrelated/nested-repo", "checkout/unrelated-repo"):
            with self.subTest(location=location):
                path = self.crash_directory(repo if location.startswith("checkout/") else None)
                marker = path / owned.MARKER
                value = json.loads(marker.read_text())
                value["repo"] = str(repo.resolve())
                marker.write_text(json.dumps(value))
                checkout = path / location
                checkout.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(["git", "worktree", "add", "--detach", str(checkout), "HEAD"],
                               cwd=foreign, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                result = owned.cleanup_owned_temporary(self.root, repos=[repo])
                self.assertEqual(result["removed"], 0)
                self.assertTrue((checkout / "keep.txt").exists())
                listing = subprocess.check_output(["git", "worktree", "list", "--porcelain"],
                                                  cwd=foreign, text=True)
                self.assertIn(str(checkout), listing)
                self.assertEqual((checkout / "keep.txt").read_text(), "foreign")


if __name__ == "__main__":
    unittest.main()
