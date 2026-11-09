import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ci_engine", ROOT / "scripts/install_ci_engine.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def archive_bytes(*, link=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"{engine.ASSET}/sing-box")
        if link:
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(member)
        else:
            binary = b"test-engine-not-executed"
            member.size = len(binary)
            archive.addfile(member, io.BytesIO(binary))
    return buffer.getvalue()


class EngineInstallTests(unittest.TestCase):
    def test_valid_cached_engine_survives_release_host_outage(self):
        data = archive_bytes()
        with tempfile.TemporaryDirectory() as directory, patch.object(engine, "SHA256", hashlib.sha256(data).hexdigest()):
            root = Path(directory)
            cache = root / "engine.tgz"
            cache.write_bytes(data)
            with patch.object(engine, "download", side_effect=RuntimeError("release 504")) as fetch:
                installed = engine.install(cache, root / "bin")
            fetch.assert_not_called()
            self.assertEqual(installed.read_bytes(), b"test-engine-not-executed")
            self.assertTrue(installed.stat().st_mode & 0o111)

    def test_corrupt_cache_is_repaired_and_verified_before_install(self):
        data = archive_bytes()
        with tempfile.TemporaryDirectory() as directory, patch.object(engine, "SHA256", hashlib.sha256(data).hexdigest()):
            root = Path(directory)
            cache = root / "engine.tgz"
            cache.write_bytes(b"partial cache")
            with patch.object(engine, "download", side_effect=lambda path: path.write_bytes(data)) as fetch:
                installed = engine.install(cache, root / "bin")
            self.assertEqual(fetch.call_count, 1)
            self.assertTrue(engine.valid_archive(cache))
            self.assertEqual(installed.read_bytes(), b"test-engine-not-executed")

    def test_failed_or_corrupt_download_preserves_installed_engine_and_cleans_scratch(self):
        for failure in (None, RuntimeError("temporary release outage")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cache, bin_directory = root / "cache" / "engine.tgz", root / "bin"
                bin_directory.mkdir()
                installed = bin_directory / "sing-box"
                installed.write_bytes(b"last installed engine")
                def fetch(path):
                    path.write_bytes(b"corrupt or interrupted transfer")
                    if failure:
                        raise failure
                with patch.object(engine, "download", side_effect=fetch), self.assertRaises(RuntimeError):
                    engine.install(cache, bin_directory)
                self.assertEqual(installed.read_bytes(), b"last installed engine")
                self.assertFalse(cache.exists())
                self.assertEqual(list(cache.parent.iterdir()), [])

    def test_link_cannot_be_installed_even_from_matching_archive(self):
        data = archive_bytes(link=True)
        with tempfile.TemporaryDirectory() as directory, patch.object(engine, "SHA256", hashlib.sha256(data).hexdigest()):
            root = Path(directory)
            cache = root / "engine.tgz"
            cache.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError, "valid bounded engine"):
                engine.install(cache, root / "bin")
            self.assertFalse((root / "bin" / "sing-box").exists())

    def test_retries_have_process_and_transfer_deadlines(self):
        with patch.object(engine.subprocess, "run") as run:
            engine.download(Path("fixture-download"))
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(kwargs["timeout"], 240)
        for flag, value in (("--retry", "4"), ("--retry-delay", "15"), ("--retry-max-time", "180"),
                            ("--max-time", "45"), ("--connect-timeout", "15")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--retry-all-errors", command)
        self.assertIn(engine.URL, command)


if __name__ == "__main__":
    unittest.main()
