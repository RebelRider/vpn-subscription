import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("control_plane", ROOT / "scripts/control_plane.py")
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class ControlPlaneTests(unittest.TestCase):
    def test_configuration_is_authenticated_loopback_direct_en0_and_doh(self):
        config = control.configuration(45123, "user", "password")
        self.assertEqual(config["inbounds"], [{"type": "socks", "tag": "control", "listen": "127.0.0.1", "listen_port": 45123, "users": [{"username": "user", "password": "password"}]}])
        self.assertEqual(config["outbounds"][0]["bind_interface"], "en0")
        self.assertEqual(config["outbounds"][0]["type"], "direct")
        self.assertEqual(config["route"]["default_interface"], "en0")
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["dns"]["servers"][0]["server"], "1.1.1.1")
        self.assertEqual(config["dns"]["servers"][0]["tls"]["server_name"], "cloudflare-dns.com")
        self.assertEqual(config["dns"]["servers"][0]["detour"], "direct")
        serialized = json.dumps(config)
        for forbidden in ("auto_route", "strict_route", "tun", "utun", "networkextension"):
            self.assertNotIn(forbidden, serialized.lower())

    def test_environment_is_command_local_and_preserves_authentication(self):
        original = {"HTTPS_PROXY": "ambient", "no_proxy": "*", "GH_TOKEN": "preserved", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": "osxkeychain"}
        with mock.patch.dict(os.environ, original, clear=True):
            environment = control.proxy_environment("user", "password", 45123)
            self.assertEqual(dict(os.environ), original)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            self.assertEqual(environment[name], "socks5h://user:password@127.0.0.1:45123")
        self.assertEqual(environment["NO_PROXY"], "localhost,127.0.0.1,::1")
        self.assertEqual(environment["GH_TOKEN"], "preserved")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "credential.helper")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "osxkeychain")
        self.assertEqual(environment["GIT_CONFIG_KEY_1"], "http.proxy")
        self.assertEqual(environment["GIT_CONFIG_VALUE_1"], environment["HTTPS_PROXY"])

    def test_command_scope_rejects_arbitrary_programs(self):
        control.validate_command(["git", "fetch"])
        control.validate_command(["gh", "api", "rate_limit"])
        control.validate_command([sys.executable, str(ROOT / "scripts/local_probe.py"), "--publish"])
        for command in ([], ["/bin/sh", "-c", "dangerous"], [sys.executable, "unrelated.py"]):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                control.validate_command(command)

    def test_authenticated_readiness_requires_both_socks_method_and_password(self):
        proxy = mock.Mock()
        proxy.poll.return_value = None
        connection = mock.MagicMock()
        connection.recv.side_effect = [b"\x05\x02", b"\x01\x00"]
        connection.__enter__.return_value = connection
        with mock.patch.object(control.socket, "create_connection", return_value=connection):
            control.wait_authenticated(proxy, 45123, "user", "password")
        self.assertEqual(connection.sendall.call_args_list[0].args[0], b"\x05\x01\x02")
        self.assertIn(b"user", connection.sendall.call_args_list[1].args[0])
        connection.recv.side_effect = [b"\x05\x00"]
        with mock.patch.object(control.socket, "create_connection", return_value=connection), self.assertRaises(RuntimeError):
            control.wait_authenticated(proxy, 45123, "user", "password")

    def test_command_result_propagated_and_owned_proxy_cleaned(self):
        for result in (0, 7):
            with self.subTest(result=result):
                proxy = mock.Mock()
                proxy.poll.return_value = None
                child = mock.Mock(returncode=result)
                child.poll.return_value = result
                paths = []
                def check_engine(command, **kwargs):
                    path = Path(command[-1])
                    paths.append(path)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                    self.assertEqual(json.loads(path.read_text())["outbounds"][0]["bind_interface"], "en0")
                    return subprocess.CompletedProcess(command, 0)
                with mock.patch.object(control.subprocess, "run", side_effect=check_engine), mock.patch.object(control.subprocess, "Popen", side_effect=[proxy, child]) as popen, mock.patch.object(control, "wait_authenticated"):
                    self.assertEqual(control.run(["git", "status"]), result)
                proxy.terminate.assert_called_once()
                proxy.wait.assert_called_once()
                for call in popen.call_args_list:
                    self.assertFalse(call.kwargs.get("start_new_session", False))
                self.assertFalse(paths[0].exists())

    def test_cancellation_cleans_owned_proxy_before_command_start(self):
        proxy = mock.Mock()
        proxy.poll.return_value = None
        with mock.patch.object(control.subprocess, "run"), mock.patch.object(control.subprocess, "Popen", return_value=proxy) as popen, mock.patch.object(control, "wait_authenticated", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                control.run(["gh", "api", "rate_limit"])
        self.assertEqual(popen.call_count, 1)
        proxy.terminate.assert_called_once()
        proxy.wait.assert_called_once()

    def test_stuck_owned_proxy_is_killed_after_grace(self):
        proxy = mock.Mock()
        proxy.poll.return_value = None
        proxy.wait.side_effect = [subprocess.TimeoutExpired("owned proxy", 2), 0]
        control.stop_owned(proxy)
        proxy.terminate.assert_called_once()
        proxy.kill.assert_called_once()

    def test_exited_process_cleanup_race_does_not_touch_other_resources(self):
        proxy = mock.Mock()
        proxy.poll.return_value = None
        proxy.terminate.side_effect = ProcessLookupError
        control.stop_owned(proxy)
        proxy.kill.assert_not_called()

    def test_runner_wraps_only_darwin_control_plane_commands(self):
        spec = importlib.util.spec_from_file_location("scheduler_control_test", ROOT / "scripts/regional_scheduler.py")
        scheduler = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scheduler)
        for platform in ("darwin", "linux"):
            for command, eligible in ((["git", "status"], True), (["gh", "api", "rate_limit"], True), ([sys.executable, "scripts/local_probe.py", "--publish"], True), ([sys.executable, "scripts/update_exit_geoip.py"], False)):
                with self.subTest(platform=platform, command=command):
                    runner = scheduler.Runner(ROOT, time.monotonic() + 5)
                    process = mock.Mock(returncode=0)
                    process.poll.return_value = 0
                    with mock.patch.object(scheduler.sys, "platform", platform), mock.patch.object(scheduler.subprocess, "Popen", return_value=process) as popen, mock.patch.object(runner, "stop"):
                        self.assertEqual(runner.run(command, "wrapping test"), (0, ""))
                    arguments = popen.call_args.args[0]
                    self.assertEqual(str(ROOT / "scripts/control_plane.py") in arguments, platform == "darwin" and eligible)

    @unittest.skipUnless(shutil.which("sing-box"), "sing-box not installed")
    def test_real_engine_accepts_configuration_without_network_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(control.configuration(45123, "test-user", "test-password")))
            result = subprocess.run([shutil.which("sing-box"), "check", "-c", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 0, "sing-box rejected control-plane configuration")


if __name__ == "__main__":
    unittest.main()
