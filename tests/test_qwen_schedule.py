"""Moscow due slots and owned launchd installation; never launches a real job."""
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from scripts import qwen_schedule as schedule
from scripts import install_qwen_discovery as installer


def epoch(iso):
    return datetime.fromisoformat(iso).timestamp()


NOW = epoch("2026-11-10T12:00:00+00:00")


class MoscowScheduleTests(unittest.TestCase):
    def test_before_at_after_due_slot_and_strictly_future_next(self):
        for current, date, due, next_due in (
            ("2026-11-10T03:00:59+03:00", "2026-11-09", "2026-11-09T03:01:00+03:00", "2026-11-10T03:01:00+03:00"),
            ("2026-11-10T03:01:00+03:00", "2026-11-10", "2026-11-10T03:01:00+03:00", "2026-11-11T03:01:00+03:00"),
            ("2026-11-10T23:59:59+03:00", "2026-11-10", "2026-11-10T03:01:00+03:00", "2026-11-11T03:01:00+03:00")):
            with self.subTest(current=current):
                self.assertEqual(schedule.latest_due_slot(epoch(current)), (date, epoch(due)))
                self.assertEqual(schedule.next_scheduled_at(epoch(current)), epoch(next_due))

    def test_year_and_leap_day_rollovers(self):
        for current, expected in (("2027-01-01T02:30:00+03:00", "2026-12-31"),
                                  ("2028-03-01T02:30:00+03:00", "2028-02-29"),
                                  ("2026-03-01T02:30:00+03:00", "2026-02-28")):
            with self.subTest(current=current):
                self.assertEqual(schedule.latest_due_slot(epoch(current))[0], expected)

    def test_machine_environment_timezone_cannot_change_moscow_due_slot(self):
        expected = schedule.latest_due_slot(NOW)
        for zone in ("America/New_York", "UTC", "Asia/Kolkata", "Pacific/Honolulu"):
            with self.subTest(zone=zone), patch.dict(os.environ, {"TZ": zone}):
                self.assertEqual(schedule.latest_due_slot(NOW), expected)
                self.assertEqual(schedule.next_scheduled_at(NOW), epoch("2026-11-11T00:01:00+00:00"))

    def test_calendar_conversion_includes_half_hour_quarter_hour_and_previous_day(self):
        for zone, hour, minute in (("Europe/Moscow", 3, 1), ("UTC", 0, 1),
                                   ("Asia/Kolkata", 5, 31), ("Asia/Kathmandu", 5, 46),
                                   ("Australia/Adelaide", 10, 31), ("Pacific/Honolulu", 14, 1)):
            with self.subTest(zone=zone):
                self.assertEqual(schedule.calendar_for_local_timezone(NOW, ZoneInfo(zone)), {"Hour": hour, "Minute": minute})

    def test_machine_dst_changes_calendar_hint_but_not_moscow_schedule(self):
        ny = ZoneInfo("America/New_York")
        for current, hour in (("2026-03-07T12:00:00+00:00", 19), ("2026-03-08T12:00:00+00:00", 20),
                              ("2026-10-31T12:00:00+00:00", 20), ("2026-11-01T12:00:00+00:00", 19)):
            with self.subTest(current=current):
                now = epoch(current)
                self.assertEqual(schedule.calendar_for_local_timezone(now, ny), {"Hour": hour, "Minute": 1})
                due = datetime.fromtimestamp(schedule.next_scheduled_at(now), schedule.MOSCOW)
                self.assertEqual((due.hour, due.minute), (3, 1))

    def test_late_wake_returns_latest_slot_only_instead_of_replaying_a_backlog(self):
        self.assertEqual(schedule.latest_due_slot(epoch("2026-11-17T18:00:00+03:00")),
                         ("2026-11-17", epoch("2026-11-17T03:01:00+03:00")))
        self.assertEqual(schedule.latest_due_slot(epoch("2026-11-18T01:00:00+03:00"))[0], "2026-11-17")

    def test_invalid_clocks_and_missing_explicit_timezone_fail_closed(self):
        for invalid in (True, None, "today", float("nan"), float("inf"), 10**1000):
            with self.subTest(value=type(invalid).__name__):
                for function in (schedule.latest_due_slot, schedule.next_scheduled_at):
                    with self.assertRaises(ValueError):
                        function(invalid)
        for zone in (None, "Europe/Moscow"):
            with self.assertRaises(ValueError):
                schedule.calendar_for_local_timezone(NOW, zone)


class QwenInstallerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name) / "home"
        self.home.mkdir()
        self.repo = Path(directory.name) / "existing-runtime"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / ".git").mkdir()
        (self.repo / "scripts/qwen_discovery.py").write_text("# controlled worker fixture\n")
        (self.repo / "scripts/qwen_schedule.py").write_text("# controlled schedule fixture\n")
        self.python = Path(sys.executable)
        self.path = self.home / "Library/LaunchAgents" / f"{installer.LABEL}.plist"

    def install(self, load=False):
        return installer.install(self.home, self.repo, self.python, load=load, now=NOW, tzinfo=ZoneInfo("UTC"))

    def completed(self, state="not running", code=0):
        return subprocess.CompletedProcess([], code, "state = " + state + "\n", "")

    def test_configuration_polls_authoritative_gate_and_does_not_keep_model_server_alive(self):
        value = installer.configuration(self.home, self.repo, self.python, now=NOW, tzinfo=ZoneInfo("UTC"))
        self.assertEqual(value["StartCalendarInterval"], {"Hour": 0, "Minute": 1})
        self.assertEqual(value["StartInterval"], 60)
        self.assertTrue(value["RunAtLoad"])
        self.assertNotIn("KeepAlive", value)
        self.assertEqual(value["Nice"], 10)
        self.assertEqual(value["ProgramArguments"], [str(self.python), str(self.repo / "scripts/qwen_discovery.py"),
            "--poll", "--repo", str(self.repo), "--state-dir", str(self.home / "Library/Application Support/best50-vpn/qwen")])
        self.assertNotIn("TZ", value["EnvironmentVariables"])

    def test_install_writes_private_plist_without_launch_or_model_operations(self):
        with patch.object(installer.subprocess, "run") as command:
            path = self.install()
        command.assert_not_called()
        value = plistlib.loads(path.read_bytes())
        self.assertEqual(value["Label"], installer.LABEL)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(value["StandardOutPath"].endswith("best50-vpn/qwen-discovery.log"))
        self.assertTrue(value["StandardErrorPath"].endswith("best50-vpn/qwen-discovery-error.log"))

    def test_installation_time_survives_updates_for_first_missed_slot_recovery(self):
        self.install()
        marker = self.home / "Library/Application Support/best50-vpn/qwen/installation.json"
        self.assertEqual(json.loads(marker.read_text())["installed_at"], NOW)
        installer.install(self.home, self.repo, self.python, now=NOW + 86400, tzinfo=ZoneInfo("UTC"))
        self.assertEqual(json.loads(marker.read_text())["installed_at"], NOW)

    def test_missing_worker_code_or_git_runtime_fails_before_installation(self):
        (self.repo / "scripts/qwen_discovery.py").unlink()
        with self.assertRaisesRegex(RuntimeError, "deploy"):
            self.install()
        self.assertFalse(self.path.exists())
        self.assertFalse((self.home / "Library/Application Support").exists())

    def test_existing_worker_lock_defers_duplicate_install_without_launchctl_changes(self):
        state = self.home / "Library/Application Support/best50-vpn/qwen"
        state.mkdir(parents=True)
        with (state / installer.LOCK_NAME).open("a+") as owned:
            fcntl.flock(owned, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(installer.subprocess, "run") as command:
                with self.assertRaisesRegex(RuntimeError, "owns its lock"):
                    self.install(load=True)
        command.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_running_own_job_is_never_stopped_or_rewritten(self):
        self.install()
        before = self.path.read_bytes()
        with patch.object(installer.subprocess, "run", return_value=self.completed("running")) as command:
            with self.assertRaisesRegex(RuntimeError, "active"):
                self.install(load=True)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][:2], ["launchctl", "print"])

    def test_unknown_transitioning_job_is_conservatively_not_reloaded(self):
        with patch.object(installer.subprocess, "run", return_value=self.completed("starting")) as command:
            with self.assertRaisesRegex(RuntimeError, "active"):
                self.install(load=True)
        self.assertEqual(command.call_count, 1)
        self.assertFalse(self.path.exists())

    def test_load_enables_only_this_idle_job_and_never_foreign_services(self):
        with patch.object(installer.subprocess, "run", return_value=self.completed()) as command:
            path = self.install(load=True)
        calls = [call.args[0] for call in command.call_args_list]
        domain = f"gui/{os.getuid()}"
        self.assertEqual(calls, [["launchctl", "print", f"{domain}/{installer.LABEL}"],
                                ["launchctl", "bootout", f"{domain}/{installer.LABEL}"],
                                ["launchctl", "enable", f"{domain}/{installer.LABEL}"],
                                ["launchctl", "bootstrap", domain, str(path)]])

    def test_new_job_bootstrap_does_not_bootout_any_existing_job(self):
        with patch.object(installer.subprocess, "run", side_effect=[self.completed(code=113), self.completed(), self.completed()]) as command:
            self.install(load=True)
        self.assertEqual([call.args[0][1] for call in command.call_args_list], ["print", "enable", "bootstrap"])

    def test_identical_loaded_job_is_enabled_without_unnecessary_reload(self):
        self.install()
        with patch.object(installer.subprocess, "run", return_value=self.completed()) as command:
            self.install(load=True)
        self.assertEqual([call.args[0][1] for call in command.call_args_list], ["print", "enable"])

    def test_launchctl_failure_is_explicit_and_does_not_modify_other_jobs(self):
        with patch.object(installer.subprocess, "run", side_effect=subprocess.TimeoutExpired("launchctl", 10)) as command:
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                self.install(load=True)
        self.assertEqual(command.call_count, 1)
        self.assertFalse(self.path.exists())

    def test_status_is_read_only_and_reports_next_moscow_and_utc_times(self):
        with patch.object(installer.subprocess, "run", return_value=self.completed(code=113)) as command:
            value = installer.status(self.home, now=NOW, tzinfo=ZoneInfo("Asia/Kolkata"))
        self.assertFalse(value["installed"])
        self.assertFalse(value["loaded"])
        self.assertEqual(value["next_run_utc"], "2026-11-11T00:01:00+00:00")
        self.assertEqual(value["next_run_moscow"], "2026-11-11T03:01:00+03:00")
        self.assertEqual(value["local_calendar_hint"], {"Hour": 5, "Minute": 31})
        self.assertFalse(self.path.exists())
        self.assertEqual(command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
