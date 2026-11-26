"""Tests for the change group (write_file, service control, kill_process)."""

import base64
import os
import re
import shlex
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_hardening import FakeRunner, build, server_tools  # noqa: E402
from test_read_group import RealpathRunner  # noqa: E402

CHANGE_TOOLS = {"write_file", "start_service", "stop_service", "restart_service", "kill_process"}


class Exposure(unittest.TestCase):
    def test_present_in_default_profile(self):
        names, rc, err = server_tools()
        self.assertEqual(rc, 0, err)
        self.assertTrue(CHANGE_TOOLS <= names)

    def test_never_in_readonly_profile(self):
        names, _, _ = server_tools(TOOL_PROFILE="readonly", READ_PATH_ALLOWLIST="/var/log")
        self.assertFalse(CHANGE_TOOLS & names)

    def test_readonly_cannot_be_widened_by_enabled_tools(self):
        names, _, _ = server_tools(TOOL_PROFILE="readonly", ENABLED_TOOLS="write_file,kill_process,check_port")
        self.assertEqual(names, {"check_port"})


class ConfirmGate(unittest.TestCase):
    def test_nothing_runs_without_confirm(self):
        _, runner, tools = build({})
        self.assertIn("REQUIRES CONFIRMATION", tools["write_file"].fn("h", "/tmp/x", "hi"))
        for name in ("start_service", "stop_service", "restart_service"):
            self.assertIn("REQUIRES CONFIRMATION", tools[name].fn("h", "docker"))
        self.assertEqual(runner.calls, [])

    def test_kill_without_confirm_only_looks_up_the_process(self):
        _, runner, tools = build({}, FakeRunner((0, "  4242 rich  python\n", "")))
        out = tools["kill_process"].fn("h", 4242)
        self.assertIn("REQUIRES CONFIRMATION", out)
        self.assertIn("python", out)
        self.assertEqual([c[1] for c in runner.calls], ["ps -p 4242 -o pid,user,comm --no-headers"])


class ServiceTools(unittest.TestCase):
    def test_commands(self):
        _, runner, tools = build({}, FakeRunner((0, "active\n", "")))
        for name, action in (("start_service", "start"), ("stop_service", "stop"), ("restart_service", "restart")):
            runner.calls.clear()
            out = tools[name].fn("h", "docker.service", True)
            self.assertEqual(runner.calls[0][1], f"systemctl {action} docker.service")
            self.assertEqual(runner.calls[1][1], "systemctl is-active docker.service")
            self.assertIn("**Now:** active", out)

    def test_sudo_uses_non_interactive_flag(self):
        _, runner, tools = build({})
        tools["restart_service"].fn("h", "docker", True, True)
        self.assertEqual(runner.calls[0][1], "sudo -n systemctl restart docker")

    def test_bad_names_rejected_before_anything_runs(self):
        _, runner, tools = build({})
        for bad in ["a; rm -rf /", "$(id)", "a b", "", "-x", "a" * 200]:
            for name in ("start_service", "stop_service", "restart_service"):
                self.assertIn("Invalid service name", tools[name].fn("h", bad, True))
        self.assertEqual(runner.calls, [])


class KillProcess(unittest.TestCase):
    def test_pid_and_signal_validation(self):
        _, runner, tools = build({})
        for bad in [0, 1, -5, 5000000, "12", "1;id", True, None, 12.5]:
            self.assertIn("pid must be", tools["kill_process"].fn("h", bad, "TERM", True))
        for bad in ["term", "9", "TERM; id", "", "SEGV"]:
            self.assertIn("signal must be", tools["kill_process"].fn("h", 4242, bad, True))
        self.assertEqual(runner.calls, [])

    def test_confirmed_kill_command(self):
        _, runner, tools = build({}, FakeRunner((0, "4242 rich python\n", "")))
        tools["kill_process"].fn("h", 4242, "HUP", True)
        self.assertEqual(runner.calls[-1][1], "kill -HUP 4242")
        tools["kill_process"].fn("h", 4242, "KILL", True, True)
        self.assertEqual(runner.calls[-1][1], "sudo -n kill -KILL 4242")

    def test_missing_process(self):
        _, runner, tools = build({}, FakeRunner((1, "", "")))
        self.assertIn("No process", tools["kill_process"].fn("h", 4242, "TERM", True))
        self.assertEqual(len(runner.calls), 1)


class WriteFile(unittest.TestCase):
    def script(self, runner):
        cmd = runner.calls[-1][1]
        parts = shlex.split(cmd)
        self.assertEqual(parts[:2], ["sh", "-c"])
        return parts[2]

    def test_content_is_carried_as_base64_only(self):
        content = "line1\n'quoted' \"double\" $(id) `id`; rm -rf / é✓\n"
        _, runner, tools = build({})
        tools["write_file"].fn("h", "/etc/app.conf", content, True)
        script = self.script(runner)
        self.assertNotIn("rm -rf", script)
        self.assertNotIn("$(id)", script)
        b64 = re.search(r"printf %s (\S+) \| base64 -d", script).group(1)
        self.assertEqual(base64.b64decode(b64).decode("utf-8"), content)

    def test_path_is_quoted_and_existing_file_backed_up(self):
        _, runner, tools = build({})
        tools["write_file"].fn("h", "/tmp/a b; rm -rf x", "z", True)
        script = self.script(runner)
        self.assertTrue(script.startswith("P='/tmp/a b; rm -rf x'; "))
        self.assertIn('cp -p -- "$P" "$P.gwbak.$(date +%s)"', script)
        self.assertNotIn("sudo", script)

    def test_sudo_applies_to_backup_and_write(self):
        _, runner, tools = build({})
        tools["write_file"].fn("h", "/etc/x", "z", True, True)
        script = self.script(runner)
        self.assertIn("sudo -n cp -p", script)
        self.assertIn("sudo -n tee", script)

    def test_validation(self):
        _, runner, tools = build({})
        self.assertIn("Invalid path", tools["write_file"].fn("h", "relative", "z", True))
        self.assertIn("Invalid path", tools["write_file"].fn("h", "/etc/../x", "z", True))
        self.assertIn("too large", tools["write_file"].fn("h", "/tmp/x", "a" * (256 * 1024 + 1), True))
        self.assertIn("must be text", tools["write_file"].fn("h", "/tmp/x", b"bytes", True))
        self.assertEqual(runner.calls, [])

    def test_write_allowlist_blocks_outside_and_symlink_escape(self):
        runner = RealpathRunner({"/srv/app/new.conf": "/srv/app/new.conf", "/srv/app/link": "/etc/passwd",
                                 "/etc/passwd": "/etc/passwd"})
        _, runner, tools = build({"WRITE_PATH_ALLOWLIST": "/srv/app"}, runner)
        self.assertIn("Wrote 1 bytes", tools["write_file"].fn("h", "/srv/app/new.conf", "z", True))
        self.assertIn("outside the allowed", tools["write_file"].fn("h", "/srv/app/link", "z", True))
        self.assertIn("outside the allowed", tools["write_file"].fn("h", "/etc/passwd", "z", True))
        wrote = [c for c in runner.calls if c[1].startswith("sh -c")]
        self.assertEqual(len(wrote), 1)

    def test_bad_write_allowlist_stops_startup(self):
        _, rc, err = server_tools(WRITE_PATH_ALLOWLIST="not/absolute")
        self.assertNotEqual(rc, 0)
        self.assertIn("Invalid path in allowlist", err)


if __name__ == "__main__":
    unittest.main()
