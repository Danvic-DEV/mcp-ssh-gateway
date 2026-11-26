"""Tests for the read group and the shared path rules."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_hardening import FakeRunner, build  # noqa: E402
from ssh_mcp_server import hardening  # noqa: E402


class RealpathRunner(FakeRunner):
    """Fake runner that answers `realpath` from a map and records everything else."""

    def __init__(self, resolve=None):
        super().__init__()
        self.resolve = resolve or {}

    def __call__(self, hostname, command):
        self.calls.append((hostname, command))
        if command.startswith("realpath"):
            for src, dst in self.resolve.items():
                if command.endswith(f"-- {src}"):
                    return 0, dst + "\n", ""
            return 1, "", "no such file"
        return 0, "ok", ""


class PathRules(unittest.TestCase):
    def test_norm_path_rejects_bad_paths(self):
        for bad in ["relative", "/a/../etc", "/a\nb", "/a\x00b", "", None, "/" + "a" * 2000]:
            self.assertIsNone(hardening.norm_path(bad), repr(bad))
        self.assertEqual(hardening.norm_path("/var//log/"), "/var/log")

    def test_prefix_match_is_by_folder_not_by_text(self):
        self.assertTrue(hardening.under_prefixes("/var/log/syslog", ("/var/log",)))
        self.assertTrue(hardening.under_prefixes("/var/log", ("/var/log",)))
        self.assertFalse(hardening.under_prefixes("/var/logs/x", ("/var/log",)))
        self.assertFalse(hardening.under_prefixes("/etc/passwd", ("/var/log",)))

    def test_without_allowlist_only_basic_rules_apply(self):
        _, runner, tools = build({})
        self.assertIn("ok", tools["read_file"].fn("h", "/etc/hostname"))
        self.assertEqual(runner.calls[-1][1], "head -c 65536 -- /etc/hostname")
        self.assertIn("Invalid path", tools["read_file"].fn("h", "../etc/passwd"))
        self.assertIn("Invalid path", tools["read_file"].fn("h", "/var/log/../../etc/shadow"))

    def test_allowlist_blocks_outside_and_symlink_escape(self):
        runner = RealpathRunner({"/var/log/app.log": "/var/log/app.log",
                                 "/var/log/sneaky": "/etc/shadow"})
        _, runner, tools = build({"READ_PATH_ALLOWLIST": "/var/log"}, runner)
        self.assertIn("ok", tools["read_file"].fn("h", "/var/log/app.log"))
        self.assertIn("outside the allowed", tools["read_file"].fn("h", "/var/log/sneaky"))
        self.assertIn("not found", tools["read_file"].fn("h", "/var/log/missing"))
        self.assertIn("outside the allowed", tools["list_directory"].fn("h", "/var/log/sneaky"))
        self.assertFalse(any(c[1].startswith("head") and "sneaky" in c[1] for c in runner.calls))

    def test_tail_log_path_mode_uses_same_rules(self):
        runner = RealpathRunner({"/var/log/app.log": "/var/log/app.log", "/etc/passwd": "/etc/passwd"})
        _, runner, tools = build({"READ_PATH_ALLOWLIST": "/var/log"}, runner)
        self.assertIn("ok", tools["tail_log"].fn("h", None, 20, "/var/log/app.log"))
        self.assertEqual(runner.calls[-1][1], "tail -n 20 -- /var/log/app.log")
        self.assertIn("outside the allowed", tools["tail_log"].fn("h", None, 20, "/etc/passwd"))
        self.assertIn("exactly one", tools["tail_log"].fn("h", "docker", 20, "/var/log/app.log"))
        self.assertIn("exactly one", tools["tail_log"].fn("h"))

    def test_tail_log_journal_mode_still_works_and_is_positional_compatible(self):
        _, runner, tools = build({})
        tools["tail_log"].fn("h", "docker", 50)
        self.assertEqual(runner.calls[-1][1], "journalctl -u docker -n 50 --no-pager")

    def test_readonly_tool_refuses_paths_without_allowlist_even_if_called_directly(self):
        _, runner, tools = build({"TOOL_PROFILE": "readonly"})
        self.assertIn("disabled in the readonly profile", tools["tail_log"].fn("h", None, 10, "/var/log/x"))
        self.assertIn("disabled in the readonly profile", tools["search_log"].fn("h", "x", None, "/var/log/x"))
        self.assertEqual(runner.calls, [])


class ReadGroupTools(unittest.TestCase):
    def test_list_processes(self):
        _, runner, tools = build({})
        tools["list_processes"].fn("h", "mem", 10)
        self.assertEqual(runner.calls[-1][1], "ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pmem | head -n 11")
        self.assertIn("sort_by", tools["list_processes"].fn("h", "cpu; id", 10))
        self.assertIn("limit", tools["list_processes"].fn("h", "cpu", 0))
        self.assertIn("limit", tools["list_processes"].fn("h", "cpu", 1000))

    def test_command_line_arguments_are_never_requested(self):
        _, runner, tools = build({})
        tools["list_processes"].fn("h")
        self.assertNotIn(",args", runner.calls[-1][1])
        self.assertNotIn("cmd", runner.calls[-1][1])

    def test_network_connections(self):
        _, runner, tools = build({})
        tools["get_network_connections"].fn("h", "established")
        self.assertEqual(runner.calls[-1][1], "ss -tnH state established")
        self.assertIn("state must be", tools["get_network_connections"].fn("h", "x; id"))

    def test_search_log_validation_and_quoting(self):
        _, runner, tools = build({})
        for bad in ["", "a\nb", "x" * 201]:
            self.assertIn("pattern must be", tools["search_log"].fn("h", bad, "docker"))
        self.assertIn("exactly one", tools["search_log"].fn("h", "err"))
        self.assertIn("Invalid service", tools["search_log"].fn("h", "err", "a;b"))
        self.assertEqual(runner.calls, [])
        tools["search_log"].fn("h", "$(id); rm -rf /", "docker", None, 5)
        cmd = runner.calls[-1][1]
        self.assertTrue(cmd.startswith("journalctl -u docker -n 20000 --no-pager | grep -F -i -m 5 -e "))
        self.assertIn("'$(id); rm -rf /'", cmd)

    def test_search_log_no_matches_label(self):
        _, _, tools = build({}, FakeRunner((1, "", "")))
        self.assertIn("no matches", tools["search_log"].fn("h", "zzz", "docker"))


if __name__ == "__main__":
    unittest.main()
