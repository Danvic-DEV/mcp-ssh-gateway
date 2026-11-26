"""Tests for the opt-in hardening. Run from the repo root:

    python -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import unittest

from mcp.server.fastmcp import FastMCP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from ssh_mcp_server import fixed_tools, hardening  # noqa: E402

ORIGINAL_TOOLS = {"test_ssh_connection", "get_server_info", "execute_command"}
NEW_READ_TOOLS = {
    "get_service_status", "tail_log", "check_port",
    "get_disk_usage", "list_failed_units", "list_containers",
    "read_file", "list_directory", "list_processes", "get_network_connections", "search_log",
}

_PROBE = (
    "import json; from ssh_mcp_server import server; "
    "print('TOOLS=' + json.dumps(sorted(server.mcp._tool_manager._tools)))"
)


def server_tools(**env):
    """Import the real server in a clean process with the given env; return (tool_names, returncode, stderr)."""
    base = {k: v for k, v in os.environ.items()
            if k not in {"TOOL_PROFILE", "ENABLED_TOOLS", "ALLOWED_HOSTS", "SCRUB_OUTPUT",
                         "REQUIRE_AUTH", "AUTH_TOKEN"}}
    base.update(env)
    base["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-W", "ignore", "-c", _PROBE], env=base,
                       capture_output=True, text=True, cwd=ROOT)
    names = None
    for line in p.stdout.splitlines():
        if line.startswith("TOOLS="):
            names = set(json.loads(line[6:]))
    return names, p.returncode, p.stderr


class DefaultsUnchanged(unittest.TestCase):
    def test_original_tools_all_present_by_default(self):
        names, rc, err = server_tools()
        self.assertEqual(rc, 0, err)
        self.assertTrue(ORIGINAL_TOOLS <= names)

    def test_new_read_tools_are_added_by_default(self):
        names, _, _ = server_tools()
        self.assertTrue(NEW_READ_TOOLS <= names)

    def test_explicit_full_profile_equals_default(self):
        a, _, _ = server_tools()
        b, _, _ = server_tools(TOOL_PROFILE="full")
        self.assertEqual(a, b)


class Profiles(unittest.TestCase):
    def test_readonly_hides_execute_and_test_connection(self):
        names, rc, err = server_tools(TOOL_PROFILE="readonly")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("execute_command", names)
        self.assertNotIn("test_ssh_connection", names)
        # file-path-only tools stay hidden until READ_PATH_ALLOWLIST is set (fail closed)
        self.assertEqual(names, hardening.READONLY_TOOLS - hardening.PATH_ONLY_TOOLS)

    def test_readonly_with_allowlist_exposes_path_tools(self):
        names, rc, err = server_tools(TOOL_PROFILE="readonly", READ_PATH_ALLOWLIST="/var/log")
        self.assertEqual(rc, 0, err)
        self.assertEqual(names, hardening.READONLY_TOOLS)

    def test_readonly_naming_path_tool_without_allowlist_fails_closed(self):
        _, rc, err = server_tools(TOOL_PROFILE="readonly", ENABLED_TOOLS="read_file")
        self.assertNotEqual(rc, 0)
        self.assertIn("READ_PATH_ALLOWLIST", err)

    def test_bad_allowlist_entry_stops_startup(self):
        _, rc, err = server_tools(READ_PATH_ALLOWLIST="relative/path")
        self.assertNotEqual(rc, 0)
        self.assertIn("Invalid path in allowlist", err)

    def test_enabled_tools_restricts(self):
        names, rc, err = server_tools(ENABLED_TOOLS="get_server_info,check_port")
        self.assertEqual(rc, 0, err)
        self.assertEqual(names, {"get_server_info", "check_port"})

    def test_enabled_tools_cannot_widen_readonly(self):
        names, _, _ = server_tools(TOOL_PROFILE="readonly", ENABLED_TOOLS="execute_command,check_port")
        self.assertEqual(names, {"check_port"})

    def test_unknown_tool_name_fails_closed(self):
        _, rc, err = server_tools(ENABLED_TOOLS="execute_comand")
        self.assertNotEqual(rc, 0)
        self.assertIn("unknown tools", err)

    def test_unknown_profile_fails_closed(self):
        _, rc, err = server_tools(TOOL_PROFILE="readonlyy")
        self.assertNotEqual(rc, 0)
        self.assertIn("Unknown TOOL_PROFILE", err)


class RequireAuth(unittest.TestCase):
    def test_refuses_without_token(self):
        _, rc, err = server_tools(REQUIRE_AUTH="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("REQUIRE_AUTH", err)

    def test_starts_with_token(self):
        names, rc, err = server_tools(REQUIRE_AUTH="true", AUTH_TOKEN="x" * 24)
        self.assertEqual(rc, 0, err)
        self.assertTrue(ORIGINAL_TOOLS <= names)

    def test_unset_still_starts(self):
        _, rc, err = server_tools()
        self.assertEqual(rc, 0, err)


class Scrubbing(unittest.TestCase):
    def test_masks_secrets(self):
        samples = [
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "password: hunter2",
            "Authorization: Bearer abcdefghijklmnop1234567890",
            "PERIPHERY_ONBOARDING_KEY=O-abc123def456",
            "url=https://user:s3cret@example.com/path",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        ]
        for s in samples:
            out = hardening.scrub(s)
            for secret in ("ghp_abc", "hunter2", "abcdefghijklmnop1234567890", "O-abc123",
                           "s3cret", "OPENSSH PRIVATE KEY-----\nabc", "eyJzdWIi"):
                self.assertNotIn(secret, out, f"{secret!r} leaked from {s!r}")

    def test_leaves_normal_text_alone(self):
        text = "nginx.service - A high performance web server\n   Active: active (running) since Mon"
        self.assertEqual(hardening.scrub(text), text)


class FakeRunner:
    def __init__(self, result=(0, "ok", "")):
        self.calls, self.result = [], result

    def __call__(self, hostname, command):
        self.calls.append((hostname, command))
        return self.result


def build(env, runner=None, auth="tok"):
    mcp = FastMCP("test")

    @mcp.tool()
    def get_server_info(hostname: str) -> str:
        return f"info {hostname} password=hunter2"

    @mcp.tool()
    def execute_command(command: str, hostname: str) -> str:
        return "ran"

    runner = runner or FakeRunner()
    hardening.register_read_tools(mcp, runner, env)
    fixed_tools.register_read_group(mcp, runner, env)
    hardening.apply_policy(mcp, env, auth)
    return mcp, runner, mcp._tool_manager._tools


class ReadTools(unittest.TestCase):
    def test_service_name_injection_rejected(self):
        _, runner, tools = build({})
        for bad in ["ssh; rm -rf /", "a b", "$(id)", "`id`", "x|y", "", "-flag", "a" * 200]:
            self.assertIn("Invalid service name", tools["get_service_status"].fn("h", bad))
            self.assertRegex(tools["tail_log"].fn("h", bad), "Invalid service name|exactly one")
        self.assertEqual(runner.calls, [])

    def test_commands_are_fixed_and_quoted(self):
        _, runner, tools = build({})
        tools["get_service_status"].fn("h", "docker.service")
        tools["tail_log"].fn("h", "docker", 50)
        tools["check_port"].fn("h", 8123)
        self.assertEqual(runner.calls[0][1], "systemctl status docker.service --no-pager --lines=0")
        self.assertEqual(runner.calls[1][1], "journalctl -u docker -n 50 --no-pager")
        self.assertEqual(runner.calls[2][1], "ss -ltnH 'sport = :8123'")

    def test_bounds(self):
        _, runner, tools = build({})
        self.assertIn("lines must be", tools["tail_log"].fn("h", "docker", 0))
        self.assertIn("lines must be", tools["tail_log"].fn("h", "docker", 100000))
        self.assertIn("port must be", tools["check_port"].fn("h", 0))
        self.assertIn("port must be", tools["check_port"].fn("h", 70000))
        self.assertEqual(runner.calls, [])


class HostsAndScrubWrapper(unittest.TestCase):
    def test_allowed_hosts(self):
        _, runner, tools = build({"ALLOWED_HOSTS": "10.0.0.1, host02"})
        self.assertIn("not allowed", tools["get_server_info"].fn(hostname="10.9.9.9"))
        self.assertIn("info host02", tools["get_server_info"].fn(hostname="host02"))
        self.assertIn("not allowed", tools["get_disk_usage"].fn(hostname="evil"))
        self.assertEqual(runner.calls, [])

    def test_no_allowed_hosts_means_any(self):
        _, _, tools = build({})
        self.assertIn("info anything", tools["get_server_info"].fn(hostname="anything"))

    def test_scrub_wraps_every_tool(self):
        _, _, tools = build({"SCRUB_OUTPUT": "true"})
        out = tools["get_server_info"].fn(hostname="h")
        self.assertNotIn("hunter2", out)
        self.assertIn("[REDACTED]", out)

    def test_scrub_off_by_default(self):
        _, _, tools = build({})
        self.assertIn("hunter2", tools["get_server_info"].fn(hostname="h"))


class ThroughMcpCallPath(unittest.TestCase):
    """The wrapped tools must work through FastMCP's real call path, not only when called directly."""

    def test_wrapped_tools_via_call_tool(self):
        import asyncio

        mcp, _, _ = build({"SCRUB_OUTPUT": "true", "ALLOWED_HOSTS": "h1"})

        async def go():
            ok = await mcp.call_tool("get_server_info", {"hostname": "h1"})
            denied = await mcp.call_tool("get_server_info", {"hostname": "other"})
            return ok, denied

        ok, denied = asyncio.run(go())
        flat = lambda r: json.dumps(r, default=str)
        self.assertIn("[REDACTED]", flat(ok))
        self.assertNotIn("hunter2", flat(ok))
        self.assertIn("not allowed", flat(denied))


if __name__ == "__main__":
    unittest.main()
