"""Fixed-command tools for mcp-ssh-gateway.

Each tool runs one fixed command with validated arguments: nothing here accepts a
free-form command or builds a shell pipeline from caller text.

Read group (safe for the "readonly" profile): read_file, list_directory,
list_processes, get_network_connections, search_log.
"""

import shlex
from typing import Mapping, Optional

from .hardening import (
    MAX_OUTPUT_CHARS,
    Runner,
    _SERVICE_RE,
    _format,
    check_path,
    path_policy,
)

MAX_READ_BYTES = 1024 * 1024
DEFAULT_READ_BYTES = 64 * 1024
MAX_PATTERN_CHARS = 200
MAX_MATCHES = 500


def _bad(msg: str) -> str:
    return f"❌ {msg}"


def register_read_group(mcp, run: Runner, env: Optional[Mapping[str, str]] = None) -> None:
    """Register the read-only file, process, network and search tools."""
    read_allow, readonly = path_policy(env)

    def _paths_disabled() -> Optional[str]:
        if readonly and read_allow is None:
            return _bad("File paths are disabled in the readonly profile until READ_PATH_ALLOWLIST is set.")
        return None

    @mcp.tool()
    def read_file(hostname: str, path: str, max_bytes: int = DEFAULT_READ_BYTES) -> str:
        """Read the start of a text file (read-only).

        When READ_PATH_ALLOWLIST is set, only files under those folders can be read
        (symlinks are resolved first).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            path: absolute file path
            max_bytes: how much to read (1 to 1048576, default 65536)
        """
        refused = _paths_disabled()
        if refused:
            return refused
        if not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_READ_BYTES:
            return _bad(f"max_bytes must be between 1 and {MAX_READ_BYTES}.")
        clean, err = check_path(run, hostname, path, read_allow)
        if err:
            return err
        return _format(hostname, f"First {max_bytes} bytes of {clean}",
                       run(hostname, f"head -c {max_bytes} -- {shlex.quote(clean)}"))

    @mcp.tool()
    def list_directory(hostname: str, path: str = "/") -> str:
        """List a directory with sizes and times (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            path: absolute directory path (default "/")
        """
        refused = _paths_disabled()
        if refused:
            return refused
        clean, err = check_path(run, hostname, path, read_allow)
        if err:
            return err
        return _format(hostname, f"Directory {clean}",
                       run(hostname, f"ls -la --time-style=long-iso -- {shlex.quote(clean)}"))

    @mcp.tool()
    def list_processes(hostname: str, sort_by: str = "cpu", limit: int = 25) -> str:
        """List the busiest processes: pid, user, cpu, memory, running time and name (read-only).

        Only the process name is shown, not its command line, so arguments that
        contain secrets are not exposed.

        Args:
            hostname: Server hostname or IP (REQUIRED)
            sort_by: "cpu" or "mem"
            limit: how many processes (1-100, default 25)
        """
        if sort_by not in ("cpu", "mem"):
            return _bad('sort_by must be "cpu" or "mem".')
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            return _bad("limit must be between 1 and 100.")
        key = "pcpu" if sort_by == "cpu" else "pmem"
        cmd = f"ps -eo pid,user,pcpu,pmem,etime,comm --sort=-{key} | head -n {limit + 1}"
        return _format(hostname, f"Top {limit} processes by {sort_by}", run(hostname, cmd))

    @mcp.tool()
    def get_network_connections(hostname: str, state: str = "listening") -> str:
        """Show TCP/UDP sockets (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            state: "listening", "established" or "all"
        """
        cmds = {
            "listening": "ss -tulnH",
            "established": "ss -tnH state established",
            "all": "ss -tunaH",
        }
        if state not in cmds:
            return _bad('state must be "listening", "established" or "all".')
        return _format(hostname, f"Network connections ({state})", run(hostname, cmds[state]))

    @mcp.tool()
    def search_log(hostname: str, pattern: str, service: str = None, path: str = None,
                   max_matches: int = 100) -> str:
        """Search a systemd unit's journal or a log file for a fixed text (case-insensitive, read-only).

        Give exactly one of `service` or `path`. The pattern is plain text, not a regex.

        Args:
            hostname: Server hostname or IP (REQUIRED)
            pattern: text to look for (1-200 characters, no line breaks)
            service: systemd unit name (searches the last 20000 journal lines)
            path: absolute log file path (restricted by READ_PATH_ALLOWLIST when set)
            max_matches: stop after this many matches (1-500, default 100)
        """
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_PATTERN_CHARS \
                or any(c in pattern for c in "\n\r\x00"):
            return _bad(f"pattern must be 1-{MAX_PATTERN_CHARS} characters with no line breaks.")
        if not isinstance(max_matches, int) or not 1 <= max_matches <= MAX_MATCHES:
            return _bad(f"max_matches must be between 1 and {MAX_MATCHES}.")
        if bool(service) == bool(path):
            return _bad("Give exactly one of service or path.")
        q = shlex.quote(pattern)
        if service:
            if not _SERVICE_RE.match(service):
                return _bad("Invalid service name.")
            cmd = (f"journalctl -u {shlex.quote(service)} -n 20000 --no-pager | "
                   f"grep -F -i -m {max_matches} -e {q}")
            code, out, err = run(hostname, cmd)
            label = f"Matches for {pattern!r} in {service}"
        else:
            refused = _paths_disabled()
            if refused:
                return refused
            clean, perr = check_path(run, hostname, path, read_allow)
            if perr:
                return perr
            code, out, err = run(hostname, f"grep -F -i -n -m {max_matches} -e {q} -- {shlex.quote(clean)}")
            label = f"Matches for {pattern!r} in {clean}"
        if code == 1 and not (out or "").strip():
            label += " (no matches)"
        return _format(hostname, label, (code, out, err))
