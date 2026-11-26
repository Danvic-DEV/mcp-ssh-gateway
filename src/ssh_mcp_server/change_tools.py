"""Change group: fixed-command tools that modify a server.

These are never part of the "readonly" profile. Every one needs confirm=True
(the same pattern execute_command uses), validates its arguments, and runs one
fixed command. Nothing here accepts a free-form command.

Tools: write_file, start_service, stop_service, restart_service, kill_process.

Optional setting: WRITE_PATH_ALLOWLIST (comma-separated folders) limits where
write_file may write. Unset keeps the documented behaviour (any absolute path
the SSH account may write to).
"""

import base64
import shlex
from typing import Mapping, Optional

from .hardening import Runner, _SERVICE_RE, _format, check_path, parse_allowlist

MAX_WRITE_BYTES = 256 * 1024
SIGNALS = ("TERM", "HUP", "INT", "KILL", "USR1", "USR2", "STOP", "CONT")
MAX_PID = 4194304  # Linux pid_max upper bound


def _bad(msg: str) -> str:
    return f"❌ {msg}"


def _needs_confirm(summary: str) -> str:
    return (f"⚠️  **CHANGE REQUIRES CONFIRMATION**\n\n{summary}\n\n"
            "**To proceed, call this tool again with confirm=True**")


def register_change_group(mcp, run: Runner, env: Optional[Mapping[str, str]] = None) -> None:
    """Register write_file, the service control tools and kill_process."""
    write_allow = parse_allowlist((env or {}).get("WRITE_PATH_ALLOWLIST"))

    def _sudo(use_sudo: bool) -> str:
        # -n: never wait for a password prompt, fail instead.
        return "sudo -n " if use_sudo else ""

    @mcp.tool()
    def write_file(hostname: str, path: str, content: str, confirm: bool = False,
                   use_sudo: bool = False) -> str:
        """Write a text file on the server (REQUIRES confirm=True).

        If the file already exists it is first copied to `<path>.gwbak.<unix time>`.
        When WRITE_PATH_ALLOWLIST is set, only those folders can be written
        (symlinks are resolved first).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            path: absolute file path
            content: the full new content (up to 262144 bytes)
            confirm: REQUIRED to actually write
            use_sudo: write through `sudo -n` (needs passwordless sudo)
        """
        if not isinstance(content, str):
            return _bad("content must be text.")
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            return _bad(f"content is too large (limit {MAX_WRITE_BYTES} bytes).")
        clean, err = check_path(run, hostname, path, write_allow, must_exist=False)
        if err:
            return err
        if not confirm:
            return _needs_confirm(
                f"Write {len(data)} bytes to `{clean}` on {hostname}"
                f"{' using sudo' if use_sudo else ''}. An existing file is backed up first.")
        s = _sudo(use_sudo)
        b64 = base64.b64encode(data).decode("ascii")
        script = (f'P={shlex.quote(clean)}; '
                  f'if [ -e "$P" ]; then {s}cp -p -- "$P" "$P.gwbak.$(date +%s)" || exit 1; fi; '
                  f'printf %s {b64} | base64 -d | {s}tee -- "$P" >/dev/null && echo written')
        return _format(hostname, f"Wrote {len(data)} bytes to {clean}",
                       run(hostname, f"sh -c {shlex.quote(script)}"))

    def _service(hostname: str, service: str, action: str, confirm: bool, use_sudo: bool) -> str:
        if not _SERVICE_RE.match(service or ""):
            return _bad("Invalid service name.")
        if not confirm:
            return _needs_confirm(f"{action.capitalize()} service `{service}` on {hostname}"
                                  f"{' using sudo' if use_sudo else ''}.")
        q = shlex.quote(service)
        result = run(hostname, f"{_sudo(use_sudo)}systemctl {action} {q}")
        state = run(hostname, f"systemctl is-active {q}")
        out = _format(hostname, f"{action.capitalize()} {service}", result)
        return out + f"\n**Now:** {(state[1] or state[2]).strip() or 'unknown'}"

    @mcp.tool()
    def start_service(hostname: str, service: str, confirm: bool = False, use_sudo: bool = False) -> str:
        """Start a systemd service (REQUIRES confirm=True).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            service: systemd unit name
            confirm: REQUIRED to actually run
            use_sudo: run through `sudo -n` (needs passwordless sudo)
        """
        return _service(hostname, service, "start", confirm, use_sudo)

    @mcp.tool()
    def stop_service(hostname: str, service: str, confirm: bool = False, use_sudo: bool = False) -> str:
        """Stop a systemd service (REQUIRES confirm=True).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            service: systemd unit name
            confirm: REQUIRED to actually run
            use_sudo: run through `sudo -n` (needs passwordless sudo)
        """
        return _service(hostname, service, "stop", confirm, use_sudo)

    @mcp.tool()
    def restart_service(hostname: str, service: str, confirm: bool = False, use_sudo: bool = False) -> str:
        """Restart a systemd service (REQUIRES confirm=True).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            service: systemd unit name
            confirm: REQUIRED to actually run
            use_sudo: run through `sudo -n` (needs passwordless sudo)
        """
        return _service(hostname, service, "restart", confirm, use_sudo)

    @mcp.tool()
    def kill_process(hostname: str, pid: int, signal: str = "TERM", confirm: bool = False,
                     use_sudo: bool = False) -> str:
        """Send a signal to one process by PID (REQUIRES confirm=True).

        Takes a PID only, never a name or pattern. PID 1 and below are refused.
        Without confirm=True it shows what the PID is and changes nothing.

        Args:
            hostname: Server hostname or IP (REQUIRED)
            pid: process id (2 or higher)
            signal: one of TERM, HUP, INT, KILL, USR1, USR2, STOP, CONT
            confirm: REQUIRED to actually send the signal
            use_sudo: run through `sudo -n` (needs passwordless sudo)
        """
        if isinstance(pid, bool) or not isinstance(pid, int) or not 2 <= pid <= MAX_PID:
            return _bad(f"pid must be a whole number between 2 and {MAX_PID}.")
        if signal not in SIGNALS:
            return _bad(f"signal must be one of: {', '.join(SIGNALS)}.")
        code, out, _ = run(hostname, f"ps -p {pid} -o pid,user,comm --no-headers")
        if code != 0 or not (out or "").strip():
            return _bad(f"No process with pid {pid} on {hostname}.")
        who = out.strip()
        if not confirm:
            return _needs_confirm(f"Send SIG{signal} to process `{who}` on {hostname}"
                                  f"{' using sudo' if use_sudo else ''}.")
        return _format(hostname, f"SIG{signal} to {who}",
                       run(hostname, f"{_sudo(use_sudo)}kill -{signal} {pid}"))
