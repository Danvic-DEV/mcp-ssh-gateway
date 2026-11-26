"""Opt-in hardening for mcp-ssh-gateway.

Everything here is OFF unless an environment variable turns it on, so a
deployment with none of these variables set behaves exactly as before.
The only default-visible addition is a small set of fixed, read-only tools.

Environment variables
---------------------
TOOL_PROFILE      "" / "full" (default): all tools.
                  "readonly": only the fixed read-only tools; execute_command
                  and test_ssh_connection are not exposed.
ENABLED_TOOLS     Comma-separated tool names. When set, only these tools are
                  exposed (intersected with the profile). Unknown names are an
                  error, so a typo cannot silently hide or expose a tool.
ALLOWED_HOSTS     Comma-separated hostnames/IPs. When set, any tool called
                  with another hostname is refused.
SCRUB_OUTPUT      "true" masks token-like strings in every tool's output.
REQUIRE_AUTH      "true" refuses to start unless AUTH_TOKEN is set.
"""

import functools
import logging
import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Tuple

log = logging.getLogger("ssh_mcp_server.hardening")

# Tools that stay available in the "readonly" profile.
READONLY_TOOLS = frozenset(
    {
        "get_server_info",
        "get_service_status",
        "tail_log",
        "check_port",
        "get_disk_usage",
        "list_failed_units",
        "list_containers",
        "read_file",
        "list_directory",
        "list_processes",
        "get_network_connections",
        "search_log",
    }
)

# Read-only tools that can only work on file paths. In the readonly profile they
# are not exposed unless READ_PATH_ALLOWLIST is set (fail closed).
PATH_ONLY_TOOLS = frozenset({"read_file", "list_directory"})

MAX_OUTPUT_CHARS = 20000
MAX_LOG_LINES = 500

_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:\-]{0,127}$")

# (code, stdout, stderr)
Runner = Callable[[str, str], Tuple[int, str, str]]


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _csv(value: Optional[str]) -> Optional[frozenset]:
    items = [i.strip() for i in (value or "").split(",") if i.strip()]
    return frozenset(items) if items else None


@dataclass(frozen=True)
class Policy:
    profile: str
    enabled_tools: Optional[frozenset]
    allowed_hosts: Optional[frozenset]
    scrub_output: bool
    require_auth: bool


def load_policy(env: Mapping[str, str]) -> Policy:
    profile = (env.get("TOOL_PROFILE") or "full").strip().lower()
    if profile not in {"full", "readonly"}:
        raise ValueError(f"Unknown TOOL_PROFILE {profile!r}; use 'full' or 'readonly'")
    return Policy(
        profile=profile,
        enabled_tools=_csv(env.get("ENABLED_TOOLS")),
        allowed_hosts=_csv(env.get("ALLOWED_HOSTS")),
        scrub_output=_truthy(env.get("SCRUB_OUTPUT")),
        require_auth=_truthy(env.get("REQUIRE_AUTH")),
    )


# --------------------------------------------------------------------------
# Output scrubbing
# --------------------------------------------------------------------------

_SCRUB_RULES = [
    # PEM private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    # key=value / key: value for secret-looking keys
    (re.compile(
        r"(?i)\b([A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api[_-]?key|apikey|"
        r"private[_-]?key|onboarding[_-]?key|authorization|credential)[A-Za-z0-9_.\-]*)"
        r"(\s*[=:]\s*)(?:Bearer\s+)?[^\s\"',;]+"),
     r"\1\2[REDACTED]"),
    # "Authorization: Bearer xxx" style
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{12,}"), "Bearer [REDACTED]"),
    # well-known token shapes
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "[REDACTED JWT]"),
    # credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s/:@]+):[^\s/@]+@"), r"\1:[REDACTED]@"),
]


def scrub(text: str) -> str:
    """Mask token-like strings. Best effort: it reduces leaks, it does not guarantee none."""
    for pattern, repl in _SCRUB_RULES:
        text = pattern.sub(repl, text)
    return text


# --------------------------------------------------------------------------
# Fixed read-only tools
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Path rules (shared by the file-based tools)
# --------------------------------------------------------------------------

def norm_path(path) -> Optional[str]:
    """Return a normalised absolute path, or None if the path is not acceptable.

    Rejects relative paths, '..' components, control characters and very long paths.
    """
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        return None
    if ".." in path.split("/"):
        return None
    return posixpath.normpath(path)


def parse_allowlist(value: Optional[str]) -> Optional[Tuple[str, ...]]:
    """Parse a comma-separated list of absolute path prefixes. None when unset."""
    items = []
    for raw in (value or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        n = norm_path(raw)
        if n is None:
            raise ValueError(f"Invalid path in allowlist: {raw!r}")
        items.append(n)
    return tuple(items) if items else None


def under_prefixes(path: str, prefixes: Tuple[str, ...]) -> bool:
    for p in prefixes:
        if p == "/" or path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


def check_path(run: "Runner", hostname: str, path, allowlist, *, must_exist: bool = True):
    """Validate a path against the allowlist.

    Returns (clean_path, None) on success or (None, error_message).
    With an allowlist, the path is resolved on the server first (following symlinks),
    so a symlink inside an allowed folder cannot point outside it.
    With no allowlist, only the basic path rules apply (documented default behaviour).
    """
    clean = norm_path(path)
    if clean is None:
        return None, "❌ Invalid path: it must be absolute, without '..' or control characters."
    if allowlist is None:
        return clean, None
    flag = "-e" if must_exist else "-m"
    code, out, _ = run(hostname, f"realpath {flag} -- {shlex.quote(clean)}")
    resolved = (out or "").strip()
    if code != 0 or not resolved:
        return None, "❌ Path not found or not resolvable."
    if not under_prefixes(resolved, allowlist):
        return None, "❌ Path is outside the allowed folders for this gateway."
    return clean, None


def _format(hostname: str, label: str, result: Tuple[int, str, str]) -> str:
    code, out, err = result
    text = (out or "").rstrip()
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS] + "\n... [truncated]"
    msg = f"**{label} on {hostname}** (exit {code})\n```\n{text}\n```"
    if err and err.strip():
        msg += f"\n**stderr:**\n```\n{err.strip()[:2000]}\n```"
    return msg


def path_policy(env: Optional[Mapping[str, str]]):
    """Return (read_allowlist, readonly_profile) from the environment."""
    env = env or {}
    return (
        parse_allowlist(env.get("READ_PATH_ALLOWLIST")),
        (env.get("TOOL_PROFILE") or "full").strip().lower() == "readonly",
    )


def register_read_tools(mcp, run: Runner, env: Optional[Mapping[str, str]] = None) -> None:
    """Register fixed read-only tools. Each runs one fixed command with validated arguments.

    `run(hostname, command)` executes a command over SSH and returns (code, stdout, stderr).
    No tool here accepts a free-form command, and none uses sudo.
    """
    read_allow, readonly = path_policy(env)

    def _bad(msg: str) -> str:
        return f"❌ {msg}"

    @mcp.tool()
    def get_service_status(hostname: str, service: str) -> str:
        """Show the status of a systemd service (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            service: systemd unit name, e.g. "docker" or "ssh.service"
        """
        if not _SERVICE_RE.match(service or ""):
            return _bad("Invalid service name.")
        cmd = f"systemctl status {shlex.quote(service)} --no-pager --lines=0"
        return _format(hostname, f"Status of {service}", run(hostname, cmd))

    @mcp.tool()
    def tail_log(hostname: str, service: str = None, lines: int = 100, path: str = None) -> str:
        """Show the last lines of a systemd unit's journal, or of a log file (read-only).

        Give exactly one of `service` or `path`.

        Args:
            hostname: Server hostname or IP (REQUIRED)
            service: systemd unit name (journal)
            lines: number of lines (1-500, default 100)
            path: absolute path of a log file (restricted by READ_PATH_ALLOWLIST when set)
        """
        if bool(service) == bool(path):
            return _bad("Give exactly one of service or path.")
        if not isinstance(lines, int) or not 1 <= lines <= MAX_LOG_LINES:
            return _bad(f"lines must be between 1 and {MAX_LOG_LINES}.")
        if service:
            if not _SERVICE_RE.match(service):
                return _bad("Invalid service name.")
            cmd = f"journalctl -u {shlex.quote(service)} -n {lines} --no-pager"
            return _format(hostname, f"Last {lines} log lines of {service}", run(hostname, cmd))
        if readonly and read_allow is None:
            return _bad("File paths are disabled in the readonly profile until READ_PATH_ALLOWLIST is set.")
        clean, err = check_path(run, hostname, path, read_allow)
        if err:
            return err
        cmd = f"tail -n {lines} -- {shlex.quote(clean)}"
        return _format(hostname, f"Last {lines} lines of {clean}", run(hostname, cmd))

    @mcp.tool()
    def check_port(hostname: str, port: int) -> str:
        """Show whether something is listening on a TCP port on the server (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
            port: TCP port number (1-65535)
        """
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return _bad("port must be between 1 and 65535.")
        cmd = f"ss -ltnH 'sport = :{port}'"
        code, out, err = run(hostname, cmd)
        state = "LISTENING" if (out or "").strip() else "nothing listening"
        return _format(hostname, f"Port {port}: {state}", (code, out, err))

    @mcp.tool()
    def get_disk_usage(hostname: str) -> str:
        """Show filesystem usage (df -h) (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
        """
        return _format(hostname, "Disk usage", run(hostname, "df -h -x tmpfs -x devtmpfs"))

    @mcp.tool()
    def list_failed_units(hostname: str) -> str:
        """List failed systemd units (read-only).

        Args:
            hostname: Server hostname or IP (REQUIRED)
        """
        return _format(hostname, "Failed units", run(hostname, "systemctl --failed --no-pager --no-legend"))

    @mcp.tool()
    def list_containers(hostname: str) -> str:
        """List Docker containers: name, image and status only (read-only).

        Needs the SSH account to be allowed to talk to Docker. Environment
        variables are never requested.

        Args:
            hostname: Server hostname or IP (REQUIRED)
        """
        fmt = shlex.quote("{{.Names}}\t{{.Image}}\t{{.Status}}")
        return _format(hostname, "Containers", run(hostname, f"docker ps -a --format {fmt}"))


# --------------------------------------------------------------------------
# Applying the policy
# --------------------------------------------------------------------------

def _registered_tools(mcp) -> dict:
    manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if tools is None:
        raise RuntimeError("Cannot reach the MCP tool registry; this mcp version is not supported by hardening.py")
    return tools


def _wrap(fn: Callable, policy: Policy) -> Callable:
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        host = kwargs.get("hostname")
        if policy.allowed_hosts is not None and host is not None and host not in policy.allowed_hosts:
            return "❌ Host not allowed by this gateway's ALLOWED_HOSTS."
        result = fn(*args, **kwargs)
        if policy.scrub_output and isinstance(result, str):
            result = scrub(result)
        return result

    return wrapper


def apply_policy(mcp, env: Mapping[str, str], auth_token: Optional[str]) -> Policy:
    """Apply the opt-in policy to the registered tools. With no variables set this changes nothing."""
    policy = load_policy(env)

    if policy.require_auth and not auth_token:
        raise RuntimeError("REQUIRE_AUTH is set but AUTH_TOKEN is empty; refusing to start without authentication.")
    if not auth_token:
        log.warning("AUTH_TOKEN is not set: anyone who can reach this gateway can use its tools.")

    tools = _registered_tools(mcp)

    allowed = set(tools)
    if policy.profile == "readonly":
        allowed &= READONLY_TOOLS
    if policy.enabled_tools is not None:
        unknown = policy.enabled_tools - set(tools)
        if unknown:
            raise ValueError(f"ENABLED_TOOLS names unknown tools: {', '.join(sorted(unknown))}")
        allowed &= policy.enabled_tools

    read_allow, _ = path_policy(env)  # also validates READ_PATH_ALLOWLIST at startup
    parse_allowlist(env.get("WRITE_PATH_ALLOWLIST"))
    if policy.profile == "readonly" and read_allow is None:
        for name in sorted(PATH_ONLY_TOOLS & set(tools)):
            if policy.enabled_tools is not None and name in policy.enabled_tools:
                raise ValueError(f"{name} in the readonly profile needs READ_PATH_ALLOWLIST to be set")
            if name in allowed:
                allowed.discard(name)
                log.warning("%s is not exposed: the readonly profile needs READ_PATH_ALLOWLIST for file paths.", name)

    for name in list(tools):
        if name not in allowed:
            del tools[name]

    if policy.allowed_hosts is not None or policy.scrub_output:
        for tool in tools.values():
            tool.fn = _wrap(tool.fn, policy)

    log.info("Tool policy: profile=%s tools=%s", policy.profile, ", ".join(sorted(tools)))
    return policy
