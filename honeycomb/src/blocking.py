"""Stage 3 - talk to the blocking host through the restricted SSH key.

The host only understands: block <ip> | unblock <ip> | verify <ip> | list
(see scripts/block_ip.sh). Nothing here builds a shell string: ssh gets an
argument list, and every value is checked before it is sent.
"""
import ipaddress
import os
import re
import subprocess

DEFAULT_HOST = "127.0.0.1"
DEFAULT_USER = "honeycomb-blocker"
DEFAULT_KEY = os.path.expanduser("~/.ssh/honeycomb_blocker")
SSH_OPTS = ["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10"]

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_BLOCKED = re.compile(
    r"^BLOCKED (\S+) timeout (\d+) packets (\d+) bytes (\d+)$")


class BlockingError(Exception):
    """The blocking host refused, or answered something unexpected."""


def _check_ip(ip):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(f"not a valid IPv4 address: {ip!r}") from None
    if str(addr) != ip:
        raise ValueError(f"not a valid IPv4 address: {ip!r}")
    return ip


def _check_name(value, what):
    if not _SAFE_NAME.match(value or ""):
        raise ValueError(f"unsafe {what}: {value!r}")
    return value


def _ask(command, host, key, user, port, runner):
    _check_name(host, "host")
    _check_name(user, "user")
    cmd = ["ssh", "-i", str(key), *SSH_OPTS, "-p", str(int(port)),
           "--", f"{user}@{host}", command]
    try:
        return runner(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BlockingError(f"could not reach {host}: {exc}") from exc


def verify_ip(ip, host=DEFAULT_HOST, key=DEFAULT_KEY, user=DEFAULT_USER,
              port=22, runner=subprocess.run):
    """Is this IP really in the block set? Returns the counter too."""
    ip = _check_ip(ip)
    result = _ask(f"verify {ip}", host, key, user, port, runner)
    out = result.stdout.strip()
    if result.returncode == 4 and out == f"NOT_BLOCKED {ip}":
        return {"ip": ip, "blocked": False, "expires_in": None,
                "packets": 0, "bytes": 0}
    match = _BLOCKED.match(out)
    if result.returncode == 0 and match and match.group(1) == ip:
        return {"ip": ip, "blocked": True, "expires_in": int(match.group(2)),
                "packets": int(match.group(3)), "bytes": int(match.group(4))}
    raise BlockingError(
        f"unexpected answer from {host}: code={result.returncode} "
        f"out={out!r} err={result.stderr.strip()!r}")


def _change(action, done_word, ip, host, key, user, port, runner):
    ip = _check_ip(ip)
    result = _ask(f"{action} {ip}", host, key, user, port, runner)
    out = result.stdout.strip()
    if result.returncode == 0 and out == f"{done_word} {ip}":
        return True
    raise BlockingError(
        f"{action} {ip} failed on {host}: code={result.returncode} "
        f"out={out!r} err={result.stderr.strip()!r}")


def block_ip(ip, host=DEFAULT_HOST, key=DEFAULT_KEY, user=DEFAULT_USER,
             port=22, runner=subprocess.run):
    """Add the IP to the block set. A whitelisted IP is refused by the host."""
    return _change("block", "BLOCKED", ip, host, key, user, port, runner)


def unblock_ip(ip, host=DEFAULT_HOST, key=DEFAULT_KEY, user=DEFAULT_USER,
               port=22, runner=subprocess.run):
    """Rollback: remove the IP from the block set."""
    return _change("unblock", "UNBLOCKED", ip, host, key, user, port, runner)
