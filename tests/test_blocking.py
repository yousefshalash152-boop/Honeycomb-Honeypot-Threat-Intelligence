"""Stage 3 - the verify/block/unblock client for the restricted-key host.

No network: a fake runner stands in for ssh and records what it was asked.
"""
from types import SimpleNamespace

import pytest

from honeycomb.src.blocking import (BlockingError, block_ip, unblock_ip,
                                    verify_ip)


def fake_ssh(returncode, stdout="", stderr=""):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=returncode, stdout=stdout,
                               stderr=stderr)

    runner.calls = calls
    return runner


def test_verify_blocked_returns_the_counter():
    runner = fake_ssh(0, "BLOCKED 10.77.0.2 timeout 604763 packets 5 bytes 300\n")
    result = verify_ip("10.77.0.2", runner=runner)
    assert result == {"ip": "10.77.0.2", "blocked": True,
                      "expires_in": 604763, "packets": 5, "bytes": 300}


def test_verify_not_blocked():
    runner = fake_ssh(4, "NOT_BLOCKED 10.77.0.2\n")
    result = verify_ip("10.77.0.2", runner=runner)
    assert result["blocked"] is False and result["packets"] == 0


def test_verify_sends_one_argument_list_and_no_shell_string():
    runner = fake_ssh(4, "NOT_BLOCKED 10.77.0.2\n")
    verify_ip("10.77.0.2", host="blocker.example", user="honeycomb-blocker",
              runner=runner)
    cmd = runner.calls[0]
    assert isinstance(cmd, list)
    assert cmd[-1] == "verify 10.77.0.2"
    assert cmd[-2] == "honeycomb-blocker@blocker.example"
    assert cmd[-3] == "--"


@pytest.mark.parametrize("bad", [
    "10.77.0.2; ls", "10.77.0.2 && id", "999.1.1.1", "010.1.1.1", "", "a.b.c.d",
    "10.77.0.2\nblock 8.8.8.8",
])
def test_bad_ip_is_rejected_before_ssh_runs(bad):
    runner = fake_ssh(0, "")
    with pytest.raises(ValueError):
        verify_ip(bad, runner=runner)
    assert runner.calls == []


@pytest.mark.parametrize("host", ["-oProxyCommand=id", "a b", "", "x;y"])
def test_unsafe_host_is_rejected_before_ssh_runs(host):
    runner = fake_ssh(0, "")
    with pytest.raises(ValueError):
        verify_ip("10.77.0.2", host=host, runner=runner)
    assert runner.calls == []


def test_answer_for_another_ip_is_not_trusted():
    runner = fake_ssh(0, "BLOCKED 10.77.0.9 timeout 1 packets 1 bytes 1\n")
    with pytest.raises(BlockingError):
        verify_ip("10.77.0.2", runner=runner)


def test_unexpected_answer_raises():
    runner = fake_ssh(255, "", "Permission denied (publickey).")
    with pytest.raises(BlockingError):
        verify_ip("10.77.0.2", runner=runner)


def test_unreachable_host_raises_blocking_error():
    def runner(cmd, **kwargs):
        raise OSError("ssh not found")

    with pytest.raises(BlockingError):
        verify_ip("10.77.0.2", runner=runner)


def test_block_and_unblock_succeed():
    assert block_ip("10.77.0.2", runner=fake_ssh(0, "BLOCKED 10.77.0.2\n"))
    assert unblock_ip("10.77.0.2", runner=fake_ssh(0, "UNBLOCKED 10.77.0.2\n"))


def test_whitelisted_ip_is_refused_by_the_host():
    runner = fake_ssh(3, "", "ERROR: 10.77.0.2 is whitelisted - refusing to block")
    with pytest.raises(BlockingError):
        block_ip("10.77.0.2", runner=runner)
