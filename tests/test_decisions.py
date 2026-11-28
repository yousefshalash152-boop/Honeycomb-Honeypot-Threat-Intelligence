import json
import sqlite3

import pytest

from honeycomb.src import decisions
from honeycomb.src.blocking import BlockingError
from honeycomb.src.decisions import ApproveRefused, approve

IP = "203.0.113.45"


def fake_scores(score=90, whitelisted=False, ip=IP):
    def scores(db_path, enrich=True):
        return [{"ip": ip, "score": score, "action": "BLOCK_CANDIDATE",
                 "whitelisted": whitelisted,
                 "evidence": [{"reason": "login_success: behaviors B03", "points": 20}]}]
    return scores


class FakeBlocker:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def __call__(self, ip, **kwargs):
        self.calls.append(ip)
        if self.error:
            raise self.error
        return True


def rows(db):
    conn = sqlite3.connect(db)
    try:
        has = conn.execute("SELECT name FROM sqlite_master WHERE name='decisions'").fetchone()
        if not has:
            return []
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM decisions")]
    finally:
        conn.close()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(decisions, "score_database", fake_scores())
    return str(tmp_path / "t.db")


def test_approve_logs_the_decision_and_blocks(db):
    blocker = FakeBlocker()
    d = approve(db, IP, "Yousef", "Brute force, login and a download",
                enrich=False, blocker=blocker, now="2026-11-01T10:00:00Z")
    assert d["block_result"] == "blocked"
    assert blocker.calls == [IP]
    (row,) = rows(db)
    assert (row["ip"], row["score"], row["approved_by"]) == (IP, 90, "Yousef")
    assert row["reason"] == "Brute force, login and a download"
    assert row["decided_at"] == "2026-11-01T10:00:00Z"
    assert row["action"] == "BLOCK" and row["block_result"] == "blocked"
    assert json.loads(row["reasons"])[0]["points"] == 20


@pytest.mark.parametrize("name", ["", "   ", None])
def test_refuses_an_empty_name(db, name):
    blocker = FakeBlocker()
    with pytest.raises(ApproveRefused):
        approve(db, IP, name, "some reason", blocker=blocker)
    assert rows(db) == [] and blocker.calls == []


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_refuses_an_empty_reason(db, reason):
    blocker = FakeBlocker()
    with pytest.raises(ApproveRefused):
        approve(db, IP, "Yousef", reason, blocker=blocker)
    assert rows(db) == [] and blocker.calls == []


def test_refuses_a_whitelisted_ip(db, monkeypatch):
    monkeypatch.setattr(decisions, "score_database", fake_scores(whitelisted=True))
    blocker = FakeBlocker()
    with pytest.raises(ApproveRefused, match="whitelist"):
        approve(db, IP, "Yousef", "reason", blocker=blocker)
    assert rows(db) == [] and blocker.calls == []


def test_refuses_a_score_below_70_but_accepts_exactly_70(db, monkeypatch):
    monkeypatch.setattr(decisions, "score_database", fake_scores(score=69))
    blocker = FakeBlocker()
    with pytest.raises(ApproveRefused, match="below"):
        approve(db, IP, "Yousef", "reason", blocker=blocker)
    assert rows(db) == [] and blocker.calls == []
    monkeypatch.setattr(decisions, "score_database", fake_scores(score=70))
    assert approve(db, IP, "Yousef", "reason", blocker=blocker)["block_result"] == "blocked"


def test_refuses_an_ip_that_was_never_seen(db):
    with pytest.raises(ApproveRefused, match="never seen"):
        approve(db, "198.51.100.1", "Yousef", "reason", blocker=FakeBlocker())


@pytest.mark.parametrize("bad", ["203.0.113.45; id", "abc", ""])
def test_refuses_an_invalid_ip(db, bad):
    blocker = FakeBlocker()
    with pytest.raises(ApproveRefused, match="valid IPv4"):
        approve(db, bad, "Yousef", "reason", blocker=blocker)
    assert blocker.calls == []


def test_failed_block_is_still_logged(db):
    d = approve(db, IP, "Yousef", "reason", blocker=FakeBlocker(BlockingError("host down")))
    assert d["block_result"].startswith("failed:")
    (row,) = rows(db)
    assert row["block_result"].startswith("failed:") and "host down" in row["block_result"]
