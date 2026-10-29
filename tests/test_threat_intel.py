
import json
import sqlite3
from pathlib import Path

import pytest
import requests

from honeycomb.src.analysis import threat_intel
from honeycomb.src.storage.schema import init_db
from honeycomb.src.storage.intel_cache import (
    get_cached_response,
    save_cached_response,
    get_pending_retries,
    enqueue_retry,
)


FIXTURES = Path(__file__).parent / "fixtures" / "intel"


def load_fixture(name):
    """Load a saved API response or test scenario."""
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeResponse:
    def __init__(self, status_code=200, body="", headers=None):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {}

    def json(self):
        return json.loads(self.body)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )


def create_test_db(tmp_path):
    db_path = str(tmp_path / "threat_intel_test.db")
    conn = sqlite3.connect(db_path)
    init_db(conn)
    conn.close()
    return db_path


def test_cache_saves_and_reads_response(tmp_path):
    db_path = create_test_db(tmp_path)
    response = {"source": "VirusTotal", "found": True}

    save_cached_response(
        db_path, "a" * 64, "VirusTotal", response
    )

    assert get_cached_response(
        db_path, "a" * 64, "VirusTotal"
    ) == response


def test_cache_returns_none_for_missing_indicator(tmp_path):
    db_path = create_test_db(tmp_path)

    assert get_cached_response(
        db_path, "missing-indicator", "VirusTotal"
    ) is None


def test_cache_ignores_expired_response(tmp_path):
    db_path = create_test_db(tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO intel_cache
           (indicator, source, response, queried_at)
           VALUES (?, ?, ?, ?)""",
        (
            "old-indicator",
            "VirusTotal",
            '{"found": true}',
            "2020-01-01T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    assert get_cached_response(
        db_path, "old-indicator", "VirusTotal"
    ) is None


def test_abuseipdb_uses_cache_without_http(tmp_path, monkeypatch):
    db_path = create_test_db(tmp_path)
    cached = {
        "source": "AbuseIPDB",
        "ip": "8.8.8.8",
        "abuse_confidence_score": 0,
    }
    save_cached_response(db_path, "8.8.8.8", "AbuseIPDB", cached)

    monkeypatch.setattr(
        threat_intel, "ABUSEIPDB_API_KEY", "test-key"
    )

    def fail_if_api_called(*args, **kwargs):
        raise AssertionError("Unexpected HTTP request")

    monkeypatch.setattr(
        threat_intel.requests, "get", fail_if_api_called
    )

    assert threat_intel.check_ip_abuseipdb(
        "8.8.8.8", db_path=db_path
    ) == cached


def test_virustotal_uses_hash_cache_without_http(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    sha256 = "a" * 64
    cached = {
        "source": "VirusTotal",
        "ioc_type": "sha256",
        "value": sha256,
        "found": True,
    }
    save_cached_response(
        db_path, sha256, "VirusTotal", cached
    )

    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    def fail_if_api_called(*args, **kwargs):
        raise AssertionError("Unexpected HTTP request")

    monkeypatch.setattr(
        threat_intel.requests, "get", fail_if_api_called
    )

    assert threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    ) == cached


def test_virustotal_404_returns_not_found(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    body = load_fixture("virustotal_404.json")
    monkeypatch.setattr(
        threat_intel.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(404, body),
    )

    result = threat_intel.check_virustotal(
        "sha256", "b" * 64, db_path=db_path
    )

    assert result["found"] is False
    assert result["value"] == "b" * 64


def test_virustotal_429_returns_unknown_without_caching(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    body = load_fixture("virustotal_429.json")
    monkeypatch.setattr(
        threat_intel.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            429, body, headers={"Retry-After": "120"}
        ),
    )

    result = threat_intel.check_virustotal(
        "sha256", "c" * 64, db_path=db_path
    )

    assert result["status"] == "unknown"
    assert result["retry_after"] == "120"
    assert get_cached_response(
        db_path, "c" * 64, "VirusTotal"
    ) is None


def test_virustotal_timeout_returns_unknown(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )
    scenario = json.loads(load_fixture("timeout.json"))
    assert scenario["simulate"] == "timeout"

    def fake_get(*args, **kwargs):
        raise requests.Timeout("Simulated timeout")

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    result = threat_intel.check_virustotal(
        "sha256", "d" * 64, db_path=db_path
    )

    assert result["status"] == "unknown"
    assert "timed out" in result["error"].lower()
    assert get_cached_response(
        db_path, "d" * 64, "VirusTotal"
    ) is None


def test_virustotal_malformed_json_returns_unknown(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    body = load_fixture("malformed_json.json")
    monkeypatch.setattr(
        threat_intel.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(200, body),
    )

    result = threat_intel.check_virustotal(
        "sha256", "e" * 64, db_path=db_path
    )

    assert result["status"] == "unknown"
    assert get_cached_response(
        db_path, "e" * 64, "VirusTotal"
    ) is None


def test_abuseipdb_success_is_cached(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "ABUSEIPDB_API_KEY", "test-key"
    )

    body = load_fixture("abuseipdb_success.json")
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(200, body)

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    first = threat_intel.check_ip_abuseipdb(
        "8.8.8.8", db_path=db_path
    )
    second = threat_intel.check_ip_abuseipdb(
        "8.8.8.8", db_path=db_path
    )

    assert first == second
    assert first["abuse_confidence_score"] == 75
    assert len(calls) == 1


def test_virustotal_success_is_cached(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    body = load_fixture("virustotal_success.json")
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(200, body)

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    sha256 = "f" * 64
    first = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )
    second = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )

    assert first == second
    assert first["found"] is True
    assert first["malicious"] == 5
    assert len(calls) == 1

def test_virustotal_429_is_added_to_retry_queue(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(
            429,
            load_fixture("virustotal_429.json"),
            headers={"Retry-After": "120"},
        )

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    sha256 = "1" * 64
    result = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )

    pending = get_pending_retries(db_path)

    assert result["status"] == "unknown"
    assert len(pending) == 1
    assert pending[0]["indicator"] == sha256
    assert pending[0]["source"] == "VirusTotal"
    assert pending[0]["ioc_type"] == "sha256"
    assert pending[0]["retry_after"] == "120"


def test_queued_429_is_deferred_without_http(
    tmp_path, monkeypatch
):
    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(
            429,
            load_fixture("virustotal_429.json"),
            headers={"Retry-After": "120"},
        )

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    sha256 = "2" * 64

    first = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )
    second = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )

    assert first["status"] == "unknown"
    assert second["error"] == "Retry deferred"
    assert len(calls) == 1


def test_expired_retry_is_attempted_and_cleared(
    tmp_path, monkeypatch
):
    from datetime import datetime, timedelta, timezone

    db_path = create_test_db(tmp_path)
    monkeypatch.setattr(
        threat_intel, "VIRUSTOTAL_API_KEY", "test-key"
    )

    sha256 = "3" * 64

    enqueue_retry(
        db_path,
        sha256,
        "VirusTotal",
        "sha256",
        retry_after="60",
    )

    old_time = (
        datetime.now(timezone.utc) - timedelta(minutes=2)
    ).isoformat()

    conn = sqlite3.connect(db_path)
    conn.execute(
        """UPDATE intel_retry_queue
           SET updated_at = ?
           WHERE indicator = ? AND source = ?""",
        (old_time, sha256, "VirusTotal"),
    )
    conn.commit()
    conn.close()

    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return FakeResponse(
            200,
            load_fixture("virustotal_success.json"),
        )

    monkeypatch.setattr(
        threat_intel.requests, "get", fake_get
    )

    result = threat_intel.check_virustotal(
        "sha256", sha256, db_path=db_path
    )

    assert result["found"] is True
    assert len(calls) == 1
    assert not any(
        item["indicator"] == sha256
        and item["source"] == "VirusTotal"
        for item in get_pending_retries(db_path)
    )
