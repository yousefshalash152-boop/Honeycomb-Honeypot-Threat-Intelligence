
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from honeycomb.src.storage.schema import init_db
from honeycomb.src.storage.intel_cache import (
    get_cached_response,
    save_cached_response,
)


def create_test_db(tmp_path):
    db_path = str(tmp_path / "intel_test.db")
    conn = sqlite3.connect(db_path)
    init_db(conn)
    conn.close()
    return db_path


def test_cache_saves_and_reads_response(tmp_path):
    db_path = create_test_db(tmp_path)
    response = {
        "source": "VirusTotal",
        "found": True,
        "malicious": 2,
    }

    save_cached_response(
        db_path, "a" * 64, "VirusTotal", response
    )

    cached = get_cached_response(
        db_path, "a" * 64, "VirusTotal"
    )

    assert cached == response


def test_cache_returns_none_for_missing_indicator(tmp_path):
    db_path = create_test_db(tmp_path)

    cached = get_cached_response(
        db_path, "missing-indicator", "VirusTotal"
    )

    assert cached is None


def test_cache_ignores_expired_response(tmp_path):
    db_path = create_test_db(tmp_path)
    indicator = "8.8.8.8"

    save_cached_response(
        db_path,
        indicator,
        "AbuseIPDB",
        {"source": "AbuseIPDB", "score": 10},
    )

    old_time = (
        datetime.now(timezone.utc) - timedelta(hours=25)
    ).isoformat()

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        UPDATE intel_cache
        SET queried_at = ?
        WHERE indicator = ? AND source = ?
        """,
        (old_time, indicator, "AbuseIPDB"),
    )
    conn.commit()
    conn.close()

    cached = get_cached_response(
        db_path, indicator, "AbuseIPDB"
    )

    assert cached is None
