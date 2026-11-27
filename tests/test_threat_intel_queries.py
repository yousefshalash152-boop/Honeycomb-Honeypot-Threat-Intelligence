
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from honeycomb.src.storage.schema import init_db


PROJECT_ROOT = Path(__file__).resolve().parent.parent
QUERY_PATH = (
    PROJECT_ROOT
    / "scripts"
    / "queries"
    / "05_malicious_sha256_hashes.sql"
)


def create_test_db(tmp_path):
    db_path = tmp_path / "query_test.db"

    with sqlite3.connect(db_path) as conn:
        init_db(conn)

    return db_path


def run_malicious_hash_query(conn):
    sql = QUERY_PATH.read_text(encoding="utf-8")
    return conn.execute(sql).fetchone()[0]


def add_hash_event(conn, indicator, event_id):
    conn.execute(
        """
        INSERT INTO events (
            event_id, ts_utc, src_ip, event_type, sha256
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            event_id,
            "2026-11-24T10:00:00+00:00",
            "1.2.3.4",
            "cowrie.command.input",
            indicator,
        ),
    )


def add_cache_response(conn, indicator, response, queried_at=None):
    if queried_at is None:
        queried_at = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        INSERT INTO intel_cache (
            indicator, source, response, queried_at
        ) VALUES (?, ?, ?, ?)
        """,
        (
            indicator,
            "VirusTotal",
            response if isinstance(response, str)
            else json.dumps(response),
            queried_at,
        ),
    )


def test_query_counts_valid_malicious_hash_once(tmp_path):
    db_path = create_test_db(tmp_path)
    indicator = "a" * 64

    with sqlite3.connect(db_path) as conn:
        add_hash_event(conn, indicator, "event-1")
        add_hash_event(conn, indicator, "event-2")

        add_cache_response(
            conn,
            indicator,
            {
                "source": "VirusTotal",
                "ioc_type": "sha256",
                "value": indicator,
                "found": True,
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 0,
                    "harmless": 10,
                    "undetected": 2,
                    "timeout": 0,
                    "failure": 0,
                },
            },
        )

        assert run_malicious_hash_query(conn) == 1


def test_query_excludes_invalid_hash_responses(tmp_path):
    db_path = create_test_db(tmp_path)

    cases = [
        {"found": False},
        {"found": True, "status": "unknown",
         "last_analysis_stats": {"malicious": 5}},
        {"found": True, "error": "Request failed",
         "last_analysis_stats": {"malicious": 5}},
        {"found": True, "last_analysis_stats": {
            "malicious": True
        }},
        {"found": True, "last_analysis_stats": {
            "malicious": -1
        }},
        {"found": True, "last_analysis_stats": []},
    ]

    with sqlite3.connect(db_path) as conn:
        for index, response in enumerate(cases):
            indicator = f"{index + 1:064x}"
            response.update({
                "source": "VirusTotal",
                "ioc_type": "sha256",
                "value": indicator,
            })
            add_hash_event(conn, indicator, f"event-{index}")
            add_cache_response(conn, indicator, response)

        assert run_malicious_hash_query(conn) == 0


def test_query_excludes_malformed_and_expired_cache(tmp_path):
    db_path = create_test_db(tmp_path)

    with sqlite3.connect(db_path) as conn:
        malformed_hash = "b" * 64
        expired_hash = "c" * 64

        add_hash_event(conn, malformed_hash, "event-malformed")
        add_hash_event(conn, expired_hash, "event-expired")

        add_cache_response(
            conn,
            malformed_hash,
            "{invalid-json",
        )

        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        ).isoformat()

        add_cache_response(
            conn,
            expired_hash,
            {
                "source": "VirusTotal",
                "ioc_type": "sha256",
                "value": expired_hash,
                "found": True,
                "last_analysis_stats": {"malicious": 5},
            },
            queried_at=old_time,
        )

        assert run_malicious_hash_query(conn) == 0


def test_query_excludes_unobserved_hash(tmp_path):
    db_path = create_test_db(tmp_path)
    indicator = "d" * 64

    with sqlite3.connect(db_path) as conn:
        add_cache_response(
            conn,
            indicator,
            {
                "source": "VirusTotal",
                "ioc_type": "sha256",
                "value": indicator,
                "found": True,
                "last_analysis_stats": {"malicious": 5},
            },
        )

        assert run_malicious_hash_query(conn) == 0
