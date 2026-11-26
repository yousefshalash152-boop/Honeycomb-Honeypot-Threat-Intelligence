
import csv
import hashlib
import json
import sqlite3

import honeycomb.src.analysis.file_inspector as file_inspector

from honeycomb.src.analysis.file_inspector import (
    inspect_downloads,
    export_file_report_csv,
)
from honeycomb.src.storage.schema import init_db


def create_download_event(db_path, filename, content_hash):
    event = {
        "eventid": "cowrie.session.file_download",
        "outfile": filename,
        "url": "http://example.test/file",
        "shasum": content_hash,
    }

    with sqlite3.connect(db_path) as conn:
        init_db(conn)

        conn.execute(
            """
            INSERT INTO events (
                event_id, ts_utc, src_ip, event_type,
                session_id, url, sha256, raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "event-1",
                "2026-11-01T10:00:00+00:00",
                "192.0.2.1",
                "cowrie.session.file_download",
                "session-1",
                event["url"],
                content_hash,
                json.dumps(event),
            ),
        )


def test_inspect_downloaded_file(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    files_dir = tmp_path / "downloads"
    files_dir.mkdir()

    content = b"#!/bin/sh\necho safe test\n"
    expected_hash = hashlib.sha256(content).hexdigest()

    (files_dir / "test.sh").write_bytes(content)

    create_download_event(db_path, "test.sh", expected_hash)

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        lambda *args, **kwargs: {
            "source": "VirusTotal",
            "found": True,
            "malicious": 2,
            "suspicious": 1,
            "harmless": 60,
        },
    )

    results = inspect_downloads(db_path, files_dir)

    assert len(results) == 1
    assert results[0]["file_status"] == "available"
    assert results[0]["filename"] == "test.sh"
    assert results[0]["file_size"] == len(content)
    assert results[0]["file_type"] == "Script"
    assert results[0]["actual_sha256"] == expected_hash
    assert results[0]["hash_matches"] is True

    assert results[0]["vt_status"] == "found"
    assert results[0]["vt_malicious"] == 2
    assert results[0]["vt_suspicious"] == 1
    assert results[0]["vt_harmless"] == 60
    assert results[0]["vt_hash"] == expected_hash


def test_missing_file(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    files_dir = tmp_path / "downloads"
    files_dir.mkdir()

    logged_hash = "a" * 64
    create_download_event(db_path, "missing.sh", logged_hash)

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        lambda *args, **kwargs: {
            "source": "VirusTotal",
            "found": False,
        },
    )

    results = inspect_downloads(db_path, files_dir)

    assert results[0]["file_status"] == "missing"
    assert results[0]["file_size"] is None
    assert results[0]["vt_status"] == "not_found"
    assert results[0]["vt_hash"] == logged_hash


def test_invalid_logged_hash(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"

    create_download_event(db_path, "test.sh", "invalid-hash")

    def unexpected_call(*args, **kwargs):
        raise AssertionError("VirusTotal should not be called")

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        unexpected_call,
    )

    results = inspect_downloads(db_path)

    assert results[0]["logged_sha256"] is None
    assert results[0]["file_status"] == "not_checked"
    assert results[0]["vt_status"] == "not_checked"


def test_missing_filename(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"

    event = {
        "eventid": "cowrie.session.file_download",
        "shasum": "a" * 64,
    }

    with sqlite3.connect(db_path) as conn:
        init_db(conn)

        conn.execute(
            """
            INSERT INTO events (
                event_id, ts_utc, src_ip, event_type, raw_json, sha256
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "event-1",
                "2026-11-01T10:00:00+00:00",
                "192.0.2.1",
                "cowrie.session.file_download",
                json.dumps(event),
                "a" * 64,
            ),
        )

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        lambda *args, **kwargs: {
            "source": "VirusTotal",
            "found": False,
        },
    )

    results = inspect_downloads(db_path)

    assert results[0]["filename"] is None
    assert results[0]["file_status"] == "not_checked"
    assert results[0]["vt_status"] == "not_found"


def test_export_file_report(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    output_path = tmp_path / "files.csv"

    create_download_event(db_path, "test.sh", "a" * 64)

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        lambda *args, **kwargs: {
            "source": "VirusTotal",
            "found": True,
            "malicious": 3,
            "suspicious": 0,
            "harmless": 55,
        },
    )

    results = inspect_downloads(db_path)
    count = export_file_report_csv(results, output_path)

    assert count == 1
    assert output_path.exists()

    with output_path.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 1
    assert rows[0]["vt_status"] == "found"
    assert rows[0]["vt_malicious"] == "3"


def test_hash_mismatch_uses_actual_file_hash(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    files_dir = tmp_path / "downloads"
    files_dir.mkdir()

    content = b"safe test content"
    actual_hash = hashlib.sha256(content).hexdigest()
    logged_hash = "a" * 64

    (files_dir / "test.bin").write_bytes(content)
    create_download_event(db_path, "test.bin", logged_hash)

    checked_hashes = []

    def fake_virustotal(ioc_type, value, db_path=None):
        checked_hashes.append(value)
        return {
            "source": "VirusTotal",
            "found": True,
            "malicious": 1,
            "suspicious": 0,
            "harmless": 10,
        }

    monkeypatch.setattr(
        file_inspector,
        "check_virustotal",
        fake_virustotal,
    )

    results = inspect_downloads(db_path, files_dir)

    assert results[0]["hash_matches"] is False
    assert results[0]["vt_hash"] == actual_hash
    assert checked_hashes == [actual_hash]
