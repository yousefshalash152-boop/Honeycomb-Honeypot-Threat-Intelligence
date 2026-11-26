
import csv
import sqlite3

from honeycomb.src.analysis.ioc_export import export_iocs_csv
from honeycomb.src.storage.schema import init_db


def test_export_iocs_to_csv(tmp_path):
    db_path = str(tmp_path / "test.db")
    output_path = tmp_path / "iocs.csv"

    with sqlite3.connect(db_path) as conn:
        init_db(conn)

        conn.execute(
            """
            INSERT INTO events (
                event_id, ts_utc, src_ip, event_type, url, command, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "event-1",
                "2026-10-14T10:00:00+00:00",
                "1.2.3.4",
                "cowrie.session.file_download",
                "http://example.com/file.sh",
                None,
                "a" * 64,
            ),
        )

        conn.commit()

    count = export_iocs_csv(db_path, str(output_path))

    assert count == 3
    assert output_path.exists()

    with output_path.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 3

    pairs = {(row["type"], row["value"]) for row in rows}

    assert ("ip", "1.2.3.4") in pairs
    assert ("url", "http://example.com/file.sh") in pairs
    assert ("sha256", "a" * 64) in pairs

    for row in rows:
        assert row["event_ids"] == "event-1"


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
        assert reader.fieldnames == ["type", "value", "event_ids"]
        assert list(reader) == []
