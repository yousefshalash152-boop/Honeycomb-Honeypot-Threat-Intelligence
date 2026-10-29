import json
import sqlite3
from datetime import datetime, timedelta, timezone


CACHE_TTL = timedelta(hours=24)


def get_cached_response(
    db_path: str,
    indicator: str,
    source: str,
) -> dict | None:
    """Return a cached response if it is less than 24 hours old."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT response, queried_at
            FROM intel_cache
            WHERE indicator = ? AND source = ?
            """,
            (indicator, source),
        ).fetchone()

        if row is None:
            return None

        try:
            queried_at = datetime.fromisoformat(row[1])
            if queried_at.tzinfo is None:
                queried_at = queried_at.replace(tzinfo=timezone.utc)

            age = datetime.now(timezone.utc) - queried_at
            if age < timedelta(0) or age >= CACHE_TTL:
                return None

            result = json.loads(row[0])
            return result if isinstance(result, dict) else None
        except (ValueError, TypeError):
            return None
    finally:
        conn.close()


def save_cached_response(
    db_path: str,
    indicator: str,
    source: str,
    response: dict,
) -> None:
    """Save a response to SQLite with its UTC timestamp."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO intel_cache (indicator, source, response, queried_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(indicator, source) DO UPDATE SET
                response = excluded.response,
                queried_at = excluded.queried_at
            """,
            (
                indicator,
                source,
                json.dumps(response),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def enqueue_retry(
    db_path: str,
    indicator: str,
    source: str,
    ioc_type: str,
    retry_after: str | None = None,
    last_error: str = "HTTP 429",
) -> None:
    """Store an indicator for retrying in a later run."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO intel_retry_queue (
                indicator, source, ioc_type, retry_after,
                attempts, last_error, updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(indicator, source) DO UPDATE SET
                ioc_type = excluded.ioc_type,
                retry_after = excluded.retry_after,
                attempts = intel_retry_queue.attempts + 1,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (
                indicator,
                source,
                ioc_type,
                retry_after,
                last_error,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_pending_retries(db_path: str) -> list[dict]:
    """Return indicators waiting for retry."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT indicator, source, ioc_type, retry_after,
                   attempts, last_error, updated_at
            FROM intel_retry_queue
            ORDER BY updated_at
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def remove_retry(
    db_path: str,
    indicator: str,
    source: str,
) -> None:
    """Remove an indicator from the retry queue after resolution."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            DELETE FROM intel_retry_queue
            WHERE indicator = ? AND source = ?
            """,
            (indicator, source),
        )
        conn.commit()
    finally:
        conn.close()
