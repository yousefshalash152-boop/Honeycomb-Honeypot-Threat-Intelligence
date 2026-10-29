SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts_utc     TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    session_id TEXT,
    event_type TEXT NOT NULL,
    username   TEXT,
    password   TEXT,
    command    TEXT,
    url        TEXT,
    sha256     TEXT,
    raw_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE TABLE IF NOT EXISTS intel_cache (
    indicator  TEXT NOT NULL,
    source     TEXT NOT NULL,
    response   TEXT NOT NULL,
    queried_at TEXT NOT NULL,
    PRIMARY KEY (indicator, source)
);

CREATE TABLE IF NOT EXISTS intel_retry_queue (
    indicator   TEXT NOT NULL,
    source      TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    retry_after TEXT,
    attempts    INTEGER NOT NULL DEFAULT 1,
    last_error  TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (indicator, source)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    src_ip        TEXT,
    started_at    TEXT,
    ended_at      TEXT,
    username      TEXT,
    command_count INTEGER DEFAULT 0
);

"""


def init_db(conn):
    """Create tables if they don't exist yet."""
    conn.executescript(SCHEMA)
    conn.commit()
