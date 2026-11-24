"""Stage 3 - read sessions from `events`, run C1-C3, write `campaigns`.

Sessions are built straight from the events table (grouped by session_id),
so this does not depend on a separate sessions table.
The campaigns tables below are a PROPOSAL: agree on them with Member 2
(schema owner) and Member 5 (scoring reads them) before merging.
"""
import hashlib
from collections import OrderedDict

from honeycomb.src.correlation import find_campaigns, merge_campaigns

CAMPAIGNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    reason      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_sessions (
    campaign_id TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    PRIMARY KEY (campaign_id, session_id)
);
"""


def init_campaigns(conn):
    conn.executescript(CAMPAIGNS_SCHEMA)
    conn.commit()


def load_sessions(conn):
    """One dict per session: IP + the hashes, URLs and commands seen in it."""
    rows = conn.execute(
        "SELECT session_id, src_ip, sha256, url, command FROM events "
        "WHERE session_id IS NOT NULL ORDER BY ts_utc, event_id"
    ).fetchall()
    sessions = OrderedDict()
    for sid, ip, sha, url, cmd in rows:
        s = sessions.setdefault(sid, {"session_id": sid, "src_ip": ip,
                                      "hashes": [], "urls": [], "commands": []})
        if sha and sha not in s["hashes"]:
            s["hashes"].append(sha)
        if url and url not in s["urls"]:
            s["urls"].append(url)
        if cmd:
            s["commands"].append(cmd)
    return list(sessions.values())


def _campaign_id(rule, evidence):
    return hashlib.sha1(f"{rule}|{evidence}".encode()).hexdigest()[:12]


def build_campaigns(conn):
    """Full rebuild: running it twice gives the same rows (no duplicates).

    One row per MERGED campaign (sessions linked by any rule are one campaign).
    """
    init_campaigns(conn)
    sessions = load_sessions(conn)
    ip_of = {s["session_id"]: s["src_ip"] for s in sessions}
    merged = merge_campaigns(find_campaigns(sessions))
    with conn:
        conn.execute("DELETE FROM campaign_sessions")
        conn.execute("DELETE FROM campaigns")
        for c in merged:
            cid = _campaign_id("MERGED", c["root_session"])
            conn.execute("INSERT INTO campaigns VALUES (?,?,?,?,?)",
                         (cid, ",".join(c["rules"]), c["confidence"],
                          " | ".join(c["evidence"]), " | ".join(c["reasons"])))
            for sid in c["sessions"]:
                conn.execute("INSERT INTO campaign_sessions VALUES (?,?,?)",
                             (cid, sid, ip_of[sid]))
    return len(merged)
