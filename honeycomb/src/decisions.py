"""Stage 3 - the approve command: a human decides, and every decision is logged.

The system only SUGGESTS (score >= 70 = block candidate). A named analyst
approves with a reason. Refused, and nothing is written, when:
  - the name or the reason is empty,
  - the IP is on the whitelist,
  - the score (recomputed from the stored events) is below the block threshold.
"""
import hashlib
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone

from honeycomb.src.blocking import BlockingError, block_ip
from honeycomb.src.pipeline import score_database
from honeycomb.src.scoring import load_config

# PROPOSAL: agree on this table with Member 2 (schema owner) before relying on it.
DECISIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    decision_id  TEXT PRIMARY KEY,
    ip           TEXT NOT NULL,
    score        INTEGER NOT NULL,
    reasons      TEXT NOT NULL,
    approved_by  TEXT NOT NULL,
    reason       TEXT NOT NULL,
    decided_at   TEXT NOT NULL,
    action       TEXT NOT NULL,
    block_result TEXT NOT NULL
);
"""


class ApproveRefused(Exception):
    """The approval was refused. Nothing was logged and nothing was blocked."""


def approve(db_path, ip, approved_by, reason, enrich=True, blocker=block_ip,
            now=None, **ssh):
    """Approve blocking one IP. Returns the logged decision as a dict."""
    name = (approved_by or "").strip()
    why = (reason or "").strip()
    if not name:
        raise ApproveRefused("refused: --by (the approver's name) is empty")
    if not why:
        raise ApproveRefused("refused: --reason is empty")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ApproveRefused(f"refused: {ip!r} is not a valid IPv4 address") from None

    scored = {r["ip"]: r for r in score_database(db_path, enrich=enrich)}
    result = scored.get(ip)
    if result is None:
        raise ApproveRefused(f"refused: {ip} was never seen in this database")
    if result["whitelisted"]:
        raise ApproveRefused(f"refused: {ip} is on the whitelist")
    threshold = load_config()["thresholds"]["block_candidate"]
    if result["score"] < threshold:
        raise ApproveRefused(
            f"refused: score {result['score']} is below the block threshold {threshold}")

    decided_at = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    decision_id = hashlib.sha1(f"{ip}|{decided_at}|{name}".encode()).hexdigest()[:12]
    decision = {"decision_id": decision_id, "ip": ip, "score": result["score"],
                "reasons": json.dumps(result["evidence"]), "approved_by": name,
                "reason": why, "decided_at": decided_at, "action": "BLOCK",
                "block_result": "pending"}

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(DECISIONS_SCHEMA)
        # Log FIRST, so even a failed block leaves an audit trail.
        with conn:
            conn.execute("INSERT INTO decisions VALUES (:decision_id, :ip, :score, "
                         ":reasons, :approved_by, :reason, :decided_at, :action, "
                         ":block_result)", decision)
        try:
            blocker(ip, **ssh)
            decision["block_result"] = "blocked"
        except (BlockingError, ValueError) as exc:
            decision["block_result"] = f"failed: {exc}"
        with conn:
            conn.execute("UPDATE decisions SET block_result = ? WHERE decision_id = ?",
                         (decision["block_result"], decision_id))
    finally:
        conn.close()
    return decision
