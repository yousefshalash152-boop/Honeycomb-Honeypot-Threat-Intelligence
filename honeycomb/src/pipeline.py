"""Stage 2 - the real pipeline behind `python -m honeycomb run --input FILE`.

load -> IOCs -> enrich -> behavior -> correlate -> score.
Steps 9 (decide) and 10 (report) are wired in later stages.
"""
import sqlite3
from collections import defaultdict

from honeycomb.src.analysis.enrichment import enrich_iocs
from honeycomb.src.analysis.ioc_extractor import extract_iocs
from honeycomb.src.behavior import detect_behaviors
from honeycomb.src.campaigns_db import build_campaigns
from honeycomb.src.scoring import load_config, load_whitelist, score_ip
from honeycomb.src.storage.loader import load_file


def _events_by_session(conn):
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events WHERE session_id IS NOT NULL AND session_id != '' "
        "ORDER BY ts_utc, event_id").fetchall()
    conn.row_factory = None
    sessions = defaultdict(list)
    for r in rows:
        sessions[r["session_id"]].append(dict(r))
    return sessions


def _reputation(db_path, conn):
    """Per-IP reputation from the (cached) enrichment answers.

    A missing or failed answer stays None: unknown is NOT the same as bad.
    """
    rep = defaultdict(lambda: {"abuse_score": None, "vt_malicious": None})
    ips_of_hash = defaultdict(set)
    for sha, ip in conn.execute(
            "SELECT DISTINCT sha256, src_ip FROM events WHERE sha256 IS NOT NULL"):
        ips_of_hash[sha.strip().lower()].add(ip)
    for item in enrich_iocs(db_path):
        intel = item["threat_intel"]
        if item["type"] == "ip":
            score = intel.get("abuseipdb", {}).get("abuse_confidence_score")
            if score is not None:
                rep[item["value"]]["abuse_score"] = score
        elif item["type"] == "sha256":
            malicious = intel.get("virustotal", {}).get("malicious")
            if malicious is not None:
                for ip in ips_of_hash.get(item["value"], ()):
                    prev = rep[ip]["vt_malicious"] or 0
                    rep[ip]["vt_malicious"] = max(prev, malicious)
    return rep


def run_pipeline(log_path, db_path, enrich=True, out=print):
    """Run steps 3-8 on one log file. Returns the list of score results."""
    config, whitelist = load_config(), load_whitelist()

    stats = load_file(db_path, log_path)
    out(f"[3] normalize: {stats['inserted']} new, {stats['duplicates']} duplicates, "
        f"{stats['bad_lines']} bad lines")

    iocs = extract_iocs(db_path)
    out(f"[4] extract_iocs: {len(iocs)} indicators")

    conn = sqlite3.connect(db_path)
    try:
        rep = _reputation(db_path, conn) if enrich else {}
        out("[5] enrich: done (cached answers reused)" if enrich
            else "[5] enrich: skipped (--no-enrich)")

        behaviors_of_ip = defaultdict(set)
        sessions = _events_by_session(conn)
        ip_of_session = {sid: evs[0]["src_ip"] for sid, evs in sessions.items()}
        total = 0
        for sid, events in sessions.items():
            hits = detect_behaviors(events, session_id=sid)
            total += len(hits)
            behaviors_of_ip[ip_of_session[sid]].update(h["rule_id"] for h in hits)
        out(f"[6] behavior: {total} behaviors in {len(sessions)} sessions")

        campaigns = build_campaigns(conn)
        out(f"[7] correlate: {campaigns} suspected campaigns "
            "(used for scoring from Stage 3)")

        all_ips = [r[0] for r in conn.execute(
            "SELECT DISTINCT src_ip FROM events ORDER BY src_ip")]
    finally:
        conn.close()

    results = [score_ip(ip, behaviors_of_ip.get(ip, set()), rep.get(ip),
                        config=config, whitelist=whitelist) for ip in all_ips]
    results.sort(key=lambda r: (-r["score"], r["ip"]))

    out(f"[8] score: {len(results)} IPs")
    for r in results:
        out(f"    {r['ip']:<18} {r['score']:>3}  {r['action']}")
        for e in r["evidence"]:
            out(f"        +{e['points']:<3} {e['reason']}")
    out("[9] decide: not implemented yet")
    out("[10] report: not implemented yet")
    return results
