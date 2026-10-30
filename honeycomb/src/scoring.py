"""Stage 2 - Scorer v1: behaviors + reputation -> score 0-100 with reasons.

Weights and thresholds come ONLY from config/scoring.yaml (never hard-coded).
Each evidence type counts ONCE per IP, however many times it happened.
The caller passes the behaviors seen for that IP in the last 24 hours.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config" / "scoring.yaml"
WHITELIST_PATH = ROOT / "config" / "whitelist.yaml"

# Behavior rule (docs/attack-mapping.md) -> evidence type (config/scoring.yaml).
# B09 (execution), B13 (hide traces), B14 and B15 have no weight yet.
BEHAVIOR_TO_EVIDENCE = {
    "B01": "login_brute_force", "B02": "login_brute_force",
    "B03": "login_success",
    "B04": "recon_commands", "B05": "recon_commands",
    "B06": "recon_commands", "B07": "recon_commands",
    "B08": "file_download",
    "B10": "persistence_attempt", "B11": "persistence_attempt",
    "B12": "persistence_attempt",
}

# Rule thresholds for reputation (the points themselves are in the config).
ABUSE_MIN = 50   # AbuseIPDB confidence score at or above this = bad IP
VT_MIN = 1       # at least this many VirusTotal engines = malicious hash


def load_config(path=None):
    with open(path or CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_whitelist(path=None):
    with open(path or WHITELIST_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return set(data.get("whitelist") or [])


def _action(total, thresholds):
    if total >= thresholds["block_candidate"]:
        return "BLOCK_CANDIDATE"
    if total >= thresholds["monitor"]:
        return "MONITOR"
    return "LOG"


def score_ip(ip, behaviors, reputation=None, campaign=False,
             config=None, whitelist=None):
    """Score one IP.

    behaviors:  iterable of rule ids seen for this IP, e.g. {"B01", "B03"}
    reputation: {"abuse_score": int|None, "vt_malicious": int|None}
                None means "no answer", which gives NO points (unknown != bad).
    campaign:   True if the IP's sessions belong to a suspected campaign.
    Returns {"ip", "score", "evidence": [{"reason", "points"}], "action",
             "whitelisted"}.
    """
    cfg = config or load_config()
    weights = cfg["evidence"]
    wl = load_whitelist() if whitelist is None else set(whitelist)

    found = {}  # evidence type -> detail text (insertion order = report order)
    by_type = {}
    for rule in sorted(set(behaviors)):
        etype = BEHAVIOR_TO_EVIDENCE.get(rule)
        if etype:
            by_type.setdefault(etype, []).append(rule)
    for etype, rules in by_type.items():
        found[etype] = "behaviors " + ", ".join(rules)

    rep = reputation or {}
    abuse, vt = rep.get("abuse_score"), rep.get("vt_malicious")
    if abuse is not None and abuse >= ABUSE_MIN:
        found["bad_ip_reputation"] = f"AbuseIPDB score {abuse}"
    if vt is not None and vt >= VT_MIN:
        found["malicious_file_hash"] = f"VirusTotal engines {vt}"
    if campaign:
        found["campaign_member"] = "part of a suspected campaign"

    evidence = [{"reason": f"{etype}: {detail}", "points": weights[etype]}
                for etype, detail in found.items()]
    total = min(sum(e["points"] for e in evidence), cfg["max_score"])

    whitelisted = ip in wl
    action = "LOG" if whitelisted else _action(total, cfg["thresholds"])
    return {"ip": ip, "score": total, "evidence": evidence,
            "action": action, "whitelisted": whitelisted}
