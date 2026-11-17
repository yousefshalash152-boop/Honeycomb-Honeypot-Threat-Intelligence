"""Stage 3 - correlation rules C1..C3 -> suspected campaigns.

A campaign is *suspected*: sessions from DIFFERENT IPs that share evidence.
It never means "same attacker".

Input: list of session dicts (adapt keys to the real sessions table):
    {"session_id": str, "src_ip": str,
     "hashes": [sha256, ...], "urls": [url, ...], "commands": [str, ...]}
"""
import re
from collections import defaultdict
from urllib.parse import urlparse

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MIN_CMDS_C3 = 2  # a 1-command sequence like "ls" is too generic to correlate

RULES = {
    "C1": ("same SHA-256", "high"),
    "C2": ("same download URL or server", "high"),
    "C3": ("same normalized command sequence", "medium"),
}


def normalize_command(cmd: str) -> str:
    cmd = IP_RE.sub("<IP>", cmd.strip())
    return re.sub(r"\s+", " ", cmd)


def _host(url: str) -> str:
    return (urlparse(url if "://" in url else "//" + url).hostname or "").lower()


def _keys(session: dict) -> dict:
    """Evidence keys per rule for one session."""
    keys = {"C1": set(), "C2": set(), "C3": set()}
    keys["C1"] |= {h.lower() for h in session.get("hashes", []) if h}
    for u in session.get("urls", []):
        keys["C2"].add("url:" + u.strip())
        if _host(u):
            keys["C2"].add("host:" + _host(u))
    cmds = tuple(normalize_command(c) for c in session.get("commands", []) if c.strip())
    if len(cmds) >= MIN_CMDS_C3:
        keys["C3"].add(" ; ".join(cmds))
    return keys


def find_campaigns(sessions: list[dict]) -> list[dict]:
    groups = defaultdict(list)  # (rule, key) -> sessions
    for s in sessions:
        for rule, ks in _keys(s).items():
            for k in ks:
                groups[(rule, k)].append(s)

    campaigns = []
    for (rule, key), members in sorted(groups.items()):
        ips = {m["src_ip"] for m in members}
        if len(ips) < 2:  # same IP twice is not a campaign
            continue
        desc, conf = RULES[rule]
        campaigns.append({
            "rule": rule,
            "confidence": conf,
            "evidence": key,
            "reason": f"{desc}: {len(members)} sessions from {len(ips)} IPs",
            "sessions": sorted(m["session_id"] for m in members),
            "ips": sorted(ips),
        })
    return campaigns


CONF_ORDER = {"medium": 1, "high": 2}


def merge_campaigns(links: list[dict]) -> list[dict]:
    """Merge links that share a session into one campaign each.

    Input: the output of find_campaigns (one entry per rule+evidence).
    Output: one dict per merged campaign, with all its reasons.
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)  # smallest id is the root: stable

    for link in links:
        first = link["sessions"][0]
        for sid in link["sessions"][1:]:
            union(first, sid)

    groups = defaultdict(list)
    for link in links:
        groups[find(link["sessions"][0])].append(link)

    merged = []
    for root, group in sorted(groups.items()):
        sessions = sorted({s for l in group for s in l["sessions"]})
        ips = sorted({ip for l in group for ip in l["ips"]})
        rules = sorted({l["rule"] for l in group})
        confidence = max((l["confidence"] for l in group), key=CONF_ORDER.get)
        if len(rules) >= 2 and confidence == "high":
            confidence = "very_high"
        merged.append({
            "root_session": root,
            "rules": rules,
            "confidence": confidence,
            "evidence": [l["evidence"] for l in group],
            "reasons": [l["reason"] for l in group],
            "sessions": sessions,
            "ips": ips,
        })
    return merged
