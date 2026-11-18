"""Stage 2 - behavior rules B01..B15: what did the attacker do in a session?

Each rule reads the events of ONE session and, if it fires, returns:
    {"session_id", "rule_id", "behavior", "technique_id", "tactic",
     "evidence", "event_id"}
`evidence` is the exact command / event that proved the behavior, so every
claim in a report can be traced back to a row in `events`.

Attacker text (commands, usernames) is DATA: it is only matched, never executed.
Rules and thresholds are documented in docs/attack-mapping.md.
"""
import re
from collections import OrderedDict

# ---- thresholds (docs/attack-mapping.md, "Thresholds") ---------------------
B01_MIN_FAILED = 5       # failed logins in one session
MIN_CMDS_DISCOVERY = 2   # B04-B07 need >= 2 commands of the same category

DEFAULT_CREDS = {
    ("root", "root"), ("root", "123456"), ("root", "password"),
    ("root", "toor"), ("root", "admin"), ("admin", "admin"),
    ("admin", "123456"), ("admin", "password"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("user", "user"), ("test", "test"),
}

# rule_id -> (behavior group, technique id, tactic)
RULES = {
    "B01": ("brute_force",        "T1110.001", "Credential Access"),
    "B02": ("credential_success", "T1110.004", "Credential Access"),
    "B03": ("credential_success", "T1078",     "Initial Access"),
    "B04": ("recon",              "T1082",     "Discovery"),
    "B05": ("recon",              "T1087.001", "Discovery"),
    "B06": ("recon",              "T1016",     "Discovery"),
    "B07": ("recon",              "T1057",     "Discovery"),
    "B08": ("download",           "T1105",     "Command and Control"),
    "B09": ("execution",          "T1059.004", "Execution"),
    "B10": ("persistence",        "T1053.003", "Persistence"),
    "B11": ("persistence",        "T1098.004", "Persistence"),
    "B12": ("persistence",        "T1136.001", "Persistence"),
    "B13": ("defense_evasion",    "T1070.003", "Defense Evasion"),
    "B14": ("defense_evasion",    "T1562.001", "Defense Evasion"),
    "B15": ("recon",              "T1046",     "Discovery"),
}

# ---- command patterns -------------------------------------------------------
_B04 = re.compile(r"^(uname|whoami|id|hostname|lscpu|free)\b|^cat\s+/etc/os-release|^cat\s+/proc/cpuinfo")
_B05_STRONG = re.compile(r"^cat\s+/etc/passwd")
_B05_WEAK = re.compile(r"^(w|who|last)\b")
_B06 = re.compile(r"^(ifconfig|netstat|ss)\b|^ip\s+(a|addr|address)\b|^cat\s+/etc/hosts")
_B07 = re.compile(r"^(ps|top)\b")
_B08 = re.compile(r"^(wget|curl|tftp)\b")
_B10 = re.compile(r"^crontab\b|/etc/cron")
_B11 = re.compile(r"authorized_keys")
_B12 = re.compile(r"^(useradd|adduser|passwd)\b")
_B13 = re.compile(r"^history\s+-c|rm\s+.*\.bash_history|unset\s+HISTFILE")
_B14 = re.compile(r"^(pkill|killall|kill\s+-9)\b.*(xmrig|minerd|miner)")
_B15 = re.compile(r"^(nmap|masscan|nc)\b")
_CHMOD_X = re.compile(r"^chmod\s+(\+x|[0-7]*[1357][0-7]{0,2}|[ugoa]*\+x)\s+(\S+)")


def _hit(sid, rule_id, evidence, event_id):
    group, tech, tactic = RULES[rule_id]
    return {"session_id": sid, "rule_id": rule_id, "behavior": group,
            "technique_id": tech, "tactic": tactic,
            "evidence": evidence, "event_id": event_id}


def _split(cmd):
    """One input line can hold several commands: 'cd /tmp; wget x'."""
    return [p.strip() for p in re.split(r";|&&|\|\|", cmd) if p.strip()]


def _commands(events):
    """(command, event_id) pairs in time order."""
    out = []
    for e in events:
        if e.get("event_type") == "cowrie.command.input" and e.get("command"):
            for part in _split(e["command"]):
                out.append((part, e.get("event_id")))
    return out


def detect_behaviors(events, session_id=None):
    """Run all rules on the events of one session. Returns a list of hits,
    sorted by rule_id, at most one hit per rule."""
    events = list(events)
    sid = session_id or (events[0].get("session_id") if events else None)
    hits = OrderedDict()

    def add(rule_id, evidence, event_id):
        hits.setdefault(rule_id, _hit(sid, rule_id, evidence, event_id))

    failed = [e for e in events if e.get("event_type") == "cowrie.login.failed"]
    success = [e for e in events if e.get("event_type") == "cowrie.login.success"]
    cmds = _commands(events)

    # B01: password guessing
    if len(failed) >= B01_MIN_FAILED:
        add("B01", f"{len(failed)} failed logins", failed[-1].get("event_id"))

    # B02: logged in with a default / well-known pair (successful logins only)
    for e in success:
        if (e.get("username"), e.get("password")) in DEFAULT_CREDS:
            add("B02", f"login {e.get('username')}/{e.get('password')}", e.get("event_id"))
            break

    # B03: success counts only when B01 fired in the same session
    if "B01" in hits and success:
        add("B03", "login.success after guessing", success[0].get("event_id"))

    # B04-B07: discovery needs >= 2 commands of the same category
    def category(rule_id, pattern):
        found = [(c, i) for c, i in cmds if pattern.search(c)]
        if len(found) >= MIN_CMDS_DISCOVERY:
            add(rule_id, " ; ".join(c for c, _ in found), found[0][1])

    category("B04", _B04)
    category("B06", _B06)
    category("B07", _B07)
    # B05: reading /etc/passwd is strong alone; w/who/last need 2
    strong = [(c, i) for c, i in cmds if _B05_STRONG.search(c)]
    if strong:
        add("B05", strong[0][0], strong[0][1])
    else:
        category("B05", _B05_WEAK)

    # single-command rules
    for c, eid in cmds:
        if _B08.search(c):  add("B08", c, eid)
        if _B10.search(c):  add("B10", c, eid)
        if _B11.search(c):  add("B11", c, eid)
        if _B12.search(c):  add("B12", c, eid)
        if _B13.search(c):  add("B13", c, eid)
        if _B14.search(c):  add("B14", c, eid)
        if _B15.search(c):  add("B15", c, eid)
    if "B08" not in hits:  # a recorded download counts even without a wget line
        for e in events:
            if e.get("event_type") == "cowrie.session.file_download":
                add("B08", e.get("url") or "file_download", e.get("event_id"))
                break

    # B09: chmod a file, then run it (./f, sh f, bash f)
    armed = {}
    for c, eid in cmds:
        m = _CHMOD_X.search(c)
        if m:
            armed[m.group(2).lstrip("./")] = c
            continue
        run = re.match(r"^(?:\./|sh\s+|bash\s+)(\S+)", c)
        if run and run.group(1).lstrip("./") in armed:
            add("B09", f"{armed[run.group(1).lstrip('./')]} ; {c}", eid)

    return sorted(hits.values(), key=lambda h: h["rule_id"])


# ---- database side -----------------------------------------------------------
# PROPOSAL: agree on this table with Member 2 (schema owner) and Member 5
# (scoring reads it) before merging, same as campaigns_db.py.
BEHAVIORS_SCHEMA = """
CREATE TABLE IF NOT EXISTS behaviors (
    session_id   TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    behavior     TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    event_id     TEXT,
    PRIMARY KEY (session_id, rule_id)
);
"""


def init_behaviors(conn):
    conn.executescript(BEHAVIORS_SCHEMA)
    conn.commit()


def load_session_events(conn):
    """{session_id: [event dict, ...]} in time order, straight from `events`."""
    cur = conn.execute(
        "SELECT event_id, session_id, event_type, username, password, command, url "
        "FROM events WHERE session_id IS NOT NULL ORDER BY ts_utc, event_id")
    cols = [c[0] for c in cur.description]
    sessions = OrderedDict()
    for row in cur.fetchall():
        e = dict(zip(cols, row))
        sessions.setdefault(e["session_id"], []).append(e)
    return sessions


def build_behaviors(conn):
    """Full rebuild: running it twice gives the same rows (no duplicates)."""
    init_behaviors(conn)
    conn.execute("DELETE FROM behaviors")
    n = 0
    for sid, events in load_session_events(conn).items():
        for h in detect_behaviors(events, sid):
            conn.execute(
                "INSERT INTO behaviors VALUES (?,?,?,?,?,?,?)",
                (h["session_id"], h["rule_id"], h["behavior"], h["technique_id"],
                 h["tactic"], h["evidence"], h["event_id"]))
            n += 1
    conn.commit()
    return n
