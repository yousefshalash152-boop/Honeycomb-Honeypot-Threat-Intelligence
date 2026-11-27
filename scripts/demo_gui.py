#!/usr/bin/env python3
"""Honeycomb control panel server (local). 127.0.0.1 only; lab attacker IP only."""
import json, os, re, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IP = "10.77.0.2"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable
ATK = os.path.expanduser("~/backup/lab_attack_2222.sh")
ATK_OPEN = os.path.expanduser("~/backup/lab_attack.sh")
LOG = "cowrie-lab:/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
SCORE = (f"docker cp {LOG} /tmp/gui_lab.json >/dev/null && rm -f /tmp/gui.db && "
         f"{PY} -m honeycomb --input /tmp/gui_lab.json --db /tmp/gui.db --no-enrich run")
LOCK = threading.Lock()
LABELS = {"login_success": "Login succeeded", "recon_commands": "Reconnaissance commands",
          "file_download": "File download", "persistence_attempt": "Persistence attempt",
          "login_brute_force": "Brute-force login", "bad_ip_reputation": "Bad IP reputation",
          "malicious_file_hash": "Malicious file hash", "campaign_member": "Campaign member"}


def sh(cmd, limit):
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=limit)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, ""


def seconds_left(text):
    units = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(int(n) * units[u] for n, u in re.findall(r"(\d+)\s*([dhms])", text or ""))


def state():
    _, out = sh([PY, "-m", "honeycomb", "verify", IP], 30)
    m = re.search(r"(NOT BLOCKED|BLOCKED)(?:\s+packets=(\d+) bytes=(\d+)\s+expires in (.+))?", out)
    if not m:
        return {"known": False, "blocked": False, "drops": 0, "expires_in": 0, "raw": out.strip()}
    return {"known": True, "blocked": m.group(1) == "BLOCKED", "drops": int(m.group(2) or 0),
            "expires_in": seconds_left(m.group(4)), "raw": out.strip()}


def res(tone, summary, command, output, **extra):
    d = {"tone": tone, "summary": summary, "command": command, "output": output}
    d.update(extra)
    return d


def tail(text):
    return re.sub(r"\n{3,}", "\n\n", text.replace("\r", "")).strip()[-1500:]


def attack(script, port):
    cmd = "bash " + script.replace(os.path.expanduser("~"), "~")
    was_blocked = state().get("blocked", False)
    limit = 30 if was_blocked else 80
    out_file = "/tmp/gui_attack.out"
    timed_out = False
    with open(out_file, "w") as f:
        p = subprocess.Popen(["bash", script], cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
        try:
            p.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            p.kill()
            timed_out = True
    with open(out_file, errors="replace") as f:
        out = f.read()
    if "svr04" in out:
        if port == 2223:
            return res("info", "Attacker reached the open trap on port 2223 and was recorded", cmd, tail(out))
        return res("warn", "Attacker got in on port 2222", cmd, tail(out))
    if timed_out and was_blocked:
        return res("ok", "BLOCKED: attacker could not reach port 2222 (connection dropped)", cmd,
                   "Timed out while 10.77.0.2 was on the block list.\n[check] block list had the IP at attack time: yes")
    note = "Timed out but the IP is NOT blocked, so this is not a block.\n" if timed_out else ""
    return res("bad", "Attack script error", cmd, note + tail(out))


def analyze():
    _, out = sh(["bash", "-c", SCORE], 60)
    found, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)", line)
        if m:
            cur = m.group(1)
            found[cur] = {"score": int(m.group(2)), "decision": m.group(3), "evidence": []}
            continue
        m = re.match(r"\s+\+(\d+)\s+(\w+): behaviors (.*)", line)
        if m and cur:
            name = m.group(2)
            found[cur]["evidence"].append({"name": name, "label": LABELS.get(name, name),
                                           "points": int(m.group(1)),
                                           "rules": [r.strip() for r in m.group(3).split(",")]})
    info = found.get(IP) or (next(iter(found.values())) if found else None)
    cmd = "docker cp trap log, then python -m honeycomb run"
    if not info:
        return res("bad", "No score produced", cmd, tail(out))
    keep = [l for l in out.splitlines() if not l.startswith(("[9]", "[10]"))]
    return res("info", f"Score {info['score']}: {info['decision']}", cmd, tail("\n".join(keep)), analysis=info)


def toggle(fn, ok_text, cmd):
    code = f"from honeycomb.src.blocking import {fn}; print({fn}('{IP}'))"
    _, out = sh([PY, "-c", code], 30)
    if out.strip().endswith("True"):
        return res("ok", ok_text, cmd, out.strip())
    return res("bad", f"{fn} failed", cmd, out.strip())


def block():
    return toggle("block_ip", "Blocked 10.77.0.2 on port 2222 (port 2223 stays open)",
                  f"ssh -i ~/.ssh/honeycomb_blocker honeycomb-blocker@127.0.0.1 block {IP}")


def unblock():
    return toggle("unblock_ip", "Unblocked 10.77.0.2 on port 2222",
                  f"ssh -i ~/.ssh/honeycomb_blocker honeycomb-blocker@127.0.0.1 unblock {IP}")


def verify():
    st = state()
    cmd = f"python -m honeycomb verify {IP}"
    if not st["known"]:
        return res("bad", "Cannot read the firewall", cmd, st["raw"])
    if not st["blocked"]:
        return res("bad", "NOT BLOCKED: 10.77.0.2 is not in the block list", cmd, st["raw"])
    if st["drops"] == 0:
        return res("ok", "BLOCKED, no attack attempted yet (0 packets)", cmd, st["raw"])
    return res("ok", f"BLOCKED, {st['drops']} packets dropped", cmd, st["raw"])


ACTIONS = {"attack2222": lambda: attack(ATK, 2222), "attack2223": lambda: attack(ATK_OPEN, 2223),
           "analyze": analyze, "block": block, "unblock": unblock, "verify": verify}

# --- Wazuh: write every defender action as one JSON line ---
import os as _os, json as _json, datetime as _dt
RESP_LOG = _os.path.expanduser("~/honeycomb-test/data/raw/honeycomb_response.json")
_last = {"score": "not analyzed"}

def _log_response(action, result):
    if not isinstance(result, dict) or result.get("tone") == "bad":
        return
    st = state()
    line = {"honeycomb": "response", "hc_action": action, "ip": IP, "port": "2222",
            "score": _last["score"], "drops": st.get("drops", 0),
            "summary": result.get("summary", ""), "source": "control_panel",
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat()}
    with open(RESP_LOG, "a") as f:
        f.write(_json.dumps(line) + "\n")

def _wrap(name, fn):
    def inner(*a, **k):
        r = fn(*a, **k)
        try:
            if name == "analyze":
                sc = (r.get("analysis") or {}).get("score", r.get("score"))
                if sc is not None: _last["score"] = sc
            else:
                _log_response(name, r)
        except Exception as e:
            print("wazuh log skipped:", e)
        return r
    return inner

for _n in ("analyze", "block", "unblock", "verify"):
    ACTIONS[_n] = _wrap(_n, ACTIONS[_n])



class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            with open(os.path.join(HERE, "demo_gui.html"), encoding="utf-8") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/status":
            self._send(200, json.dumps(state()), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        origin = self.headers.get("Origin")
        if origin and origin != "http://127.0.0.1:8088":
            self._send(403, "{}", "application/json")
            return
        name = self.path.rsplit("/", 1)[-1]
        if not (self.path.startswith("/api/") and name in ACTIONS):
            self._send(404, "{}", "application/json")
            return
        with LOCK:
            result = ACTIONS[name]()
        self._send(200, json.dumps(result), "application/json")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Control panel: http://127.0.0.1:8088   (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8088), Handler).serve_forever()
