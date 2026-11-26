from honeycomb.src.correlation import find_campaigns, merge_campaigns

CMDS = ["uname -a", "whoami", "cat /etc/passwd"]

SESSIONS = [
    {"session_id": "A", "src_ip": "1.1.1.1", "hashes": ["aaa"], "urls": [], "commands": []},
    {"session_id": "B", "src_ip": "2.2.2.2", "hashes": ["aaa"], "urls": [], "commands": CMDS},
    {"session_id": "C", "src_ip": "3.3.3.3", "hashes": [], "urls": [], "commands": CMDS},
    {"session_id": "D", "src_ip": "4.4.4.4", "hashes": ["zzz"], "urls": [], "commands": ["ls"]},
]


def test_chain_merges_into_one_campaign():
    merged = merge_campaigns(find_campaigns(SESSIONS))
    assert len(merged) == 1
    assert merged[0]["sessions"] == ["A", "B", "C"]
    assert merged[0]["rules"] == ["C1", "C3"]


def test_unrelated_session_not_included():
    merged = merge_campaigns(find_campaigns(SESSIONS))
    assert "D" not in merged[0]["sessions"]


def test_two_rules_raise_confidence():
    merged = merge_campaigns(find_campaigns(SESSIONS))
    assert merged[0]["confidence"] == "very_high"


def test_running_twice_gives_same_result():
    first = merge_campaigns(find_campaigns(SESSIONS))
    second = merge_campaigns(find_campaigns(SESSIONS))
    assert first == second
