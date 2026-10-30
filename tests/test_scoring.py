import json
from pathlib import Path

import pytest

from honeycomb.src.scoring import score_ip

ROOT = Path(__file__).resolve().parents[1]
SCEN = ROOT / "tests" / "fixtures" / "scenarios"


def cfg(weight, max_score=100):
    """Tiny config with ONE evidence type, to test the thresholds."""
    return {"max_score": max_score,
            "thresholds": {"monitor": 40, "block_candidate": 70},
            "evidence": {"login_success": weight}}


@pytest.mark.parametrize("weight, score, action", [
    (39, 39, "LOG"),
    (40, 40, "MONITOR"),
    (69, 69, "MONITOR"),
    (70, 70, "BLOCK_CANDIDATE"),
    (100, 100, "BLOCK_CANDIDATE"),
])
def test_threshold_boundaries(weight, score, action):
    r = score_ip("9.9.9.9", {"B03"}, config=cfg(weight), whitelist=[])
    assert (r["score"], r["action"]) == (score, action)


def test_score_never_exceeds_max():
    r = score_ip("9.9.9.9", {"B03"}, config=cfg(150), whitelist=[])
    assert r["score"] == 100


def test_full_attack_scores_90():
    # brute force 20 + login 20 + recon 10 + download 25 + persistence 15
    r = score_ip("1.1.1.1", {"B01", "B03", "B04", "B08", "B11"}, whitelist=[])
    assert r["score"] == 90
    assert r["action"] == "BLOCK_CANDIDATE"
    assert sum(e["points"] for e in r["evidence"]) == 90


def test_brute_force_only_scores_20():
    r = score_ip("1.1.1.1", {"B01"}, whitelist=[])
    assert (r["score"], r["action"]) == (20, "LOG")


def test_no_behavior_scores_0():
    r = score_ip("1.1.1.1", set(), whitelist=[])
    assert (r["score"], r["evidence"], r["action"]) == (0, [], "LOG")


def test_each_evidence_type_counts_once():
    r = score_ip("1.1.1.1", {"B01", "B02", "B04", "B05", "B06"}, whitelist=[])
    assert r["score"] == 30  # 20 (B01+B02 once) + 10 (B04+B05+B06 once)


def test_reputation_adds_points_and_unknown_adds_nothing():
    bad = score_ip("1.1.1.1", set(),
                   {"abuse_score": 80, "vt_malicious": 5}, whitelist=[])
    unknown = score_ip("1.1.1.1", set(),
                       {"abuse_score": None, "vt_malicious": None}, whitelist=[])
    assert bad["score"] == 45   # 20 + 25
    assert unknown["score"] == 0


def test_campaign_member_adds_points():
    r = score_ip("1.1.1.1", set(), campaign=True, whitelist=[])
    assert r["score"] == 10


def test_whitelisted_ip_is_never_a_block_candidate():
    r = score_ip("5.5.5.5", {"B01", "B03", "B04", "B08", "B11"},
                 whitelist=["5.5.5.5"])
    assert r["score"] == 90
    assert r["action"] == "LOG" and r["whitelisted"] is True


def test_every_evidence_has_reason_and_points():
    r = score_ip("1.1.1.1", {"B01", "B08"}, whitelist=[])
    assert all(e["reason"] and e["points"] > 0 for e in r["evidence"])


def _scenario_ip(name):
    first = (SCEN / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()[0]
    return json.loads(first)["src_ip"]


@pytest.mark.parametrize("name, score, action", [
    ("S1", 65, "MONITOR"),   # 20 + 20 + 10 + 15
    ("S2", 45, "MONITOR"),   # 20 + 25
    ("S3", 45, "MONITOR"),
    ("S4", 45, "MONITOR"),
    ("S5", 0, "LOG"),        # port scanner: false-positive check
    ("S6", 0, "LOG"),        # curious user: false-positive check
])
def test_labeled_scenarios(name, score, action):
    expected = json.loads((SCEN / "expected.json").read_text(encoding="utf-8"))
    r = score_ip(_scenario_ip(name), expected[name]["behaviors"], whitelist=[])
    assert (r["score"], r["action"]) == (score, action)
    if expected[name]["label"] == "not_attack":
        assert r["action"] != "BLOCK_CANDIDATE"
