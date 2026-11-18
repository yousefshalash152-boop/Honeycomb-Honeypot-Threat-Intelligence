import subprocess
import sys
from pathlib import Path

from honeycomb.src.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]
SCEN = ROOT / "tests" / "fixtures" / "scenarios"


def _all_scenarios(tmp_path):
    log = tmp_path / "all.jsonl"
    log.write_text("".join(f.read_text(encoding="utf-8")
                           for f in sorted(SCEN.glob("S*.jsonl"))), encoding="utf-8")
    return log


def test_pipeline_scores_the_labeled_scenarios(tmp_path):
    results = run_pipeline(str(_all_scenarios(tmp_path)), str(tmp_path / "t.db"),
                           enrich=False, out=lambda *_: None)
    by_ip = {r["ip"]: r for r in results}
    assert by_ip["203.0.113.10"]["score"] == 65    # S1: attack
    assert by_ip["198.51.100.7"]["score"] == 45    # S2: attack
    assert by_ip["198.51.100.200"]["score"] == 0   # S5: scanner, not an attack
    assert by_ip["192.0.2.150"]["score"] == 0      # S6: curious user, not an attack
    assert all(r["action"] != "BLOCK_CANDIDATE" for r in results)


def test_pipeline_twice_gives_the_same_scores(tmp_path):
    log, db = str(_all_scenarios(tmp_path)), str(tmp_path / "t.db")
    first = run_pipeline(log, db, enrich=False, out=lambda *_: None)
    second = run_pipeline(log, db, enrich=False, out=lambda *_: None)
    assert [(r["ip"], r["score"]) for r in first] == [(r["ip"], r["score"]) for r in second]


def test_every_score_comes_with_reasons(tmp_path):
    results = run_pipeline(str(_all_scenarios(tmp_path)), str(tmp_path / "t.db"),
                           enrich=False, out=lambda *_: None)
    for r in results:
        assert r["evidence"] or r["score"] == 0
        assert sum(e["points"] for e in r["evidence"]) == r["score"]


def test_cli_with_input_runs_the_real_steps(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "honeycomb", "run", "--input",
         str(_all_scenarios(tmp_path)), "--db", str(tmp_path / "c.db"), "--no-enrich"],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0
    assert "[8] score: 6 IPs" in result.stdout
    assert "[9] decide: not implemented yet" in result.stdout
