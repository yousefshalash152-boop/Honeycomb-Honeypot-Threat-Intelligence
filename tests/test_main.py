import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_run_prints_all_eight_steps():
    result = subprocess.run(
        [sys.executable, "-m", "honeycomb", "run"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0
    assert result.stdout.count("not implemented yet") == 8
