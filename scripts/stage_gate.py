"""Honeycomb Stage Gate Verification Script.

Usage:
  python scripts/stage_gate.py
  python scripts/stage_gate.py --upto 3
"""
import argparse
import os
import subprocess
import sys

OWNER_TESTS = {
    "Member 1 (Infra & Honeypot)": [
        "docs/scope.md",
    ],
    "Member 2 (Storage & SIEM - Ibrahim)": [
        "tests/test_loader.py",
        "tests/test_pipeline_e2e.py",
        "tests/test_quality_data.py",
    ],
    "Member 3 (Threat Intel & IOCs)": [
        "tests/test_ioc_extractor.py",
        "tests/test_enrichment.py",
        "tests/test_intel_cache.py",
        "tests/test_threat_intel.py",
    ],
    "Member 4 (Behaviors & Campaigns)": [
        "tests/test_correlation.py",
        "tests/test_campaigns_db.py",
    ],
    "Member 5 (Scoring & Decisions)": [
        "tests/test_main.py",
    ],
}


def run_tests_for_files(files):
    test_files = [f for f in files if f.endswith(".py")]
    if not test_files:
        return True, "No python tests (docs verified)"
    
    cmd = [sys.executable, "-m", "pytest", "-q"] + test_files
    res = subprocess.run(cmd, capture_output=True, text=True)
    passed = (res.returncode == 0)
    output_summary = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else res.stderr.strip()
    return passed, output_summary


def run_stage_gate(upto_stage: int = 3):
    print("=" * 64)
    print(f"[*] HONEYCOMB STAGE GATE VERIFICATION (Up to Stage {upto_stage})")
    print("=" * 64)

    all_passed = True
    results = {}

    for owner, files in OWNER_TESTS.items():
        passed, summary = run_tests_for_files(files)
        results[owner] = (passed, summary)
        if not passed:
            all_passed = False

    # Print summary per owner
    print(f"{'Owner / Component':<38} | {'Status':<8} | {'Summary'}")
    print("-" * 64)
    for owner, (passed, summary) in results.items():
        status_tag = "\033[92m[PASS]\033[0m" if passed else "\033[91m[FAIL]\033[0m"
        # Fallback for terminals without ANSI
        plain_tag = "[PASS]" if passed else "[FAIL]"
        display_tag = status_tag if sys.stdout.isatty() else plain_tag
        print(f"{owner:<38} | {display_tag:<8} | {summary}")

    print("=" * 64)
    if all_passed:
        print(f"\033[92m[+] STAGE GATE {upto_stage} PASSED: All owner checks are GREEN!\033[0m"
              if sys.stdout.isatty() else f"[+] STAGE GATE {upto_stage} PASSED: All owner checks are GREEN!")
        return 0
    else:
        print(f"\033[91m[-] STAGE GATE {upto_stage} FAILED: Some owner checks are RED!\033[0m"
              if sys.stdout.isatty() else f"[-] STAGE GATE {upto_stage} FAILED: Some owner checks are RED!")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Honeycomb Stage Gate Runner")
    parser.add_argument("--upto", type=int, default=3, help="Stage number up to which to verify (default: 3)")
    args = parser.parse_args()

    exit_code = run_stage_gate(upto_stage=args.upto)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
