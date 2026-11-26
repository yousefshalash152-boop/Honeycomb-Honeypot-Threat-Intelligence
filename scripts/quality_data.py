"""Honeycomb Stage 3: Data Quality Verification Script.

Verifies:
1. lines == events + duplicates + errors
2. all times UTC
3. no time gap over 2 hours between consecutive events
"""
import os
import sys
from datetime import datetime, timezone

# Ensure project root is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from honeycomb.src.storage.normalizer import normalize_line


def check_data_quality(log_path: str) -> dict:
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    lines = 0
    events = 0
    duplicates = 0
    errors = 0
    seen_ids = set()
    timestamps = []
    non_utc_count = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            lines += 1
            line_str = raw_line.strip()
            if not line_str:
                errors += 1
                continue

            row = normalize_line(raw_line)
            if row is None:
                errors += 1
                continue

            # Event ID & Duplicates check
            eid = row.get("event_id")
            if eid in seen_ids:
                duplicates += 1
            else:
                seen_ids.add(eid)
                events += 1

            # Timestamp UTC check
            ts_str = row.get("ts_utc")
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
                    non_utc_count += 1
                else:
                    timestamps.append(dt)
            except Exception:
                non_utc_count += 1

    # Invariant 1: lines == events + duplicates + errors
    balance_passed = (lines == (events + duplicates + errors))

    # Invariant 2: all times UTC
    utc_passed = (non_utc_count == 0)

    # Invariant 3: no gap over 2 hours (7200 seconds)
    timestamps.sort()
    max_gap_seconds = 0
    gap_violations = []

    for i in range(len(timestamps) - 1):
        delta = (timestamps[i + 1] - timestamps[i]).total_seconds()
        if delta > max_gap_seconds:
            max_gap_seconds = delta
        if delta > 7200:  # 2 hours
            gap_violations.append((timestamps[i], timestamps[i + 1], delta))

    continuity_passed = (len(gap_violations) == 0)
    overall_passed = balance_passed and utc_passed and continuity_passed

    return {
        "log_path": log_path,
        "lines": lines,
        "events": events,
        "duplicates": duplicates,
        "errors": errors,
        "balance_passed": balance_passed,
        "non_utc_count": non_utc_count,
        "utc_passed": utc_passed,
        "max_gap_seconds": max_gap_seconds,
        "gap_violations": gap_violations,
        "continuity_passed": continuity_passed,
        "overall_passed": overall_passed,
    }


def print_report(res: dict) -> None:
    print("=" * 62)
    print("  HONEYCOMB STAGE 3: DATA QUALITY REPORT")
    print("=" * 62)
    print(f"Log File:               {res['log_path']}")
    print(f"Total Lines Processed:  {res['lines']}")
    print(f"  - Valid Events:       {res['events']}")
    print(f"  - Duplicate Events:   {res['duplicates']}")
    print(f"  - Corrupt / Errors:   {res['errors']}")
    print("-" * 62)
    print("Quality Invariants:")
    
    b_tag = "[+]" if res["balance_passed"] else "[-]"
    print(f" {b_tag} lines == events + duplicates + errors: {'PASSED' if res['balance_passed'] else 'FAILED'}")
    
    u_tag = "[+]" if res["utc_passed"] else "[-]"
    print(f" {u_tag} All timestamps in UTC:                 {'PASSED' if res['utc_passed'] else 'FAILED'}")
    
    c_tag = "[+]" if res["continuity_passed"] else "[-]"
    max_gap_min = res["max_gap_seconds"] / 60.0
    print(f" {c_tag} No gap over 2 hours (Max gap: {max_gap_min:.1f}m):    {'PASSED' if res['continuity_passed'] else 'FAILED'}")
    
    if res["gap_violations"]:
        print(f"     Warning: Found {len(res['gap_violations'])} gaps exceeding 2 hours!")

    print("=" * 62)
    if res["overall_passed"]:
        print("  [+] STAGE 3 DATA QUALITY GATE: PASSED")
    else:
        print("  [-] STAGE 3 DATA QUALITY GATE: FAILED")
    print("=" * 62)


def main():
    target = None
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Default fallback to sample test logs
        default_candidates = [
            os.path.join(PROJECT_ROOT, "tests", "sample.jsonl"),
            os.path.join(PROJECT_ROOT, "tests", "fixtures", "scenarios", "S1.jsonl"),
        ]
        for c in default_candidates:
            if os.path.isfile(c):
                target = c
                break

    if not target or not os.path.isfile(target):
        print("[-] Error: No valid log file provided or found.")
        print("Usage: python scripts/quality_data.py <path_to_log.jsonl>")
        sys.exit(1)

    result = check_data_quality(target)
    print_report(result)
    sys.exit(0 if result["overall_passed"] else 1)


if __name__ == "__main__":
    main()
