"""Print real sessions next to the behaviors the program found, for the
manual review in docs/stages/stage-2.md.

    python scripts/review_sessions.py data/honeycomb.db --n 5 --seed 1

Read the commands first, write what the attacker did in your own words,
THEN compare with the program's list.
"""
import argparse
import random
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honeycomb.src.behavior import detect_behaviors, load_session_events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--min-events", type=int, default=4,
                    help="skip sessions that only connect and leave")
    a = ap.parse_args()

    sessions = load_session_events(sqlite3.connect(a.db))
    pool = [s for s, evs in sessions.items() if len(evs) >= a.min_events]
    random.Random(a.seed).shuffle(pool)
    for sid in pool[: a.n]:
        evs = sessions[sid]
        print("=" * 70)
        print("session:", sid, "| events:", len(evs))
        for e in evs:
            what = e["command"] or e["url"] or e["username"] or ""
            print(f"  {e['event_type']:<30} {what}")
        hits = detect_behaviors(evs, sid)
        print("program says:", ", ".join(h["rule_id"] for h in hits) or "(nothing)")


if __name__ == "__main__":
    main()
