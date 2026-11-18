# Stage 2 - Behavior rules and manual review

Owner: Member 4 · Reviewer: Member 3

## What was built
- `honeycomb/src/behavior.py`: rules B01-B15, each tied to an ATT&CK technique and returning the evidence (the exact command/event).
- `behaviors` table (proposal, agreed with Members 2 and 5): `session_id, rule_id, behavior, technique_id, tactic, evidence, event_id`.
- `tests/test_behavior.py`: a test per rule + the 6 labeled scenarios against `expected.json`.

## Rule decisions
- B02 counts only a **successful** login with a default pair. A failed `admin/admin` alone is not B02 (S6 must stay clean).
- B05: reading `/etc/passwd` is strong enough alone; `w` / `who` / `last` need 2 commands.
- B04, B06, B07: need 2 commands of the same category.
- B03: only when B01 fired in the same session.
- B09: `chmod` on a file, then running that same file.

## Manual review of 5 real sessions
Run: `python scripts/review_sessions.py data/honeycomb.db --n 5 --seed 1`

Write "what the attacker did" BEFORE looking at "program says".

| # | session_id | What the attacker did (my words) | Program says | Match? | Notes |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

## Thresholds after real data
- B01 (5 failed logins): kept / changed to ___ because ___.

## Mismatches found and fixed
- (write each rule that was wrong on real data, and what changed)
