# Attack Mapping: Behavior Rules → MITRE ATT&CK

Owner: Member 4 · Stage 1 (draft on paper) · Stage 2: implemented in `honeycomb/src/behavior.py`

Input: Cowrie events per session (`cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, `cowrie.session.file_upload`, `cowrie.client.version`).
Output: a list of behaviors per session, each tied to one ATT&CK technique.

## Rule table

| Rule ID | Behavior | Trigger (draft) | ATT&CK technique | Tactic |
|---|---|---|---|---|
| B01 | Password guessing | ≥ 5 `login.failed` in one session or from one IP within a short window | T1110.001 Password Guessing | Credential Access |
| B02 | Credential stuffing / known-default creds | A **successful** login using a short list of default pairs (root/root, admin/admin, root/123456...). A failed default pair alone does not count | T1110.004 Credential Stuffing | Credential Access |
| B03 | Successful login after guessing | `login.success` preceded by ≥ 1 `login.failed` | T1078 Valid Accounts | Initial Access |
| B04 | System discovery | Commands: `uname`, `whoami`, `id`, `hostname`, `cat /etc/os-release`, `lscpu`, `cat /proc/cpuinfo` | T1082 System Information Discovery | Discovery |
| B05 | Account discovery | `cat /etc/passwd` alone, or 2 or more of `w`, `who`, `last` | T1087.001 Local Account Discovery | Discovery |
| B06 | Network discovery | `ifconfig`, `ip a`, `netstat`, `ss`, `cat /etc/hosts` | T1016 System Network Configuration Discovery | Discovery |
| B07 | Process discovery | `ps`, `top`, `ps aux` | T1057 Process Discovery | Discovery |
| B08 | Tool download | `wget` / `curl` / `tftp` command, or `session.file_download` | T1105 Ingress Tool Transfer | Command and Control |
| B09 | Execute downloaded file | `chmod +x` then `./file`, `sh file`, `bash file` | T1059.004 Unix Shell | Execution |
| B10 | Persistence via cron | `crontab`, writing to `/etc/cron*` | T1053.003 Cron | Persistence |
| B11 | Persistence via SSH key | Appending to `~/.ssh/authorized_keys` | T1098.004 SSH Authorized Keys | Persistence |
| B12 | Account creation / password change | `useradd`, `adduser`, `passwd` | T1136.001 Local Account | Persistence |
| B13 | Hide traces | `history -c`, `rm ~/.bash_history`, `unset HISTFILE` | T1070.003 Clear Command History | Defense Evasion |
| B14 | Kill competing miners / security tools | `pkill`, `killall`, `kill -9` on names like `xmrig`, `minerd` | T1562.001 Disable or Modify Tools | Defense Evasion |
| B15 | Pivot / scan from honeypot | `nmap`, `masscan`, `nc` to other hosts | T1046 Network Service Discovery | Discovery |

## Notes per rule (to decide with the team)

- **B01 threshold:** 5 is a starting point. After real data arrives (Stage 2), check the distribution and adjust. Document the final number.
- **B03:** Cowrie accepts some logins by design, so `login.success` alone is not an attack signal. It only matters combined with B01.
- **B04–B07:** A single discovery command is weak evidence (a curious user could run `whoami`). Suggestion: flag the behavior only when ≥ 2 commands from the same category appear in a session.
- **B14:** Killing miners or security tools maps to T1562.001.
- Each rule must store: `rule_id`, `technique_id`, `evidence` (the exact event/command that triggered it), `session_id`.

## Bot vs human hint (used in Stage 4 report)

| Signal | Leans bot | Leans human |
|---|---|---|
| Time between commands | < 1 s, constant | seconds, irregular |
| Command sequence | Identical to other sessions | Unique, typos, corrections |
| Session length | Very short, fixed script | Longer, exploratory |

Always state the limits: this is a hint, not a proof.

## Correlation rules (Stage 3 draft, for reference)

| Rule | Description | Minimum evidence |
|---|---|---|
| C01 | Same downloaded file hash across sessions from different IPs | Same SHA-256 |
| C02 | Same download URL | Same URL |
| C03 | Same command sequence | Identical ordered list of commands (after normalization) |

Each campaign stores: the rules that matched, the session list, and a confidence level (high for C01, medium for C02/C03 alone, higher when 2+ rules match).

## Thresholds (Stage 1 values, reviewed again with real data in Stage 2)

- B01: 5 failed logins in one session
- B04, B06, B07: flagged when 2 or more commands of the same category appear in the session
- B05: `cat /etc/passwd` is enough alone (S1 expects it); `w`/`who`/`last` need 2 commands
- B02: counts only a successful login with a default pair (a failed admin/admin in S6 must not fire it)
- B03: counts only when B01 fired in the same session

## Log event that proves each rule
| Rule | Event in the Cowrie log |
| --- | --- |
| B01 | `cowrie.login.failed` |
| B02 | `cowrie.login.success` |
| B03 | `cowrie.login.failed` then `cowrie.login.success` |
| B04-B07 | `cowrie.command.input` |
| B08 | `cowrie.command.input` or `cowrie.session.file_download` |
| B09-B15 | `cowrie.command.input` |

## Fact vs inference
| Fact (in the log) | Inference (our conclusion) |
| --- | --- |
| 5 or more `login.failed` in one session | Automated password guessing (B01) |
| `login.success` after failures | The attacker got past the trap's login (B03), not that the password was valid |
| `session.file_download` with a SHA-256 | A tool was downloaded (B08) |
| Same SHA-256 in two sessions | A suspected campaign, not "the same attacker" |
