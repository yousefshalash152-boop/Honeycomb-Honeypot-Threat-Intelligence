# Threat Model

What can go wrong, and how we protect against it.

## What we protect

- The team's machines, keys and personal data
- The API keys (AbuseIPDB, VirusTotal)
- The integrity of our data and decisions
- Legitimate users, who must never be blocked by mistake

## Who we worry about

- Attackers who hit the honeypot (the expected case)
- An attacker who tries to escape the honeypot or abuse the VM
- An attacker who types text meant to trick our code or our AI

## Ports

| Port | Purpose | Who can reach it |
|---|---|---|
| 22 | Honeypot (Cowrie) | Everyone |
| 22222 | Real SSH for administration | Team IPs only, key login only |
| 2222 | Protected service where blocking is applied | Everyone except blocked IPs |

## Threats and protections

| Threat | Why it matters | Protection |
|---|---|---|
| Attacker escapes the honeypot | They could reach the VM or our network | Cowrie runs in Docker. No keys or personal data on the VM. No link to home or university networks. VM snapshot to rebuild. |
| VM used to attack others | Legal and reputation risk | Outbound traffic limited to what is needed. Azure budget alert. |
| Server used to reach our lab | Lab compromise | The lab pulls logs. The server never connects to the lab. |
| Keys or real data pushed to GitHub | The repo is public | .env is in .gitignore. CI fails if .env, PCAP or database files are committed. A leaked key is rotated immediately. |
| Malware sample executed by accident | Infects a team machine | Samples are never executed or opened outside the server. VirusTotal lookups use the hash only, no uploads. Samples stay in a password-protected zip on the server. |
| Attacker text tricks the AI (prompt injection) | Wrong or manipulated report | The AI gets structured facts only, never raw logs. It writes a draft only. A human checks every sentence. It cannot decide or block. |
| Attacker text breaks the dashboard or report (HTML or script injection) | Code runs in the analyst's browser | Commands and usernames are shown as plain text only. Unsafe HTML is disabled. |
| An innocent IP gets blocked | Real users lose access | Whitelist for team IPs. Analyst approval with a name and a reason. Threshold of 70. Rollback is tested. Shared IPs (NAT, VPN) are a known limit. |
| Attacker inflates the score with volume | Wrong block candidates | Each type of evidence counts once per IP per 24 hours. 300 failed logins count as one evidence. |
| API limit or outage | Missing reputation data | 24-hour cache. On errors the result is "unknown". No result means no reports, not that the IP is clean. |
| Lost or messy data | Wrong numbers | Persistent Docker volumes. Daily archive with SHA-256. All times in UTC. Line count check: lines = events + duplicates + errors. |
| Lockout from the server | We cannot manage the VM | Key-only SSH, root login disabled, one user per member. The blocking key can only update the block list. |

## Known limits

- Blocking works per IP. Attackers who change IPs are only caught through campaign grouping, which is a suspicion, not proof.
- Wazuh and Honeycomb must read the same number of events. A difference is investigated, not ignored.
