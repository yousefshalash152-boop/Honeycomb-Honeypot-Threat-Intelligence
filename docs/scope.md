# Project Scope

Honeycomb is a honeypot that turns real attacks into evidence-based block decisions.
A human analyst approves every block.

## What is inside the project

| Area | What we build |
|---|---|
| Honeypot | Cowrie on an Azure Linux VM. Port 22 is the trap, open to everyone. |
| Log collection | The lab PULLS logs from the server on a schedule. The server never contacts the lab. |
| Cleaning | Every log line becomes one fixed Event shape and is stored in SQLite. Loading the same file twice creates no duplicates. |
| Indicators | IPs, URLs and file hashes are extracted from events. |
| Enrichment | AbuseIPDB for IPs and VirusTotal for hashes. Answers are cached for 24 hours. |
| Behavior | Simple rules say what the attacker did: password guessing, recon, download, execution, persistence. Each rule maps to a MITRE ATT&CK technique. |
| Correlation | Sessions from different IPs that share a file hash, a download URL or the same commands are grouped into a suspected campaign. |
| Scoring | Each piece of evidence has points in config/scoring.yaml. Total is 0 to 100. 70+ is a block candidate, 40-69 is monitor, below 40 is log. |
| Decision and block | An analyst approves with a name and a reason. The IP is then blocked on the protected service (port 2222). |
| Verification | A counter proves the blocked IP came back and was stopped. |
| Reports | One command builds an incident report. A local AI model (Ollama) writes a DRAFT summary that a human reviews. |
| SIEM | Wazuh reads the same logs and raises alerts next to our pipeline. |
| Evaluation | False positives, false negatives, correlation accuracy, enrichment rate, block verification and AI accuracy, all from one script. |

## What is outside the project (future work)

- DDoS detection
- Running malware in a sandbox (samples are never executed)
- TheHive and Shuffle
- Any machine learning

## Rules we keep

- The AI never scores, never blocks and never sees raw logs.
- We say "suspected campaign", never "the same attacker".
- Team IPs are on the whitelist and are never blocked.
- No keys, passwords, real logs, PCAPs, databases or malware in the repo.

## Definition of done (MVP)

A real IP from the honeypot passes through the whole chain: cleaning, indicators, enrichment, behavior, score with reasons, analyst approval, block on port 2222, counter proof, and a report from one command.

## Timeline

| Stage | Dates | Goal |
|---|---|---|
| 1 | Oct 13-17 | Foundation and live honeypot |
| 2 | Oct 18-23 | From logs to information |
| 3 | Oct 24-29 | Understanding and decision |
| 4 | Oct 30 - Nov 4 | Reports, dashboard and AI |
| 5 | Nov 5-11 | Evaluation and delivery (code freeze Nov 9, delivery Nov 12) |
