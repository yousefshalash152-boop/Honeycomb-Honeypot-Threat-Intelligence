# Wazuh SIEM Integration with Cowrie Honeypot

## Overview
This section covers the integration of Cowrie Honeypot with Wazuh SIEM using Docker containers on WSL 2 to monitor, detect, and visualize unauthorized SSH/Telnet security incidents.

## Key Configurations
- **Log Path:** `/var/ossec/logs/cowrie/cowrie.json` (Direct ingestion from live JSON output to prevent log duplication).
- **Custom Detection Rules:** Integrated custom security rules via `honeycomb_rules.xml`.
- **Environment:** Containerized deployment using Docker Compose.

## Verification & Attack Simulation
Simulated multiple unauthorized login attempts and brute-force events to test detection logic:
1. Triggered authentication failures over SSH/Telnet ports.
2. Verified live alert generation in **Wazuh Dashboard** under **Threat Intelligence / Events**.
3. Captured severity-level distributions and rule trigger alerts.

## Repository Structure
- `honeycomb_rules.xml`: Custom Wazuh rules for Cowrie event parsing.
- `screenshots/`: Dashboard evidence of simulated threats and alerts.