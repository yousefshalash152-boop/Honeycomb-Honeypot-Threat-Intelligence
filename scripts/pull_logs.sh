#!/usr/bin/env bash
# Pull the Cowrie log from the honeypot into data/raw/ (never committed).
# Keeps ONE growing file, data/raw/cowrie.json, and adds only the events it does not have yet.
# Safe to run every minute (cron): nothing is duplicated, and Wazuh can follow the file.
# Usage:
#   scripts/pull_logs.sh <VM_IP> <ADMIN_PORT> <ADMIN_USER>   # real VM over SSH
#   scripts/pull_logs.sh local                               # local test container
#   SNAPSHOT=1 scripts/pull_logs.sh local                    # also keep a timestamped full copy
# The Cowrie image has no cat/ls, so we read the log with Python inside it.
set -euo pipefail

LOG_PATH="/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
PY="import sys; sys.stdout.write(open('${LOG_PATH}').read())"

usage() { echo "Usage: $0 <VM_IP> <ADMIN_PORT> <ADMIN_USER> | local" >&2; exit 1; }

if [[ "${1:-}" == "local" && $# -eq 1 ]]; then
  pull() { docker exec honeycomb-cowrie python -c "$PY"; }
elif [[ $# -eq 3 ]]; then
  VM_IP=$1; PORT=$2; ADMIN=$3
  REMOTE_CMD="docker exec honeycomb-cowrie python -c \"$PY\""
  pull() { ssh -p "$PORT" "$ADMIN@$VM_IP" "$REMOTE_CMD"; }
else
  usage
fi

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data/raw"
MASTER="$OUT_DIR/cowrie.json"
mkdir -p "$OUT_DIR"

# One pull at a time (cron every minute must not overlap with a slow run).
exec 9> "$OUT_DIR/.pull.lock"
if ! flock -n 9; then
  echo "Another pull is still running. Skipping this one."
  exit 0
fi

TMP="$(mktemp "$OUT_DIR/.pull.XXXXXX")"
NEW="$(mktemp "$OUT_DIR/.new.XXXXXX")"
trap 'rm -f "$TMP" "$NEW"' EXIT

if ! pull > "$TMP"; then
  echo "Pull failed (ssh or docker error). Nothing saved." >&2
  exit 1
fi
if [[ ! -s "$TMP" ]]; then
  echo "Connected, but there are no events yet. Nothing saved."
  exit 0
fi

# Cowrie may be in the middle of writing a line: drop an unfinished last line, we get it next time.
if [[ -n "$(tail -c 1 "$TMP")" ]]; then
  sed -i '$d' "$TMP"
fi

touch "$MASTER"
# New lines = lines in this pull that master does not have yet (works even if master is empty).
awk 'FILENAME == ARGV[1] { seen[$0] = 1; next } !($0 in seen) { print; seen[$0] = 1 }' \
  "$MASTER" "$TMP" > "$NEW"
COUNT="$(wc -l < "$NEW")"

if [[ "${SNAPSHOT:-0}" == "1" ]]; then
  cp "$TMP" "$OUT_DIR/cowrie-$(date +%Y%m%d-%H%M%S).json"
fi

if [[ "$COUNT" -eq 0 ]]; then
  echo "No new events. $MASTER has $(wc -l < "$MASTER") lines."
  exit 0
fi
cat "$NEW" >> "$MASTER"
echo "Added $COUNT new events to $MASTER (total $(wc -l < "$MASTER") lines)"
