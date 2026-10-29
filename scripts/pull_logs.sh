#!/usr/bin/env bash
# Pull the Cowrie log from the honeypot into data/raw/ (never committed).
# Usage:
#   scripts/pull_logs.sh <VM_IP> <ADMIN_PORT> <ADMIN_USER>   # real VM over SSH
#   scripts/pull_logs.sh local                               # local test container
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
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/cowrie-$(date +%Y%m%d-%H%M%S).json"
TMP="$(mktemp "$OUT_DIR/.pull.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

if ! pull > "$TMP"; then
  echo "Pull failed (ssh or docker error). Nothing saved." >&2
  exit 1
fi
if [[ ! -s "$TMP" ]]; then
  echo "Connected, but there are no events yet. Nothing saved."
  exit 0
fi
mv "$TMP" "$OUT"
trap - EXIT
echo "Saved $OUT ($(wc -l < "$OUT") lines)"
