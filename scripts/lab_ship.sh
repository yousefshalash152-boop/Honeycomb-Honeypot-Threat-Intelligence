#!/usr/bin/env bash
# Copy the cowrie-lab log into data/raw/cowrie.json (append-only, no duplicates)
set -euo pipefail
OUT="${OUT:-data/raw/cowrie.json}"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
docker cp cowrie-lab:/cowrie/cowrie-git/var/log/cowrie/cowrie.json "$TMP" >/dev/null
touch "$OUT"
NEW="$(grep -vxFf "$OUT" "$TMP" || true)"
if [ -n "$NEW" ]; then printf '%s\n' "$NEW" >> "$OUT"; fi
COUNT="$(printf '%s' "$NEW" | grep -c . || true)"
echo "Added $COUNT new line(s) to $OUT"
