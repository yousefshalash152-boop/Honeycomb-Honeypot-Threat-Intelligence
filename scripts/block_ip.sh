#!/usr/bin/env bash
# Server-side IP block control for Honeycomb.
# Allowed requests, and nothing else:  block <ipv4> | unblock <ipv4> | verify <ipv4> | list
# The request comes from SSH_ORIGINAL_COMMAND (restricted-key mode) or from the arguments (manual mode).
set -euo pipefail

SET="${HONEYCOMB_SET:-honeycomb-block}"
WHITELIST="${HONEYCOMB_WHITELIST:-config/whitelist.yaml}"

die() { echo "ERROR: $1" >&2; exit "${2:-1}"; }

# Root runs ipset directly; the restricted ssh user goes through sudo (see docs/blocking.md).
if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo -n); fi
ipset_cmd() {
  if [ -n "${HONEYCOMB_DRY_RUN:-}" ]; then
    echo "DRY: ipset $*"
  else
    ${SUDO[@]+"${SUDO[@]}"} ipset "$@"
  fi
}

# Attacker-controlled text only ever gets MATCHED against strict patterns, never executed.
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  read -r -a ARGS <<< "$SSH_ORIGINAL_COMMAND"
else
  ARGS=("$@")
fi
[ "${#ARGS[@]}" -le 2 ] || die "too many arguments" 1
ACTION="${ARGS[0]:-}"
IP="${ARGS[1]:-}"

valid_ip() {
  local octet='(0|[1-9][0-9]{0,2})'
  [[ "$1" =~ ^${octet}\.${octet}\.${octet}\.${octet}$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do
    [ "$o" -le 255 ] || return 1
  done
  local first="${BASH_REMATCH[1]}"
  # never 0.x, loopback, multicast or reserved ranges
  if [ "$first" -eq 0 ] || [ "$first" -eq 127 ] || [ "$first" -ge 224 ]; then return 1; fi
}

is_whitelisted() {
  [ -f "$WHITELIST" ] || die "whitelist file not found: $WHITELIST (refusing to block without it)" 3
  # No -q on the second grep, so the first one is never cut off by SIGPIPE.
  grep -vE '^[[:space:]]*#' "$WHITELIST" | grep -wF -- "$1" > /dev/null
}

case "$ACTION" in
  block)
    valid_ip "$IP" || die "invalid or disallowed IPv4 address" 2
    if is_whitelisted "$IP"; then die "$IP is whitelisted - refusing to block" 3; fi
    ipset_cmd add "$SET" "$IP" -exist
    echo "BLOCKED $IP"
    ;;
  unblock)
    valid_ip "$IP" || die "invalid or disallowed IPv4 address" 2
    ipset_cmd del "$SET" "$IP" -exist
    echo "UNBLOCKED $IP"
    ;;
  verify)
    valid_ip "$IP" || die "invalid or disallowed IPv4 address" 2
    line="$(ipset_cmd list "$SET" | grep -E "^${IP//./\\.} " || true)"
    if [ -z "$line" ]; then echo "NOT_BLOCKED $IP"; exit 4; fi
    echo "BLOCKED $line"
    ;;
  list)
    ipset_cmd list "$SET"
    ;;
  *)
    die "usage: block <ip> | unblock <ip> | verify <ip> | list" 1
    ;;
esac
