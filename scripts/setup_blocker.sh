#!/usr/bin/env bash
# One-time setup on the honeypot host: a locked-down user whose ONLY power is scripts/block_ip.sh.
# Usage: sudo scripts/setup_blocker.sh <public-key-file> [allowed-source-ip]
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run with sudo" >&2; exit 1; }
PUB="${1:?usage: $0 <public-key-file> [allowed-source-ip]}"
FROM="${2:-127.0.0.1,::1}"   # only this source may use the key (lab default: this machine)
USER_NAME=honeycomb-blocker
DEST=/opt/honeycomb
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IPSET="$(command -v ipset)" || { echo "ERROR: ipset is not installed" >&2; exit 1; }

[ -f "$PUB" ] || { echo "ERROR: key file not found: $PUB" >&2; exit 1; }
KEY="$(head -n 1 "$PUB")"
case "$KEY" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
  *) echo "ERROR: $PUB does not look like a PUBLIC ssh key (never use the private one)" >&2; exit 1 ;;
esac

# 1. the user: key login only, no password
id "$USER_NAME" > /dev/null 2>&1 || useradd --system --create-home --shell /bin/bash "$USER_NAME"
usermod -p '*' "$USER_NAME"

# 2. the script and whitelist, owned by root so the user cannot edit them
install -d -m 755 -o root -g root "$DEST"
install -m 755 -o root -g root "$HERE/scripts/block_ip.sh" "$DEST/block_ip.sh"
install -m 644 -o root -g root "$HERE/config/whitelist.yaml" "$DEST/whitelist.yaml"

# 3. sudo: the user may run ONLY these ipset commands on this one set
TMP="$(mktemp)"
printf '%s ALL=(root) NOPASSWD: %s add honeycomb-block *, %s del honeycomb-block *, %s list honeycomb-block\n' \
  "$USER_NAME" "$IPSET" "$IPSET" "$IPSET" > "$TMP"
visudo -cf "$TMP" > /dev/null
install -d -m 750 -o root -g root /etc/sudoers.d
install -m 440 -o root -g root "$TMP" "/etc/sudoers.d/$USER_NAME"
rm -f "$TMP"

# 4. the key: forced command, no pty, no forwarding, limited source
SSHDIR="/home/$USER_NAME/.ssh"
install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$SSHDIR"
printf 'from="%s",restrict,command="HONEYCOMB_WHITELIST=%s/whitelist.yaml %s/block_ip.sh" %s\n' \
  "$FROM" "$DEST" "$DEST" "$KEY" > "$SSHDIR/authorized_keys"
chown "$USER_NAME:$USER_NAME" "$SSHDIR/authorized_keys"
chmod 600 "$SSHDIR/authorized_keys"

echo "SETUP_BLOCKER_OK  (user=$USER_NAME, scripts in $DEST, key allowed from $FROM)"
