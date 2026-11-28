#!/usr/bin/env bash
# One-command demo: block -> attack fails -> counter -> rollback -> attack works
set -u
IP="${IP:-10.77.0.2}"
SRC=scripts/lab_attack.sh; [ -f "$SRC" ] || SRC=/tmp/lab_attack.sh
ATK="$(mktemp)"; trap 'rm -f "$ATK"' EXIT
sed 's/^PORT=.*/PORT=2222/' "$SRC" > "$ATK"; chmod +x "$ATK"
step() { echo; echo "=== $* ==="; }
python -c "from honeycomb.src.blocking import unblock_ip; unblock_ip('$IP')" >/dev/null 2>&1
step "1/6 Before: attacker is not blocked"
python -m honeycomb verify "$IP"
step "2/6 Block the attacker (needs analyst approval in real use)"
python -c "from honeycomb.src.blocking import block_ip; print(block_ip('$IP'))"
step "3/6 Attack on the protected port (should hang, then time out)"
timeout 20 "$ATK" >/dev/null 2>&1; echo "attack exit code: $? (124 = timed out = blocked)"
step "4/6 Counter proves the firewall dropped real packets"
python -m honeycomb verify "$IP"
step "5/6 Rollback: remove the block"
python -c "from honeycomb.src.blocking import unblock_ip; print(unblock_ip('$IP'))"
python -m honeycomb verify "$IP"
step "6/6 Attack again (should work now)"
OUT="$(timeout 40 "$ATK" 2>&1)"
echo "$OUT" | grep -q "svr04" && echo "RESULT: attacker got in again after rollback" || echo "RESULT: attacker did not get in"
