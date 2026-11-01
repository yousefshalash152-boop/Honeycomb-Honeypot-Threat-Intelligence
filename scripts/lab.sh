#!/usr/bin/env bash
# Blocking lab: build / remove the local lab from docs/blocking-lab.md in one command.
# Usage: scripts/lab.sh up | down | status | attack <port> | block <ip> | unblock <ip>
set -euo pipefail

SET=honeycomb-block
NET=honeycomb-lab-attacker
TRAP=cowrie-lab
HOST_IP=172.30.0.1
OPEN_PORT=2223        # stands in for port 22 on Azure: the open trap, never blocked
PROTECTED_PORT=2222   # the "protected" service: blocked IPs are dropped here
ATT_NS=attacker
ATT_IP=10.77.0.2

# Match the ORIGINAL port the attacker asked for (before Docker's DNAT).
# Both published ports end up on container port 2222, so --dport alone could not tell them apart.
RULE=(-p tcp -m conntrack --ctorigdstport "$PROTECTED_PORT" -m set --match-set "$SET" src -j DROP)

up() {
  sudo ipset create "$SET" hash:ip timeout 604800 counters -exist
  sudo iptables -C DOCKER-USER "${RULE[@]}" 2>/dev/null || sudo iptables -I DOCKER-USER 1 "${RULE[@]}"

  docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet 172.30.0.0/24 "$NET" >/dev/null
  if docker ps -a --format '{{.Names}}' | grep -qx "$TRAP"; then
    docker start "$TRAP" >/dev/null
  else
    docker run -d --name "$TRAP" \
      -p "$HOST_IP:$OPEN_PORT:2222" -p "$HOST_IP:$PROTECTED_PORT:2222" \
      cowrie/cowrie:latest >/dev/null
  fi

  if ! sudo ip netns list | grep -qw "$ATT_NS"; then
    sudo ip netns add "$ATT_NS"
    sudo ip link add veth-att type veth peer name veth-host
    sudo ip link set veth-att netns "$ATT_NS"
    sudo ip addr add 10.77.0.1/24 dev veth-host
    sudo ip link set veth-host up
    sudo ip netns exec "$ATT_NS" ip addr add "$ATT_IP/24" dev veth-att
    sudo ip netns exec "$ATT_NS" ip link set veth-att up
    sudo ip netns exec "$ATT_NS" ip link set lo up
    sudo ip netns exec "$ATT_NS" ip route add default via 10.77.0.1
  fi
  echo "LAB_UP (wait ~15s for Cowrie to start before the first attack)"
}

down() {
  sudo iptables -D DOCKER-USER "${RULE[@]}" 2>/dev/null || true
  sudo ipset destroy "$SET" 2>/dev/null || true
  sudo ip netns del "$ATT_NS" 2>/dev/null || true
  sudo ip link del veth-host 2>/dev/null || true
  docker rm -f "$TRAP" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "LAB_DOWN"
}

status() {
  sudo ipset list "$SET"
  sudo iptables -L DOCKER-USER -n -v
}

attack() {
  sudo ip netns exec "$ATT_NS" ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$1" "root@$HOST_IP"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  attack) attack "${2:?usage: attack <port>}" ;;
  block) sudo ipset add "$SET" "${2:?usage: block <ip>}" -exist ;;
  unblock) sudo ipset del "$SET" "${2:?usage: unblock <ip>}" ;;
  *) echo "usage: $0 up|down|status|attack <port>|block <ip>|unblock <ip>"; exit 1 ;;
esac
