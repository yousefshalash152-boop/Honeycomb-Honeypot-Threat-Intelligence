# Blocking lab (ipset + DOCKER-USER)

Test the IP-blocking mechanism on a local Cowrie before touching Azure.

**Requirements: Linux only** (Kali/Ubuntu VM, or WSL2 with Docker installed inside). It does NOT work on Docker Desktop for Windows. Needs Docker, `sudo`, and `ipset` (`sudo apt install -y ipset`).

## Why it is built this way

- The block rule goes in the `DOCKER-USER` chain, not `INPUT`. Traffic to Docker published ports is forwarded (DNAT, then FORWARD), so it never passes through `INPUT` or `ufw`.
- The attacker must come from **outside Docker**. A connection from the same machine (127.0.0.1) or from another Docker network goes through `docker-proxy`, never reaches `DOCKER-USER`, and will not be blocked. So we simulate an external attacker with a network namespace.
- Everything here is lost on reboot (ipset, iptables, namespace). Set entries also expire by themselves after 7 days (`timeout 604800`).

## 1. Lab trap

The network only gives the host a private IP (172.30.0.1) to publish the lab trap on.

```bash
docker network create --subnet 172.30.0.0/24 honeycomb-lab-attacker
docker run -d --name cowrie-lab -p 172.30.0.1:2223:2222 cowrie/cowrie:latest
sleep 10
docker ps --filter "name=cowrie-lab"
```

## 2. Block set and rule

```bash
sudo ipset create honeycomb-block hash:ip timeout 604800 counters -exist
sudo iptables -I DOCKER-USER 1 -p tcp --dport 2222 -m set --match-set honeycomb-block src -j DROP
sudo iptables -L DOCKER-USER -n -v
```

Expected: a `DROP` rule on `tcp dpt:2222 match-set honeycomb-block src`. 2222 is the container port (the rule sees the packet after DNAT).

## 3. Simulated external attacker (10.77.0.2)

Paste this as ONE line:

```bash
sudo ip netns add attacker && sudo ip link add veth-att type veth peer name veth-host && sudo ip link set veth-att netns attacker && sudo ip addr add 10.77.0.1/24 dev veth-host && sudo ip link set veth-host up && sudo ip netns exec attacker ip addr add 10.77.0.2/24 dev veth-att && sudo ip netns exec attacker ip link set veth-att up && sudo ip netns exec attacker ip link set lo up && sudo ip netns exec attacker ip route add default via 10.77.0.1 && echo SETUP_OK
```

Expected: `SETUP_OK`.

## 4. Attack BEFORE the block (must succeed)

```bash
sudo ip netns exec attacker ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2223 root@172.30.0.1
```

Type a dummy password (never a real one), then `whoami`, then `exit`. Cowrie closes idle connections after 2 minutes, so answer quickly.

IMPORTANT: after this ssh you are inside the honeypot. Run `exit` and wait for your own prompt before pasting the next command, or the commands go into the fake shell.

## 5. Block the attacker (must fail)

```bash
sudo ipset add honeycomb-block 10.77.0.2
sudo ip netns exec attacker ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2223 root@172.30.0.1
sudo ipset list honeycomb-block
```

Expected: `Connection timed out` with no password prompt, and `10.77.0.2 ... packets N` with N greater than 0. Each retry makes the counter grow, which proves the block is what stopped it.

## 6. Rollback (must succeed again)

```bash
sudo ipset del honeycomb-block 10.77.0.2
sudo ipset list honeycomb-block
sudo ip netns exec attacker ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2223 root@172.30.0.1
```

Expected: `Number of entries: 0`, then the attacker gets the password prompt again. Type `exit`.

## 7. Clean up the lab

Order matters: remove the iptables rule before destroying the set.

```bash
sudo iptables -D DOCKER-USER -p tcp --dport 2222 -m set --match-set honeycomb-block src -j DROP
sudo ipset destroy honeycomb-block
sudo ip netns del attacker
sudo ip link del veth-host 2>/dev/null
docker rm -f cowrie-lab
docker network rm honeycomb-lab-attacker
```

## Notes

- Never put your own IP or a teammate's IP in the set.
- This is the lab only. The real block on Azure is a later task.

## Newer version

The manual steps above use a single published port and `--dport 2222`. For the two-port lab, the Azure-ready rule (`--ctorigdstport`), the restricted key and `honeycomb verify`, use `scripts/lab.sh` and follow `docs/blocking.md`.
