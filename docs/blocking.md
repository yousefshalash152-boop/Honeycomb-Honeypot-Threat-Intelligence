# Blocking an IP (ipset + DOCKER-USER)

How Honeycomb blocks an attacker IP, how to check that the block works, and how to undo it.
Everything here was tested on the local lab (Kali VM). The same steps apply to Azure later; see "Not tested yet".

## The idea

1. A human approves an IP (`honeycomb approve`, owned by member 5).
2. The IP goes into an `ipset` list on the honeypot host.
3. One `iptables` rule drops connections from any IP in that list to the protected port (2222).
4. `honeycomb verify <IP>` reads the counter to prove packets were really dropped.
5. Rollback removes the IP from the list in one command.

The trap on the open port (22 on Azure, 2223 in the lab) is never blocked, so we keep collecting data.

## The pieces

| File | What it does |
|------|--------------|
| `scripts/lab.sh` | Builds and removes the local lab: ipset, iptables rule, second trap container, simulated external attacker. |
| `scripts/block_ip.sh` | Runs on the host. Accepts only `block`, `unblock`, `verify`, `list` and checks the IP and the whitelist. |
| `scripts/setup_blocker.sh` | One-time setup: restricted user, sudo rule, restricted SSH key. |
| `honeycomb/src/blocking.py` | Python client: `verify_ip`, `block_ip`, `unblock_ip` (used by `approve`). |
| `python -m honeycomb verify <IP>` | Command line check. Exit code 0 = blocked, 1 = not blocked, 2 = error. |
| `config/whitelist.yaml` | Team IPs that must never be blocked (changes go in their own reviewed PR). |

## Why it is built this way

- **Rule in `DOCKER-USER`, not `INPUT`.** Traffic to Docker published ports is rewritten (DNAT) and forwarded, so it never reaches `INPUT` or `ufw`.
- **`--ctorigdstport 2222`, not `--dport 2222`.** Both published ports (open trap and protected port) end up on container port 2222 after DNAT. `--dport` would block both. `--ctorigdstport` looks at the port the attacker originally asked for.
- **`ipset` with `timeout 604800` and `counters`.** Entries expire after 7 days by themselves, and every entry counts the packets it dropped.
- **Restricted SSH key.** The key can only run `scripts/block_ip.sh` (`command=`, `restrict`, `from=`). If it is stolen, the worst case is that someone blocks or unblocks an IP. It cannot open a shell or read files.
- **Whitelist check on the host too.** Even if a caller forgets, the host refuses to block a whitelisted IP.
- **The attacker must come from outside Docker.** A connection from the same machine goes through `docker-proxy` and never reaches `DOCKER-USER`. The lab uses a network namespace (10.77.0.2) to act as an external attacker.

## Run the lab

    scripts/lab.sh up          # builds everything, wait ~15 seconds
    scripts/lab.sh status      # ipset members and rule counters
    scripts/lab.sh attack 2222 # ssh from the simulated attacker (protected port)
    scripts/lab.sh attack 2223 # ssh from the simulated attacker (open trap)
    scripts/lab.sh down        # removes everything

Inside the honeypot shell, type `exit` and wait for your own prompt before running anything else. Everything is lost on reboot; run `scripts/lab.sh up` again.

## Restricted key setup (once)

    ssh-keygen -t ed25519 -f ~/.ssh/honeycomb_blocker -N "" -C honeycomb-blocker-lab
    sudo scripts/setup_blocker.sh ~/.ssh/honeycomb_blocker.pub
    sudo systemctl start ssh

The private key stays on the analyst machine and is never shared. For a remote host pass the analyst IP as the second argument of `setup_blocker.sh` so `from=` is limited to it.

## Block, verify, rollback

    python -c "from honeycomb.src.blocking import block_ip; print(block_ip('10.77.0.2'))"
    python -m honeycomb verify 10.77.0.2
    python -c "from honeycomb.src.blocking import unblock_ip; print(unblock_ip('10.77.0.2'))"

Manual equivalent with the restricted key:

    ssh -i ~/.ssh/honeycomb_blocker -o IdentitiesOnly=yes honeycomb-blocker@127.0.0.1 "unblock 10.77.0.2"

Rollback takes one command. After it, `verify` says `NOT BLOCKED` and the attacker can connect again.

## Results on the lab

Attacker: simulated host `10.77.0.2` (network namespace).

| Step | Result |
|------|--------|
| Attack on 2222 before the block | Password prompt, login, `whoami` returned `root`. |
| `block_ip('10.77.0.2')` | `True`. `verify` showed `BLOCKED packets=0`. |
| Attack on 2222 after the block | `Connection timed out`, no password prompt. |
| `verify` after the attack | `BLOCKED packets=5 bytes=300`. The counter proves the rule dropped it. |
| Attack on 2223 (open trap) while blocked | Still works. The trap keeps collecting data. |
| `unblock_ip` then `verify` | `NOT BLOCKED`, exit code 1. Attacker could log in again. |
| Restricted key with `ls` | Rejected: `ERROR: usage: block <ip> ...`. |
| Restricted key with no command (shell) | Rejected, no prompt. |
| Restricted key with `block 10.77.0.3 && id` | Rejected: `too many arguments`, `id` did not run. |
| Whitelisted IP, invalid IP, `127.0.0.1` | All refused by `block_ip.sh`. |

## Limits and honest notes

- **NAT and shared IPs.** Many people can sit behind one IP (a university or company network). Blocking it blocks the innocent too.
- **VPN and proxies.** An attacker can change IP in seconds. A block slows them down; it does not stop them. This is why a block is only a recommendation with human approval and a 7-day timeout.
- **Never put your own or a teammate's IP in the set.** `config/whitelist.yaml` is the safety net; it is empty at the moment and needs a reviewed PR with the real team IPs.
- **The whitelist match is by exact IP.** A CIDR range written there protects only that exact address text.

## Not tested yet

- The real Azure server (adding port 2222 to `docker-compose.azure.yml` and the NSG). Azure is postponed by team decision, so the lab on Kali is the evidence for now.
- A real attacker. The attacker here is simulated.
- The `approve` command calling `block_ip` (member 5's task).
- Persistence across reboot: the ipset, rule and namespace are not saved.

## Clean up

    scripts/lab.sh down
    sudo systemctl stop ssh
