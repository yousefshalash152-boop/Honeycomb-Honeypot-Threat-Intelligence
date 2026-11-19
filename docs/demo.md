# Backup demo (offline)

The live demo can break at any moment. This one runs from scratch in about 10 minutes and needs no internet.

## What you need

- Kali or Debian with Docker, `ipset`, `iptables` and OpenSSH 8.4 or newer, and `sudo`.
- The Cowrie image already pulled: `docker image ls cowrie/cowrie` must list it.
- This repo with the Python environment active, so `python -m honeycomb` works.

## Option A: full run with the lab

1. Build the lab and wait about 20 seconds for Cowrie to start:

        scripts/lab.sh up

2. Run the scripted attack from the "attacker" namespace (10.77.0.2). It ends with `ATTACK_DONE`:

        scripts/lab_attack.sh

3. Copy the log out of the trap and score it:

        docker cp cowrie-lab:/cowrie/cowrie-git/var/log/cowrie/cowrie.json /tmp/demo-live.json
        python -m honeycomb --input /tmp/demo-live.json --db /tmp/demo-live.db --no-enrich run

   Expected: `10.77.0.2  70  BLOCK_CANDIDATE`.

4. Block the attacker and show the block:

        scripts/lab.sh block 10.77.0.2
        scripts/lab.sh status

5. Prove it works. The protected port now times out, while the open trap still answers:

        scripts/lab.sh attack 2222
        scripts/lab.sh attack 2223

   Type `exit` once if you reach the honeypot shell.

6. Roll back. After this the protected port works again:

        scripts/lab.sh unblock 10.77.0.2

7. Clean up:

        scripts/lab.sh down

## Option B: no lab (fallback if Docker fails)

Run the pipeline on the saved log. It gives the same score:

    python -m honeycomb --input tests/fixtures/demo/cowrie.json --db /tmp/demo-fixture.db --no-enrich run

## Expected score

| Evidence | Behaviors | Points |
|---|---|---|
| login_success | B02 | 20 |
| recon_commands | B04, B05 | 10 |
| file_download | B08 | 25 |
| persistence_attempt | B10, B11 | 15 |
| Total | | 70 (BLOCK_CANDIDATE) |

## Notes and limits

- **Brute force (B01) cannot fire in this lab.** Cowrie accepts a login after a random 2 to 5 tries, so a session has at most 4 failed logins, while B01 needs 5. The demo reaches 70 without it.
- **No internet is needed.** The `wget` fails inside the trap, but B08 is decided from the command text, not from the download result.
- **The fixture is clean.** `tests/fixtures/demo/cowrie.json` came from a fresh trap, so its only source IP is 10.77.0.2.
- **The lab is lost on reboot** (ipset, iptables rule, namespace). `scripts/lab.sh up` rebuilds it.
- **Not covered:** a real server (Azure) and the restricted SSH key path. Those are in `docs/blocking.md`.

## Reviewer check

Someone other than the author runs Option A with a stopwatch and no internet. It passes if it finishes in 10 minutes and step 3 prints 70 BLOCK_CANDIDATE.
