# Honeycomb — Cowrie Honeypot Setup

## 1. Purpose

This setup runs Cowrie, an SSH honeypot, locally for development and testing. It captures simulated attacker login attempts and commands as JSON events.

**Note:** This is a local test environment, not the production Azure deployment.

## 2. Requirements

* Docker Desktop installed and running.
* Windows CMD or PowerShell.
* The Honeycomb repository cloned locally.

## 3. Start Cowrie

From the repository root, run:

```cmd
docker compose -f infra\docker-compose.yml up -d
```

Check the container status:

```cmd
docker ps --filter "name=honeycomb-cowrie"
```

View Cowrie logs:

```cmd
docker logs --tail 50 honeycomb-cowrie
```

## 4. Test the Honeypot

Connect to the local SSH honeypot:

```cmd
ssh -p 2222 root@127.0.0.1
```

Use only dummy test credentials. Never enter real passwords because honeypot logs may record submitted credentials.

After connecting, try a harmless simulated command:

```text
whoami
exit
```

Cowrie provides a simulated shell. Commands run there do not mean you have gained access to the host operating system.

## 5. Inspect JSON Events

Cowrie JSON logs are stored inside the container at:

`/cowrie/cowrie-git/var/log/cowrie/cowrie.json`

To display recent events without printing credential fields, run:

```cmd
docker exec honeycomb-cowrie python -c "import json; p='/cowrie/cowrie-git/var/log/cowrie/cowrie.json'; events=[json.loads(x) for x in open(p) if x.strip()]; keys=['timestamp','eventid','src_ip','src_port','session','username','input']; [print(json.dumps({k:e[k] for k in keys if k in e},ensure_ascii=False)) for e in events[-10:]]"
```

The `cowrie-var` Docker volume preserves Cowrie data beyond the container's lifecycle.

## 6. Stop Cowrie

```cmd
docker compose -f infra\docker-compose.yml down
```

This stops and removes the container but keeps the named volume. Do not use `-v` unless you intentionally want to delete the persisted volume.

## 7. Security Notes

* The SSH port is bound to `127.0.0.1:2222` for local testing only.
* Never use personal or production credentials.
* Do not expose a local development machine directly to the internet.
* Public deployment must use an isolated cloud VM with appropriate firewall rules and monitoring.
* Do not share raw logs containing passwords or other sensitive information.
* This setup has been tested locally; cloud deployment and integration with the team's analysis pipeline remain separate tasks.

## 8. Linux (Kali / Ubuntu)

The commands above use Windows paths. On Linux use forward slashes. Install Docker first (`sudo apt install -y docker.io docker-compose jq`), then add yourself to the docker group and log out/in:

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Start, test and stop:

```bash
docker compose -f infra/docker-compose.yml up -d
docker ps --filter "name=honeycomb-cowrie"
ssh -p 2222 root@127.0.0.1        # use a dummy password, then run: whoami, exit
docker compose -f infra/docker-compose.yml down
```

The Cowrie container has no `cat` or `ls`. Do not run `docker exec ... cat`. To read the log, use the pull script (works on the local container too):

```bash
scripts/pull_logs.sh local
jq -c '{eventid, session, input}' data/raw/cowrie-*.json | head
```

For a real VM: `scripts/pull_logs.sh <VM_IP> <ADMIN_PORT> <ADMIN_USER>`.

## 9. Hourly log pull (cron)

Pull the Cowrie log into `data/raw/` automatically every hour (Linux). `data/` is gitignored.

```bash
sudo systemctl enable --now cron
( crontab -l 2>/dev/null; echo "0 * * * * $HOME/honeycomb-test/scripts/pull_logs.sh local >> $HOME/honeycomb-test/data/pull.log 2>&1" ) | crontab -
crontab -l
```

For the real VM replace `local` with `<VM_IP> <ADMIN_PORT> <ADMIN_USER>` (needs an SSH key without passphrase, since cron has no agent).

Check: `ls data/raw/` and `tail data/pull.log`. To test quickly, change `0 * * * *` to `* * * * *` (every minute), then change it back.

Remove: `crontab -l | grep -v pull_logs.sh | crontab -`
