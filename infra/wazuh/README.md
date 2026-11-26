# Wazuh local setup (single-node, Docker)

Monitoring layer for Honeycomb. The honeypot logs
(`data/raw/cowrie.json`) are shipped by a Wazuh agent to a
Wazuh manager running in Docker on the host machine.

## 1. Start the manager (host, PowerShell)

    git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0 --depth 1
    cd wazuh-docker\single-node
    wsl -d docker-desktop sysctl -w vm.max_map_count=262144
    docker compose -f generate-indexer-certs.yml run --rm generator
    docker compose up -d

Dashboard: https://localhost (self-signed certificate).
Needs about 4-5 GB of free RAM. Change the default dashboard
password before sharing the machine.

## 2. Load the Cowrie rules (rules 100201-100205)

    docker cp infra\wazuh\cowrie_rules.xml single-node-wazuh.manager-1:/tmp/cowrie_rules.xml
    docker exec single-node-wazuh.manager-1 bash -c "cat /tmp/cowrie_rules.xml >> /var/ossec/etc/rules/local_rules.xml"
    docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
    docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

Run these once only; running twice duplicates the rules.

## 3. Open the ports for the VM (host, PowerShell as Administrator)

    New-NetFirewallRule -DisplayName "Wazuh from VMware" -Direction Inbound -Protocol TCP -LocalPort 1514,1515 -RemoteAddress 192.168.127.0/24 -Action Allow

Replace the subnet with the VMware NAT subnet of your machine
(`ipconfig`, adapter "VMware Network Adapter VMnet8").

## 4. Connect the agent (Kali VM)

    sudo systemctl stop wazuh-agent
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    sudo sed -i 's#<address>.*</address>#<address>HOST_IP</address>#' /var/ossec/etc/ossec.conf
    sudo /var/ossec/bin/agent-auth -m HOST_IP -A kali-honeypot-2
    sudo systemctl start wazuh-agent

Use a new agent name each time a new manager is created, to avoid
"Duplicate agent name". The agent must also have a `<localfile>`
block (log_format json) for `data/raw/cowrie.json`.

## 5. Check

    sudo grep "Connected to the server" /var/ossec/logs/ossec.log
    docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

In the dashboard (Threat Hunting) search:
`rule.id:(100201 OR 100202 OR 100203 OR 100204 OR 100205)`

## Notes and limits

- The agent only reads lines appended after it starts. Events must
  reach `data/raw/cowrie.json` first (see `infra/README.md`,
  pull_logs). Lab trap logs live in the `cowrie-lab` container and
  are copied with `docker cp`.
- Wazuh only monitors. Blocking stays in Honeycomb with human
  approval.
