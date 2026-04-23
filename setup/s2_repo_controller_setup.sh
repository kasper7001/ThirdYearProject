#!/bin/bash
# =============================================================================
# System 2 – Repo-Controller VM Setup Script
# Role: Bare Git repository server + MQTT-driven enforcement
#       (rollback + denylist + pre-receive hook)
# IP: 10.0.3.20 (victim-2 subnet) / gateway: 10.0.3.1
# =============================================================================
set -e

echo "[*] System 2 – Repo-Controller setup starting..."

# -----------------------------------------------------------------------------
# 1. Network configuration (reuses victim subnet via bastion)
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.3.20
    netmask 255.255.255.0
    gateway 10.0.3.1
EOF

cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF

# -----------------------------------------------------------------------------
# 2. Install packages
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y git openssh-server python3 python3-paho-mqtt

# -----------------------------------------------------------------------------
# 3. Create git user and bare repository
# -----------------------------------------------------------------------------
echo "[*] Creating git user and repository..."
id git &>/dev/null || useradd -m -s /usr/bin/git-shell git

mkdir -p /home/git/.ssh
chmod 700 /home/git/.ssh
touch /home/git/.ssh/authorized_keys
chmod 600 /home/git/.ssh/authorized_keys

mkdir -p /home/git/repos
git init --bare /home/git/repos/project.git
chown -R git:git /home/git

# Disable password auth for git user
cat >> /etc/ssh/sshd_config << 'EOF'

Match User git
    PasswordAuthentication no
    AuthorizedKeysFile /home/git/.ssh/authorized_keys
EOF

# Enable PermitUserEnvironment globally (required for KEY_ID tagging)
if ! grep -q "^PermitUserEnvironment" /etc/ssh/sshd_config; then
    echo "PermitUserEnvironment yes" >> /etc/ssh/sshd_config
fi

systemctl enable ssh
systemctl restart ssh

# -----------------------------------------------------------------------------
# 4. Denylist file
# -----------------------------------------------------------------------------
touch /home/git/denylist.txt
chown git:git /home/git/denylist.txt

# -----------------------------------------------------------------------------
# 5. Git pre-receive hook (blocks denylisted identities)
# -----------------------------------------------------------------------------
echo "[*] Installing pre-receive hook..."
cat > /home/git/repos/project.git/hooks/pre-receive << 'EOF'
#!/bin/bash
# Block pushes from denylisted KEY_IDs
DENYLIST="/home/git/denylist.txt"
KEY_ID="${KEY_ID:-unknown}"

echo "remote: DEBUG: KEY_ID='$KEY_ID'"

if [ -f "$DENYLIST" ] && grep -qx "$KEY_ID" "$DENYLIST" 2>/dev/null; then
    echo "remote: Push rejected: identity $KEY_ID is denylisted."
    exit 1
fi
exit 0
EOF
chmod +x /home/git/repos/project.git/hooks/pre-receive
chown git:git /home/git/repos/project.git/hooks/pre-receive

# -----------------------------------------------------------------------------
# 6. Repo enforcer script (MQTT subscriber)
# -----------------------------------------------------------------------------
echo "[*] Installing repo-enforcer MQTT subscriber..."
cat > /opt/repo_enforcer.py << 'PYEOF'
#!/usr/bin/env python3
"""
repo-enforcer: subscribes to repo/alerts and:
  1. Rolls back refs/heads/main to the previous commit.
  2. Appends the offending KEY_ID to the denylist.
"""
import json
import subprocess
import logging
import paho.mqtt.client as mqtt

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger(__name__)

BROKER   = "10.0.3.1"      # Bastion/Firewall MQTT broker
PORT     = 1883
TOPIC    = "repo/alerts"
REPO     = "/home/git/repos/project.git"
DENYLIST = "/home/git/denylist.txt"

def rollback_main():
    """Reset main to the commit before the current tip."""
    try:
        result = subprocess.run(
            ["git", "--git-dir", REPO, "rev-parse", "main~1"],
            capture_output=True, text=True, check=True
        )
        prev = result.stdout.strip()
        subprocess.run(
            ["git", "--git-dir", REPO, "update-ref", "refs/heads/main", prev],
            check=True
        )
        log.info("Rolled back main to %s", prev)
        return True
    except subprocess.CalledProcessError as exc:
        log.error("Rollback failed: %s", exc)
        return False

def denylist_identity(key_id: str):
    """Append KEY_ID to the denylist if not already present."""
    try:
        with open(DENYLIST) as f:
            existing = f.read().splitlines()
        if key_id not in existing:
            with open(DENYLIST, "a") as f:
                f.write(key_id + "\n")
            log.info("Added %s to denylist", key_id)
        else:
            log.info("%s already in denylist", key_id)
    except Exception as exc:
        log.error("Denylist update failed: %s", exc)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        log.info("Alert received: %s", payload)
        key_id = payload.get("key_id", "unknown")
        rollback_main()
        denylist_identity(key_id)
    except Exception as exc:
        log.error("Error handling message: %s", exc)

def on_connect(client, userdata, flags, rc):
    log.info("Connected to broker (rc=%s), subscribing to %s", rc, TOPIC)
    client.subscribe(TOPIC)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, 60)
log.info("Repo enforcer started, waiting for alerts...")
client.loop_forever()
PYEOF
chmod +x /opt/repo_enforcer.py

# -----------------------------------------------------------------------------
# 7. systemd service for the enforcer
# -----------------------------------------------------------------------------
cat > /etc/systemd/system/repo-enforcer.service << 'EOF'
[Unit]
Description=Repository Enforcer – MQTT subscriber for malware alerts
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/repo_enforcer.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable repo-enforcer.service

echo ""
echo "[+] System 2 Repo-Controller setup complete."
echo "    - git user created; bare repo at /home/git/repos/project.git"
echo "    - PermitUserEnvironment yes set in sshd_config"
echo "    - pre-receive hook installed (checks denylist)"
echo "    - repo-enforcer.service enabled (start for collaborative trials)"
echo ""
echo "    To add a developer SSH key, append to /home/git/.ssh/authorized_keys:"
echo '    environment="KEY_ID=dev1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... root@attacker'
echo '    environment="KEY_ID=scanner1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... root@scanner'
