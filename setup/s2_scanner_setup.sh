#!/bin/bash
# =============================================================================
# System 2 – Endpoint Scanner VM Setup Script
# Role: Pulls Git repo, scans with ClamAV, publishes MQTT alert on detection
# IP: 10.0.3.2 (reuses Victim-IDS slot) / gateway: 10.0.3.1
# =============================================================================
set -e

echo "[*] System 2 – Endpoint Scanner setup starting..."

# -----------------------------------------------------------------------------
# 1. Network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.3.2
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
apt-get install -y clamav clamav-daemon git openssh-client python3 python3-paho-mqtt mosquitto-clients

# Update ClamAV signatures
echo "[*] Updating ClamAV virus database..."
freshclam || true

# -----------------------------------------------------------------------------
# 3. Generate SSH key for scanner identity (KEY_ID=scanner1)
# -----------------------------------------------------------------------------
if [ ! -f /root/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@scanner"
    echo "[*] SSH key generated."
fi

echo ""
echo "[!] Add scanner public key to Repo-Controller authorized_keys:"
echo '    environment="KEY_ID=scanner1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding' $(cat /root/.ssh/id_ed25519.pub)

# -----------------------------------------------------------------------------
# 4. Clone the repository (initial checkout)
# -----------------------------------------------------------------------------
REPO_CONTROLLER="10.0.3.20"
if [ ! -d /root/project ]; then
    ssh-keyscan -H "$REPO_CONTROLLER" >> /root/.ssh/known_hosts 2>/dev/null || true
    git clone git@${REPO_CONTROLLER}:/home/git/repos/project.git /root/project || \
        echo "[!] Clone failed – run manually after adding SSH key to repo-controller"
fi

# -----------------------------------------------------------------------------
# 5. Endpoint scan script
# -----------------------------------------------------------------------------
echo "[*] Installing endpoint-scan.sh..."
cat > /opt/endpoint-scan.sh << 'SEOF'
#!/bin/bash
# endpoint-scan.sh: pull latest repo, scan with ClamAV, publish MQTT alert on detection
set -e

REPO_DIR="/root/project"
MQTT_BROKER="10.0.3.1"
MQTT_TOPIC="repo/alerts"

cd "$REPO_DIR"
git pull origin main

COMMIT=$(git rev-parse HEAD)
echo "[*] Scanning commit $COMMIT..."

# Run ClamAV scan
SCAN_OUTPUT=$(clamscan --recursive --no-summary "$REPO_DIR" 2>&1)
echo "$SCAN_OUTPUT"

if echo "$SCAN_OUTPUT" | grep -q "FOUND"; then
    INFECTED=$(echo "$SCAN_OUTPUT" | grep "FOUND" | head -1 | awk '{print $1}' | tr -d ':')
    echo "[ALERT] $INFECTED: Eicar-Test-Signature FOUND"

    # Get KEY_ID from environment (set via SSH authorized_keys)
    KEY_ID="${KEY_ID:-unknown}"

    PAYLOAD=$(python3 -c "
import json, datetime
print(json.dumps({
    'timestamp': datetime.datetime.utcnow().isoformat(),
    'key_id': '${KEY_ID}',
    'commit': '${COMMIT}',
    'infected_file': '${INFECTED}',
    'malware': 'Eicar-Test-Signature',
    'source': 'clamav'
}))
")
    mosquitto_pub -h "$MQTT_BROKER" -t "$MQTT_TOPIC" -m "$PAYLOAD"
    echo "[ALERT] Published to $MQTT_TOPIC ($PAYLOAD)"
else
    echo "[OK] No malware detected (commit $COMMIT)"
fi
SEOF
chmod +x /opt/endpoint-scan.sh

echo ""
echo "[+] System 2 Endpoint Scanner setup complete."
echo "    - ClamAV installed and updated"
echo "    - /opt/endpoint-scan.sh ready"
echo "    - SSH key: /root/.ssh/id_ed25519.pub"
echo "    - Run a scan: /opt/endpoint-scan.sh"
