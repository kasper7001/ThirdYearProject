#!/bin/bash
# =============================================================================
# System 1 – Victim-IDS VM Setup Script
# Role: HIDS host – detects mass file changes, publishes alerts via MQTT
# IP: 10.0.3.2 / gateway: 10.0.3.1
# =============================================================================
set -e

echo "[*] System 1 – Victim-IDS setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
echo "[*] Configuring network..."
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
nameserver 1.1.1.1
EOF

# -----------------------------------------------------------------------------
# 2. Install packages
# -----------------------------------------------------------------------------
echo "[*] Installing packages..."
apt-get update -qq
apt-get install -y python3 python3-paho-mqtt libpam-runtime openssh-server

# -----------------------------------------------------------------------------
# 3. Create watched data directory
# -----------------------------------------------------------------------------
echo "[*] Creating /srv/labdata/ ..."
mkdir -p /srv/labdata
for i in $(seq 1 100); do echo "init" > /srv/labdata/file${i}.txt; done
chmod -R 777 /srv/labdata

# -----------------------------------------------------------------------------
# 4. PAM hook – capture attacker IP at SSH login
# -----------------------------------------------------------------------------
echo "[*] Installing PAM attacker-IP capture hook..."
cat > /opt/cache-attacker-ip.sh << 'EOF'
#!/bin/bash
# Called by PAM on SSH session open; caches the remote IP for the HIDS
if [ -n "$PAM_RHOST" ]; then
    echo "$PAM_RHOST" > /run/last_attacker_ip
fi
EOF
chmod +x /opt/cache-attacker-ip.sh

# Add PAM session rule (insert after pam_env.so line)
PAM_FILE="/etc/pam.d/sshd"
if ! grep -q "cache-attacker-ip" "$PAM_FILE"; then
    sed -i '/pam_env.so/a session optional pam_exec.so /opt/cache-attacker-ip.sh' "$PAM_FILE"
    echo "[*] PAM hook added to $PAM_FILE"
fi

# -----------------------------------------------------------------------------
# 5. Mass file-change detector (HIDS simulation)
# -----------------------------------------------------------------------------
echo "[*] Installing mass-change-detector script..."
cat > /opt/mass_change_detector.py << 'PYEOF'
#!/usr/bin/env python3
"""
mass-change-detector: polls /srv/labdata for rapid file changes.
When the event count exceeds the threshold in the observation window,
an alert is published to hids/alerts via MQTT.
"""
import os
import time
import json
import logging
import datetime
import paho.mqtt.client as mqtt

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger(__name__)

WATCH_DIR       = "/srv/labdata"
WINDOW_SECONDS  = 10
EVENT_THRESHOLD = 50           # file changes in WINDOW_SECONDS → alert
POLL_INTERVAL   = 1            # seconds between polls
MQTT_BROKER     = "10.0.3.1"
MQTT_PORT       = 1883
MQTT_TOPIC      = "hids/alerts"
ATTACKER_IP_FILE = "/run/last_attacker_ip"

client = mqtt.Client()
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()

log.info("Watching %s for mass file changes...", WATCH_DIR)

snapshots = []  # list of (timestamp, mtime_set)

def get_mtimes():
    mtimes = {}
    try:
        for fname in os.listdir(WATCH_DIR):
            fpath = os.path.join(WATCH_DIR, fname)
            mtimes[fpath] = os.path.getmtime(fpath)
    except OSError:
        pass
    return mtimes

prev = get_mtimes()

while True:
    time.sleep(POLL_INTERVAL)
    curr = get_mtimes()
    changed = sum(1 for k, v in curr.items() if prev.get(k) != v)
    prev = curr

    if changed == 0:
        continue

    now = time.time()
    snapshots.append((now, changed))
    # Keep only events within the window
    snapshots = [(t, c) for t, c in snapshots if now - t <= WINDOW_SECONDS]
    total = sum(c for _, c in snapshots)

    if total >= EVENT_THRESHOLD:
        # Read cached attacker IP
        attacker_ip = "unknown"
        try:
            with open(ATTACKER_IP_FILE) as f:
                attacker_ip = f.read().strip()
        except FileNotFoundError:
            pass

        victim_ip = "10.0.3.2"
        payload = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "+00:00",
            "victim_ip": victim_ip,
            "attacker_ip": attacker_ip,
            "reason": "mass_file_changes",
            "watch_dir": WATCH_DIR,
            "window_seconds": WINDOW_SECONDS,
            "event_count": total,
        }
        msg = json.dumps(payload)
        client.publish(MQTT_TOPIC, msg)
        log.info("ALERT published to %s: %s", MQTT_TOPIC, msg)
        snapshots.clear()   # reset window after alert
PYEOF
chmod +x /opt/mass_change_detector.py

# -----------------------------------------------------------------------------
# 6. systemd service for the detector
# -----------------------------------------------------------------------------
echo "[*] Creating mass-change-detector systemd service..."
cat > /etc/systemd/system/mass-change-detector.service << 'EOF'
[Unit]
Description=Mass File Change Detector (HIDS simulation)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/mass_change_detector.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mass-change-detector.service

echo ""
echo "[+] System 1 Victim-IDS setup complete."
echo "    - PAM hook installed: captures SSH remote IP -> /run/last_attacker_ip"
echo "    - /srv/labdata/ created with 100 placeholder files"
echo "    - mass-change-detector.service enabled (start for collaborative trials)"
echo "    - Publishes to MQTT topic: hids/alerts on 10.0.3.1:1883"
