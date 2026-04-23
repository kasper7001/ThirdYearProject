#!/bin/bash
# =============================================================================
# System 1 – Firewall / Bastion VM Setup Script
# Role: Network gateway, MQTT broker, iptables+ipset enforcement point
# Interfaces:
#   enp0s3 -> NAT (internet, DHCP)
#   enp0s8 -> Victim network  10.0.3.0/24  (IP: 10.0.3.1)
#   enp0s9 -> Attacker network 10.0.1.0/24 (IP: 10.0.1.1)
# =============================================================================
set -e

echo "[*] System 1 – Firewall setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
echo "[*] Configuring network interfaces..."

cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

# NAT / management (VirtualBox NAT adapter)
auto enp0s3
iface enp0s3 inet dhcp

# Victim network
auto enp0s8
iface enp0s8 inet static
    address 10.0.3.1
    netmask 255.255.255.0

# Attacker network
auto enp0s9
iface enp0s9 inet static
    address 10.0.1.1
    netmask 255.255.255.0
EOF

# -----------------------------------------------------------------------------
# 2. Enable IP forwarding (persistent)
# -----------------------------------------------------------------------------
echo "[*] Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# -----------------------------------------------------------------------------
# 3. Install packages
# -----------------------------------------------------------------------------
echo "[*] Installing packages..."
apt-get update -qq
apt-get install -y iptables iptables-persistent ipset mosquitto mosquitto-clients python3 python3-paho-mqtt

# Keep ipset across reboots
apt-get install -y ipset-persistent 2>/dev/null || true

# -----------------------------------------------------------------------------
# 4. Configure Mosquitto MQTT broker
# -----------------------------------------------------------------------------
echo "[*] Configuring Mosquitto..."
cat > /etc/mosquitto/conf.d/local.conf << 'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF

systemctl enable mosquitto
systemctl restart mosquitto

# -----------------------------------------------------------------------------
# 5. Create ipset for dynamic blocking
# -----------------------------------------------------------------------------
echo "[*] Creating ipset attacker_block..."
ipset create attacker_block hash:ip timeout 3600 2>/dev/null || ipset flush attacker_block

# Persist ipset definition (members stay ephemeral)
cat > /etc/ipset.conf << 'EOF'
create attacker_block hash:ip family inet hashsize 1024 maxelem 65536 timeout 3600
EOF

# Create ipset-init service so the set exists after reboot
cat > /etc/systemd/system/ipset-init.service << 'EOF'
[Unit]
Description=Initialise ipset attacker_block
Before=iptables-restore.service network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/ipset create -exist attacker_block hash:ip timeout 3600
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ipset-init.service
systemctl start ipset-init.service

# -----------------------------------------------------------------------------
# 6. iptables rules
# -----------------------------------------------------------------------------
echo "[*] Applying iptables rules..."
iptables -F
iptables -X

# Default policies
iptables -P INPUT   ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# Allow established/related
iptables -A INPUT   -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH to firewall (management)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow MQTT from victim subnet
iptables -A INPUT -s 10.0.3.0/24 -p tcp --dport 1883 -j ACCEPT

# Dynamic block set – must be near top of FORWARD
iptables -A FORWARD -m set --match-set attacker_block src -j DROP

# Baseline forward rules: attacker <-> victim
iptables -A FORWARD -i enp0s9 -o enp0s8 -j ACCEPT
iptables -A FORWARD -i enp0s8 -o enp0s9 -j ACCEPT

# NAT for outbound traffic
iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

# Allow victim internet access (setup only – can be removed post-setup)
iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o enp0s8 -j ACCEPT

# Save rules
netfilter-persistent save

# -----------------------------------------------------------------------------
# 7. MQTT blocker script (subscribes and blocks attacker IPs)
# -----------------------------------------------------------------------------
echo "[*] Installing MQTT blocker script..."
cat > /opt/mqtt_blocker.py << 'PYEOF'
#!/usr/bin/env python3
"""
hids-mqtt-blocker: subscribes to hids/alerts and adds attacker IPs to ipset.
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

BROKER   = "localhost"
PORT     = 1883
TOPIC    = "hids/alerts"
IPSET    = "attacker_block"

def block_ip(ip: str):
    try:
        subprocess.run(["ipset", "add", IPSET, ip, "-exist"], check=True)
        log.info("Blocked attacker IP %s", ip)
        # Also write to custom log for latency measurements
        with open("/var/log/sec-reconfig.log", "a") as f:
            import datetime
            f.write(f"{datetime.datetime.utcnow().isoformat()} blocked ip={ip}\n")
    except subprocess.CalledProcessError as exc:
        log.error("Failed to block %s: %s", ip, exc)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        ip = payload.get("attacker_ip") or payload.get("src_ip")
        if ip:
            block_ip(ip)
        else:
            log.warning("No IP in payload: %s", payload)
    except Exception as exc:
        log.error("Error processing message: %s", exc)

def on_connect(client, userdata, flags, rc):
    log.info("Connected to broker (rc=%s), subscribing to %s", rc, TOPIC)
    client.subscribe(TOPIC)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, 60)
log.info("MQTT blocker started")
client.loop_forever()
PYEOF

chmod +x /opt/mqtt_blocker.py

# -----------------------------------------------------------------------------
# 8. systemd service for the blocker
# -----------------------------------------------------------------------------
echo "[*] Creating hids-mqtt-blocker systemd service..."
cat > /etc/systemd/system/hids-mqtt-blocker.service << 'EOF'
[Unit]
Description=HIDS MQTT Blocker – receives IDS alerts and blocks attacker IPs
After=network.target mosquitto.service ipset-init.service
Requires=mosquitto.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/mqtt_blocker.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hids-mqtt-blocker.service
# Start only during collaborative trials: systemctl start hids-mqtt-blocker.service

echo ""
echo "[+] System 1 Firewall setup complete."
echo "    - ipset 'attacker_block' created"
echo "    - Mosquitto listening on 0.0.0.0:1883"
echo "    - hids-mqtt-blocker.service installed (start manually for collaborative trials)"
echo "    - To flush blocklist between trials: sudo ipset flush attacker_block"
