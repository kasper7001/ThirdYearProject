#!/bin/bash
# =============================================================================
# System 3 – Firewall VM Setup Script
# Role: Network gateway, MQTT broker, dynamic iptables enforcement
# Interfaces:
#   enp0s3 -> NAT (internet, DHCP)
#   enp0s8 -> Attacker network 10.0.0.0/24 (IP: 10.0.0.1)
#   enp0s9 -> Victim network   10.0.1.0/24 (IP: 10.0.1.1)
# =============================================================================
set -e

echo "[*] System 3 – Firewall setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet dhcp

# Attacker network
auto enp0s8
iface enp0s8 inet static
    address 10.0.0.1
    netmask 255.255.255.0

# Victim network
auto enp0s9
iface enp0s9 inet static
    address 10.0.1.1
    netmask 255.255.255.0
EOF

# -----------------------------------------------------------------------------
# 2. Enable IP forwarding (persistent)
# -----------------------------------------------------------------------------
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# -----------------------------------------------------------------------------
# 3. Install packages
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y iptables iptables-persistent mosquitto mosquitto-clients jq

# -----------------------------------------------------------------------------
# 4. Mosquitto MQTT broker
# -----------------------------------------------------------------------------
cat > /etc/mosquitto/conf.d/local.conf << 'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF

systemctl enable mosquitto
systemctl restart mosquitto

# -----------------------------------------------------------------------------
# 5. Baseline iptables rules
# -----------------------------------------------------------------------------
iptables -F
iptables -X

iptables -P INPUT   ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

iptables -A INPUT   -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i lo -j ACCEPT
iptables -A INPUT   -p tcp --dport 22  -j ACCEPT   # SSH management
iptables -A INPUT   -p tcp --dport 1883 -j ACCEPT  # MQTT from any internal host

iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Baseline: allow attacker <-> victim (dynamic DROP inserted above this at runtime)
iptables -A FORWARD -i enp0s8 -o enp0s9 -j ACCEPT
iptables -A FORWARD -i enp0s9 -o enp0s8 -j ACCEPT

# NAT
iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
# Victim internet access (for setup)
iptables -A FORWARD -i enp0s9 -o enp0s3 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o enp0s9 -j ACCEPT

netfilter-persistent save

# -----------------------------------------------------------------------------
# 6. Firewall blocking script
# -----------------------------------------------------------------------------
cat > /usr/local/bin/fw_block_ip.sh << 'EOF'
#!/bin/bash
# Inserts a DROP rule at the top of the FORWARD chain for the given IP
IP="$1"
if [ -z "$IP" ]; then
    echo "Usage: fw_block_ip.sh <ip>"
    exit 1
fi
iptables -I FORWARD 1 -s "$IP" -j DROP
echo "$(date -u --iso-8601=seconds) blocked ip=$IP" >> /var/log/sec-reconfig.log
echo "[*] Blocked $IP in FORWARD chain"
EOF
chmod +x /usr/local/bin/fw_block_ip.sh

# -----------------------------------------------------------------------------
# 7. MQTT subscriber script
# -----------------------------------------------------------------------------
cat > /usr/local/bin/mqtt_fw_subscriber.sh << 'EOF'
#!/bin/bash
# Subscribes to sec/fail2ban/ban and calls fw_block_ip.sh for each alert
BROKER="localhost"
TOPIC="sec/fail2ban/ban"

echo "[*] Subscribing to $TOPIC on $BROKER..."

mosquitto_sub -h "$BROKER" -t "$TOPIC" | while read -r LINE; do
    echo "[*] Received: $LINE"
    IP=$(echo "$LINE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('src_ip',''))" 2>/dev/null)
    if [ -n "$IP" ]; then
        /usr/local/bin/fw_block_ip.sh "$IP"
    else
        echo "[!] Could not parse IP from: $LINE"
    fi
done
EOF
chmod +x /usr/local/bin/mqtt_fw_subscriber.sh

# -----------------------------------------------------------------------------
# 8. systemd service for the subscriber
# -----------------------------------------------------------------------------
cat > /etc/systemd/system/mqtt-fw-subscriber.service << 'EOF'
[Unit]
Description=MQTT Firewall Subscriber – Fail2Ban alert enforcement
After=network.target mosquitto.service
Requires=mosquitto.service

[Service]
Type=simple
ExecStart=/usr/local/bin/mqtt_fw_subscriber.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mqtt-fw-subscriber.service

echo ""
echo "[+] System 3 Firewall setup complete."
echo "    - Mosquitto listening on 0.0.0.0:1883"
echo "    - fw_block_ip.sh: inserts DROP at top of FORWARD chain"
echo "    - mqtt-fw-subscriber.service: enabled (start for collaborative trials)"
echo "    - Logs written to: /var/log/sec-reconfig.log"
echo "    - To remove a dynamic rule between trials:"
echo "      iptables -D FORWARD -s <attacker_ip> -j DROP"
