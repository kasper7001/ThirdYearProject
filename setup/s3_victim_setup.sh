#!/bin/bash
# =============================================================================
# System 3 – Victim VM Setup Script
# Role: SSH server + Fail2Ban host detection, MQTT alert publisher
# IP: 10.0.1.10 / gateway: 10.0.1.1
# =============================================================================
set -e

echo "[*] System 3 – Victim setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.1.10
    netmask 255.255.255.0
    gateway 10.0.1.1
EOF

cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF

# -----------------------------------------------------------------------------
# 2. Install packages
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y fail2ban openssh-server mosquitto-clients python3

systemctl enable ssh
systemctl start ssh

# -----------------------------------------------------------------------------
# 3. Create a regular user for the attacker to target (for clean SSH logs)
# -----------------------------------------------------------------------------
id fakeuser &>/dev/null || useradd -m -s /bin/bash fakeuser
echo "fakeuser:wrongpassword" | chpasswd

# -----------------------------------------------------------------------------
# 4. Fail2Ban base configuration
# -----------------------------------------------------------------------------
cat > /etc/fail2ban/jail.d/sshd-mqtt.conf << 'EOF'
[sshd]
enabled   = true
backend   = systemd
maxretry  = 5
findtime  = 60
bantime   = 600
action    = iptables-multiport[name=SSH, port="ssh", protocol=tcp]
            mqtt-ban
EOF

# -----------------------------------------------------------------------------
# 5. MQTT publish script (called by Fail2Ban action)
# -----------------------------------------------------------------------------
cat > /usr/local/bin/f2b_mqtt_publish.sh << 'EOF'
#!/bin/bash
# f2b_mqtt_publish.sh <ip> <jail>
# Called by Fail2Ban when a ban event is triggered.
IP="${1:-unknown}"
JAIL="${2:-sshd}"
BROKER="10.0.1.1"       # Firewall / MQTT broker
TOPIC="sec/fail2ban/ban"

PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
    'src_ip':  sys.argv[1],
    'source':  'fail2ban',
    'jail':    sys.argv[2]
}))
" "$IP" "$JAIL")

mosquitto_pub -h "$BROKER" -t "$TOPIC" -m "$PAYLOAD"
echo "[$(date -u --iso-8601=seconds)] Published ban: $PAYLOAD" >> /var/log/f2b-mqtt.log
EOF
chmod +x /usr/local/bin/f2b_mqtt_publish.sh

# -----------------------------------------------------------------------------
# 6. Custom Fail2Ban MQTT action definition
# -----------------------------------------------------------------------------
cat > /etc/fail2ban/action.d/mqtt-ban.conf << 'EOF'
[Definition]
actionban  = /usr/local/bin/f2b_mqtt_publish.sh <ip> <name>
actionunban =

[Init]
EOF

# -----------------------------------------------------------------------------
# 7. Enable and restart Fail2Ban
# -----------------------------------------------------------------------------
systemctl enable fail2ban
systemctl restart fail2ban

echo ""
echo "[+] System 3 Victim setup complete."
echo "    - IP: 10.0.1.10, gateway: 10.0.1.1"
echo "    - SSH server running; target user: fakeuser"
echo "    - Fail2Ban configured: maxretry=5, findtime=60s, bantime=600s"
echo "    - Custom action 'mqtt-ban' publishes to sec/fail2ban/ban on 10.0.1.1:1883"
echo "    - Logs: /var/log/f2b-mqtt.log"
echo ""
echo "    To verify Fail2Ban is active:"
echo "      fail2ban-client status sshd"
echo "    To manually unban between trials:"
echo "      fail2ban-client set sshd unbanip 10.0.0.50"
