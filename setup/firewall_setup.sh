#!/usr/bin/env bash
set -euo pipefail

# ---- Config (edit if your interface names differ) ----
WAN_IF="enp0s3"
VICTIM_IF="enp0s8"
ATTACKER_IF="enp0s9"

FIREWALL_VICTIM_IP="10.0.3.1/24"
FIREWALL_ATTACKER_IP="10.0.1.1/24"

VICTIM_NET="10.0.3.0/24"
ATTACKER_NET="10.0.1.0/24"

MQTT_PORT="1883"
IPSET_NAME="attacker_block"

echo "[*] Installing packages..."
apt update
apt install -y \
  iptables-persistent netfilter-persistent \
  ipset ipset-persistent \
  mosquitto mosquitto-clients \
  python3 python3-paho-mqtt

echo "[*] Configuring IP addresses (idempotent)..."
ip addr add "${FIREWALL_VICTIM_IP}" dev "${VICTIM_IF}" 2>/dev/null || true
ip addr add "${FIREWALL_ATTACKER_IP}" dev "${ATTACKER_IF}" 2>/dev/null || true
ip link set "${VICTIM_IF}" up || true
ip link set "${ATTACKER_IF}" up || true

echo "[*] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1
sed -i 's/^#\?net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

echo "[*] Configuring Mosquitto broker..."
mkdir -p /etc/mosquitto/conf.d
cat >/etc/mosquitto/conf.d/lab.conf <<EOF
listener ${MQTT_PORT} 0.0.0.0
allow_anonymous true
log_type error
log_type warning
log_type notice
log_type information
EOF

systemctl enable --now mosquitto
systemctl restart mosquitto

echo "[*] Creating ipset and firewall rules..."
ipset create "${IPSET_NAME}" hash:ip timeout 3600 -exist

# NAT for Internet access (attacker/victim -> WAN)
iptables -t nat -C POSTROUTING -o "${WAN_IF}" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j MASQUERADE

# Default forward policy (project baseline)
iptables -P FORWARD DROP

# Allow established/related
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Baseline allow between attacker and victim (adjust as needed for your experiments)
iptables -C FORWARD -s "${ATTACKER_NET}" -d "${VICTIM_NET}" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s "${ATTACKER_NET}" -d "${VICTIM_NET}" -j ACCEPT

# Allow attacker/victim to access Internet via firewall (setup convenience)
iptables -C FORWARD -s "${ATTACKER_NET}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s "${ATTACKER_NET}" -o "${WAN_IF}" -j ACCEPT

iptables -C FORWARD -s "${VICTIM_NET}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s "${VICTIM_NET}" -o "${WAN_IF}" -j ACCEPT

# MQTT broker access on firewall INPUT (from victim net; add attacker net if you want)
iptables -C INPUT -p tcp -s "${VICTIM_NET}" --dport "${MQTT_PORT}" -j ACCEPT 2>/dev/null || \
iptables -I INPUT 1 -p tcp -s "${VICTIM_NET}" --dport "${MQTT_PORT}" -j ACCEPT

# Dynamic block rule (must be near top of FORWARD)
iptables -C FORWARD -m set --match-set "${IPSET_NAME}" src -j DROP 2>/dev/null || \
iptables -I FORWARD 1 -m set --match-set "${IPSET_NAME}" src -j DROP

echo "[*] Persisting iptables and ipset..."
netfilter-persistent save
ipset save > /etc/ipset.conf || true

echo "[*] Done. Next: place /opt/mqtt_blocker.py and run it."
