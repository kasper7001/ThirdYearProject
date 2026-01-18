#!/usr/bin/env bash
set -euo pipefail

# ---- Config (edit if interface differs) ----
IFACE="enp0s3"
VICTIM_IP="10.0.3.2/24"
GW_IP="10.0.3.1"
FIREWALL_MQTT_IP="10.0.3.1"

echo "[*] Installing packages..."
apt update
apt install -y suricata ethtool python3 python3-paho-mqtt

echo "[*] Configure IP (idempotent) + gateway..."
ip addr add "${VICTIM_IP}" dev "${IFACE}" 2>/dev/null || true
ip link set "${IFACE}" up || true
ip route replace default via "${GW_IP}"

echo "[*] Disable NIC offloading (common VM requirement)..."
# Best-effort; some flags may be fixed depending on driver.
ethtool -K "${IFACE}" gro off gso off tso off lro off rx off tx off 2>/dev/null || true

echo "[*] Configure Suricata to capture on ${IFACE}..."
# Ensure af-packet uses correct interface
if grep -qE '^[[:space:]]*-[[:space:]]*interface:' /etc/suricata/suricata.yaml; then
  sed -i "s/^\([[:space:]]*-[[:space:]]*interface:\).*/\1 ${IFACE}/" /etc/suricata/suricata.yaml
else
  # If af-packet block is missing/unexpected, do not try to auto-insert complex YAML.
  echo "WARNING: Could not auto-update af-packet interface in /etc/suricata/suricata.yaml"
fi

echo "[*] Add deterministic local ICMP alert rule..."
mkdir -p /etc/suricata/rules
cat >/etc/suricata/rules/local.rules <<'EOF'
alert icmp any any -> any any (msg:"TEST ICMP ping detected"; sid:1000001; rev:1;)
EOF

# Ensure local.rules is referenced under rule-files:
if ! grep -q '^- local.rules' /etc/suricata/suricata.yaml; then
  sed -i '/^rule-files:/a\  - local.rules' /etc/suricata/suricata.yaml
fi

echo "[*] Restart Suricata..."
systemctl enable --now suricata
systemctl restart suricata

echo "[*] Sanity checks..."
suricata -T -c /etc/suricata/suricata.yaml >/dev/null || true
echo "Victim setup done. MQTT broker expected at ${FIREWALL_MQTT_IP}:1883"
echo "Next: place /opt/suri_mqtt_publisher.py and run it."
