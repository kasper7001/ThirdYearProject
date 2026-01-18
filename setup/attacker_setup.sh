#!/usr/bin/env bash
set -euo pipefail

IFACE="enp0s3"
ATTACKER_IP="10.0.1.2/24"
GW_IP="10.0.1.1"

echo "[*] Installing tools..."
apt update
apt install -y nmap iputils-ping

echo "[*] Configure IP (idempotent) + gateway..."
ip addr add "${ATTACKER_IP}" dev "${IFACE}" 2>/dev/null || true
ip link set "${IFACE}" up || true
ip route replace default via "${GW_IP}"

echo "[*] Done."
echo "Example attack traffic:"
echo "  ping -c 2 10.0.3.2"
echo "  nmap -sT -p 22 10.0.3.2"
