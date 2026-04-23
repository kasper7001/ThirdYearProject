#!/bin/bash
# =============================================================================
# System 1 – Victim 2 VM Setup Script
# Role: Internal host with no IDS – used to demonstrate blast-radius reduction
# IP: 10.0.3.3 / gateway: 10.0.3.1
# =============================================================================
set -e

echo "[*] System 1 – Victim 2 setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.3.3
    netmask 255.255.255.0
    gateway 10.0.3.1
EOF

cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF

# -----------------------------------------------------------------------------
# 2. Install SSH server (so attacker can attempt connections)
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y openssh-server

systemctl enable ssh
systemctl start ssh

echo ""
echo "[+] System 1 Victim 2 setup complete."
echo "    - IP: 10.0.3.3, gateway: 10.0.3.1"
echo "    - SSH server running (for blast-radius demonstration)"
echo "    - No IDS installed – protection comes only from firewall enforcement"
