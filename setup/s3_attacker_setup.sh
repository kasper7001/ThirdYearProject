#!/bin/bash
# =============================================================================
# System 3 – Attacker VM Setup Script
# Role: Generates SSH brute-force attempts against the victim
# IP: 10.0.0.50 / gateway: 10.0.0.1
# =============================================================================
set -e

echo "[*] System 3 – Attacker setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.0.50
    netmask 255.255.255.0
    gateway 10.0.0.1
EOF

cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF

# -----------------------------------------------------------------------------
# 2. Install tools
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y openssh-client iputils-ping nmap

# -----------------------------------------------------------------------------
# 3. Attack helper scripts
# -----------------------------------------------------------------------------

# Baseline connectivity test
cat > /root/check_connectivity.sh << 'SEOF'
#!/bin/bash
echo "[*] Pinging victim (10.0.1.10)..."
ping -c 5 10.0.1.10
echo "[*] Attempting SSH..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 fakeuser@10.0.1.10 exit 2>&1 | head -3
SEOF
chmod +x /root/check_connectivity.sh

# Brute-force simulation (triggers Fail2Ban after 5 attempts)
cat > /root/run_brute_force.sh << 'SEOF'
#!/bin/bash
# Simulates SSH brute-force: sends 10 failed login attempts
VICTIM=${1:-10.0.1.10}
echo "[*] Starting SSH brute-force simulation against $VICTIM..."
for i in $(seq 1 10); do
    echo "  Attempt $i..."
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 \
        -o NumberOfPasswordPrompts=1 \
        -o PasswordAuthentication=yes \
        fakeuser@"$VICTIM" 2>&1 | head -2 || true
done
echo "[*] Brute force attempts complete."
SEOF
chmod +x /root/run_brute_force.sh

echo ""
echo "[+] System 3 Attacker setup complete."
echo "    - IP: 10.0.0.50, gateway: 10.0.0.1"
echo "    - Connectivity test: /root/check_connectivity.sh"
echo "    - Brute-force attack: /root/run_brute_force.sh [victim_ip]"
echo ""
echo "    Example brute force (manual):"
echo "      for i in {1..10}; do ssh fakeuser@10.0.1.10; done"
