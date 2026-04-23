#!/bin/bash
# =============================================================================
# System 1 – Attacker VM Setup Script
# Role: Generates attack traffic (ping, nmap, SSH file modification)
# IP: 10.0.1.2 / gateway: 10.0.1.1
# =============================================================================
set -e

echo "[*] System 1 – Attacker setup starting..."

# -----------------------------------------------------------------------------
# 1. Static network configuration
# -----------------------------------------------------------------------------
cat > /etc/network/interfaces << 'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static
    address 10.0.1.2
    netmask 255.255.255.0
    gateway 10.0.1.1
EOF

cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF

# -----------------------------------------------------------------------------
# 2. Install attack tools
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y nmap openssh-client iputils-ping

# -----------------------------------------------------------------------------
# 3. Create SSH key pair for connecting to victims
# -----------------------------------------------------------------------------
if [ ! -f /root/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@attacker"
    echo "[*] SSH key generated: /root/.ssh/id_ed25519"
    echo "[!] Copy the public key below to victim authorized_keys:"
    cat /root/.ssh/id_ed25519.pub
fi

# -----------------------------------------------------------------------------
# 4. Helper attack scripts
# -----------------------------------------------------------------------------
cat > /root/run_baseline_attack.sh << 'SEOF'
#!/bin/bash
# Baseline trial: SSH in and modify 100 files
# Usage: ./run_baseline_attack.sh <victim_ip> <username>
VICTIM=${1:-10.0.3.2}
USER=${2:-kasper}
echo "[*] Connecting to $USER@$VICTIM and performing file modifications..."
ssh -o StrictHostKeyChecking=no "$USER@$VICTIM" \
    'for i in $(seq 1 100); do echo "change$i" > /srv/labdata/file$i.txt; done; whoami'
SEOF
chmod +x /root/run_baseline_attack.sh

echo ""
echo "[+] System 1 Attacker setup complete."
echo "    - IP: 10.0.1.2, gateway: 10.0.1.1"
echo "    - Tools: nmap, ssh, ping"
echo "    - SSH key: /root/.ssh/id_ed25519.pub  (add to victim authorized_keys)"
echo "    - Attack script: /root/run_baseline_attack.sh <victim_ip> <user>"
