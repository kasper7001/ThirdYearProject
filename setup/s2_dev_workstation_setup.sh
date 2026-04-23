#!/bin/bash
# =============================================================================
# System 2 – Dev Workstation (Attacker) VM Setup Script
# Role: Developer pushing commits (including a malicious EICAR commit)
# IP: 10.0.1.2 / gateway: 10.0.1.1
# =============================================================================
set -e

echo "[*] System 2 – Dev Workstation setup starting..."

# -----------------------------------------------------------------------------
# 1. Network configuration
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
# 2. Install packages
# -----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y git openssh-client

git config --global user.email "dev@example.com"
git config --global user.name "Developer"

# -----------------------------------------------------------------------------
# 3. Generate SSH key for dev identity (KEY_ID=dev1)
# -----------------------------------------------------------------------------
if [ ! -f /root/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@attacker"
    echo "[*] SSH key generated."
fi

echo ""
echo "[!] Add developer public key to Repo-Controller authorized_keys as dev1:"
echo '    environment="KEY_ID=dev1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding' $(cat /root/.ssh/id_ed25519.pub)

# -----------------------------------------------------------------------------
# 4. Clone repository and create helper scripts
# -----------------------------------------------------------------------------
REPO_CONTROLLER="10.0.3.20"
ssh-keyscan -H "$REPO_CONTROLLER" >> /root/.ssh/known_hosts 2>/dev/null || true

if [ ! -d /root/project ]; then
    git clone git@${REPO_CONTROLLER}:/home/git/repos/project.git /root/project || \
        echo "[!] Clone failed – run manually after adding SSH key to repo-controller"
fi

# Helper: push a clean commit
cat > /root/push_clean.sh << 'SEOF'
#!/bin/bash
cd /root/project
git pull origin main 2>/dev/null || true
echo "hello world $(date)" > test.txt
git add test.txt
git commit -m "clean commit"
git push origin main
SEOF
chmod +x /root/push_clean.sh

# Helper: push a malicious EICAR commit
cat > /root/push_malicious.sh << 'SEOF'
#!/bin/bash
cd /root/project
git pull origin main 2>/dev/null || true
# EICAR test string (safe – triggers AV but is not real malware)
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
git add eicar.txt
git commit -m "malicious commit"
git push origin main
SEOF
chmod +x /root/push_malicious.sh

echo ""
echo "[+] System 2 Dev Workstation setup complete."
echo "    - SSH key: /root/.ssh/id_ed25519.pub"
echo "    - Clean commit script:     /root/push_clean.sh"
echo "    - Malicious commit script: /root/push_malicious.sh"
