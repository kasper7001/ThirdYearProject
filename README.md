# Dynamic Reconfiguration of Security Controls to Mitigate Unexpected Attacks

**B.Sc. (Hons) Computer Science – Third Year Project**

This project investigates whether collaboration and adaptive reconfiguration between
security controls improves the detection and mitigation of attacks compared to security
controls operating in isolation. Three experimental systems were implemented in a
virtualised network environment, each demonstrating a different type of inter-control
coordination via MQTT.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Repository Structure](#repository-structure)
- [Architecture Summary](#architecture-summary)
  - [System 1 – Collaborative HIDS and Firewall](#system-1--collaborative-hids-and-firewall)
  - [System 2 – Adaptive Supply-Chain Security](#system-2--adaptive-supply-chain-security)
  - [System 3 – Host Detection Escalation to Network Enforcement](#system-3--host-detection-escalation-to-network-enforcement)
- [Requirements](#requirements)
- [Reproducing the Environment](#reproducing-the-environment)
  - [VirtualBox Network Configuration](#virtualbox-network-configuration)
  - [Running the Setup Scripts](#running-the-setup-scripts)
- [Running an Experiment](#running-an-experiment)
  - [System 1 – Trial Procedure](#system-1--trial-procedure)
  - [System 2 – Trial Procedure](#system-2--trial-procedure)
  - [System 3 – Trial Procedure](#system-3--trial-procedure)
- [Key Operational Notes](#key-operational-notes)
- [Known Limitations](#known-limitations)

---

## Project Overview

Three collaborative security systems were designed and evaluated:

| System | Detection Mechanism | Coordination | Enforcement |
|--------|-------------------|--------------|-------------|
| 1 | Host-based IDS (mass file change) | MQTT | iptables + ipset (firewall block) |
| 2 | Malware scanner (ClamAV + EICAR) | MQTT | Git rollback + identity denylist |
| 3 | Fail2Ban (SSH brute-force) | MQTT | iptables FORWARD DROP (firewall) |

Each system was tested in two configurations: a **baseline** (controls operating independently) and a **collaborative** (detection triggers automated enforcement).

---

## Repository Structure

```
ThirdYearProject/
├── README.md
├── LICENSE
├── setup/                        # VM provisioning scripts (run once per VM)
│   ├── s1_firewall_setup.sh
│   ├── s1_victim_ids_setup.sh
│   ├── s1_victim2_setup.sh
│   ├── s1_attacker_setup.sh
│   ├── s2_repo_controller_setup.sh
│   ├── s2_scanner_setup.sh
│   ├── s2_dev_workstation_setup.sh
│   ├── s3_firewall_setup.sh
│   ├── s3_victim_setup.sh
│   └── s3_attacker_setup.sh
├── src/                          # Runtime scripts deployed to VMs
│   ├── system1/
│   │   ├── cache-attacker-ip.sh        # PAM hook – caches SSH remote IP
│   │   ├── mass-change-detector.sh     # HIDS – monitors /srv/labdata for bulk changes
│   │   ├── mqtt_blocker.py             # Firewall subscriber – adds IPs to ipset
│   │   ├── hids-mqtt-blocker.sh        # Shell wrapper for mqtt_blocker
│   │   └── suri_mqtt_publisher.py      # Legacy Suricata publisher (reference only)
│   ├── system2/
│   │   ├── endpoint-scan.sh            # Pull repo + ClamAV scan + MQTT publish
│   │   ├── repo_controller.py          # MQTT subscriber – rollback + denylist
│   │   ├── repo-enforcer.sh            # Shell wrapper for repo_controller
│   │   └── pre-receive                 # Git hook – blocks denylisted identities
│   └── system3/
│       ├── f2b_mqtt_publish.sh         # Fail2Ban action – publishes ban event via MQTT
│       ├── fw_block_ip.sh              # Inserts DROP rule into iptables FORWARD chain
│       └── mqtt_fw_subscriber.sh       # Firewall subscriber – receives alerts, calls fw_block_ip
└── systemd/                      # systemd service unit files
    ├── hids-mqtt-blocker.service
    ├── mass-change-detector.service
    ├── mqtt-blocker.service
    ├── mqtt-fw-subscriber.service
    ├── repo-enforcer.service
    └── suri-mqtt-publisher.service
```

---

## Architecture Summary

All three systems share a common coordination model:

```
Detection Control  →  MQTT Broker  →  Enforcement Control
   (publishes alert)                  (subscribes, reconfigures)
```

The MQTT broker runs on Mosquitto and is hosted on the firewall/bastion VM in every system. No authentication or TLS is configured as the broker is restricted to isolated internal networks.

### System 1 – Collaborative HIDS and Firewall

**Scenario:** Attacker gains SSH access to an internal host and performs mass file modification (simulating post-compromise ransomware-style impact). The HIDS detects this and the firewall automatically blocks the attacker at the perimeter, protecting all internal hosts.

**Network topology:**

```
Attacker VM (10.0.1.2)
        |
  [enp0s9 – 10.0.1.1]
  Firewall/Bastion VM        <- MQTT broker + iptables + ipset
  [enp0s8 – 10.0.3.1]
        |
  Victim-IDS (10.0.3.2)     <- HIDS, mass-change-detector, MQTT publisher
  Victim 2   (10.0.3.3)     <- No IDS (blast-radius demonstration)
```

**Flow:**
1. Attacker SSHs to Victim-IDS and modifies 100+ files in `/srv/labdata/`
2. `mass-change-detector` detects the rate of change exceeds the threshold
3. Alert published to MQTT topic `hids/alerts` (includes attacker IP from PAM hook)
4. Firewall receives alert, adds attacker IP to ipset `attacker_block`
5. iptables FORWARD rule drops all traffic from `attacker_block`
6. SSH session terminated; Victim 2 is also protected

**MQTT topic:** `hids/alerts`

---

### System 2 – Adaptive Supply-Chain Security

**Scenario:** A developer (attacker) pushes a malicious commit containing an EICAR test string to a shared Git repository. An endpoint scanner detects the malware, triggering automatic rollback of the commit and denylisting of the developer identity.

**Network topology:**

```
Dev Workstation / Attacker (10.0.1.2)
        |  git push (SSH, KEY_ID=dev1)
  Repo-Controller (10.0.3.20)         <- bare Git repo, pre-receive hook, MQTT subscriber
        |  git pull
  Endpoint Scanner (10.0.3.2)         <- ClamAV scan, MQTT publisher
        |
  Bastion/MQTT (10.0.3.1)             <- Mosquitto broker
```

**Flow:**
1. Developer pushes a commit containing the EICAR test string
2. Scanner pulls the repo and runs `endpoint-scan.sh` (ClamAV)
3. EICAR detected → JSON alert published to `repo/alerts` (includes KEY_ID, commit hash)
4. Repo-Controller receives alert, rolls back `main` to the previous clean commit
5. Developer KEY_ID appended to `/home/git/denylist.txt`
6. Pre-receive hook blocks all future pushes from the denylisted identity

**MQTT topic:** `repo/alerts`

**Identity tagging:** SSH keys in `authorized_keys` are tagged with `environment="KEY_ID=dev1"` so the identity is available at scan time.

---

### System 3 – Host Detection Escalation to Network Enforcement

**Scenario:** Attacker brute-forces SSH on a victim host. Fail2Ban detects repeated authentication failures and bans the attacker locally, then publishes an MQTT alert. The perimeter firewall receives the alert and inserts a DROP rule, blocking the attacker at the network level.

**Network topology:**

```
Attacker VM (10.0.0.50)
        |
  [enp0s8 – 10.0.0.1]
  Firewall VM                <- MQTT broker + iptables enforcement
  [enp0s9 – 10.0.1.1]
        |
  Victim VM (10.0.1.10)      <- SSH server + Fail2Ban + MQTT publisher
```

**Flow:**
1. Attacker sends repeated failed SSH login attempts (`fakeuser@10.0.1.10`)
2. Fail2Ban detects ≥5 failures within 60 seconds → bans attacker locally
3. Custom `mqtt-ban` action executes `f2b_mqtt_publish.sh`
4. JSON alert published to `sec/fail2ban/ban` (includes `src_ip`, `jail`)
5. Firewall subscriber receives alert and runs `fw_block_ip.sh <ip>`
6. `iptables -I FORWARD 1 -s <ip> -j DROP` inserted dynamically
7. Attacker blocked at perimeter; victim host protected network-wide

**MQTT topic:** `sec/fail2ban/ban`

**Fail2Ban thresholds:** `maxretry=5`, `findtime=60s`, `bantime=600s`

---

## Requirements

- **Virtualisation:** Oracle VirtualBox (tested with 6.1 / 7.0)
- **Guest OS:** Debian 12 (Bookworm) – all VMs
- **Host OS:** Any (tested on Linux and Windows)
- **Network:** VirtualBox Internal Networks (no physical hardware required)
- **Internet access:** Required during setup for `apt-get` packages; not required during trials

Packages installed automatically by the setup scripts:

| VM | Key packages |
|----|-------------|
| Firewall (S1/S2) | `mosquitto`, `iptables-persistent`, `ipset`, `python3-paho-mqtt` |
| Firewall (S3) | `mosquitto`, `iptables-persistent`, `mosquitto-clients`, `jq` |
| Victim-IDS (S1) | `python3-paho-mqtt`, `openssh-server`, `libpam-runtime` |
| Scanner (S2) | `clamav`, `git`, `python3-paho-mqtt`, `mosquitto-clients` |
| Repo-Controller (S2) | `git`, `openssh-server`, `python3-paho-mqtt` |
| Victim (S3) | `fail2ban`, `openssh-server`, `mosquitto-clients` |
| Attacker (all) | `nmap`, `openssh-client`, `iputils-ping` |

---

## Reproducing the Environment

### VirtualBox Network Configuration

Each VM requires two NICs configured in VirtualBox before booting:

**System 1 – Firewall/Bastion:**

| Adapter | Type | Name |
|---------|------|------|
| Adapter 1 | NAT | *(auto)* |
| Adapter 2 | Internal Network | `victim-net` |
| Adapter 3 | Internal Network | `attacker-net` |

**System 1 – Victim-IDS and Victim 2:**

| Adapter | Type | Name |
|---------|------|------|
| Adapter 1 | Internal Network | `victim-net` |

**System 1 – Attacker:**

| Adapter | Type | Name |
|---------|------|------|
| Adapter 1 | Internal Network | `attacker-net` |

> System 2 reuses the same VM slots and internal network names as System 1.
>
> System 3 uses separate internal networks: `s3-attacker-net` (10.0.0.0/24) and `s3-victim-net` (10.0.1.0/24).

---

### Running the Setup Scripts

1. Boot each VM from a fresh Debian 12 minimal install.
2. Copy the relevant setup script from `setup/` to the VM (via shared folder, USB, or paste into terminal).
3. Run as root:

```bash
chmod +x <script>.sh
sudo ./<script>.sh
```

Run scripts in this order within each system:

**System 1:**
```
s1_firewall_setup.sh        (on Firewall VM)
s1_victim_ids_setup.sh      (on Victim-IDS VM)
s1_victim2_setup.sh         (on Victim 2 VM)
s1_attacker_setup.sh        (on Attacker VM)
```

After setup, copy the attacker's public key (`/root/.ssh/id_ed25519.pub`) into `/root/.ssh/authorized_keys` on Victim-IDS.

**System 2:**
```
s2_repo_controller_setup.sh    (on Repo-Controller VM)
s2_scanner_setup.sh            (on Scanner VM)
s2_dev_workstation_setup.sh    (on Dev Workstation VM)
```

After setup:
- Append scanner public key to `/home/git/.ssh/authorized_keys` on Repo-Controller with `KEY_ID=scanner1`
- Append developer public key to `/home/git/.ssh/authorized_keys` on Repo-Controller with `KEY_ID=dev1`

Format for each entry:
```
environment="KEY_ID=dev1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... root@attacker
```

**System 3:**
```
s3_firewall_setup.sh    (on Firewall VM)
s3_victim_setup.sh      (on Victim VM)
s3_attacker_setup.sh    (on Attacker VM)
```

---

## Running an Experiment

### System 1 – Trial Procedure

**Reset between trials:**
```bash
# On Firewall VM
sudo ipset flush attacker_block
```

**Baseline trial** (controls operating independently):
```bash
# Ensure hids-mqtt-blocker.service and mass-change-detector.service are STOPPED
sudo systemctl stop hids-mqtt-blocker.service mass-change-detector.service

# On Attacker VM – SSH in and modify files
ssh kasper@10.0.3.2
for i in $(seq 1 100); do echo "change$i" > /srv/labdata/file$i.txt; done
whoami   # session remains active – no enforcement
```

**Collaborative trial:**
```bash
# On Firewall VM – start the subscriber
sudo systemctl start hids-mqtt-blocker.service

# On Victim-IDS VM – start the detector
sudo systemctl start mass-change-detector.service

# On Attacker VM – SSH in and modify files
ssh kasper@10.0.3.2
for i in $(seq 1 100); do echo "change$i" > /srv/labdata/file$i.txt; done
# SSH session will be terminated mid-execution once alert fires

# Verify block on Firewall VM
sudo ipset list attacker_block
ping -c 3 10.0.3.2   # should show 100% packet loss
```

**Latency measurement:**
```bash
# On Victim-IDS – get detection timestamp
journalctl -u mass-change-detector.service | grep "ALERT published"

# On Firewall – get enforcement timestamp
journalctl -u hids-mqtt-blocker.service | grep "Blocked"
# Or: tail /var/log/sec-reconfig.log
```

---

### System 2 – Trial Procedure

**Reset between trials:**
```bash
# On Repo-Controller VM
sudo -u git git --git-dir=/home/git/repos/project.git log --oneline -3
# Roll back to last clean commit if needed:
sudo -u git git --git-dir=/home/git/repos/project.git update-ref refs/heads/main <clean_commit_hash>
# Clear denylist:
> /home/git/denylist.txt
```

**Baseline trial** (detection only, no enforcement):
```bash
# Ensure repo-enforcer.service is STOPPED on Repo-Controller
sudo systemctl stop repo-enforcer.service

# On Dev Workstation – push malicious commit
/root/push_malicious.sh

# On Scanner VM – scan (detects but takes no action)
/opt/endpoint-scan.sh

# Verify malicious commit still present (no rollback)
sudo -u git git --git-dir=/home/git/repos/project.git log --oneline -3
```

**Collaborative trial:**
```bash
# On Repo-Controller – start subscriber
sudo systemctl start repo-enforcer.service

# On Dev Workstation – push malicious commit
/root/push_malicious.sh

# On Scanner VM – scan and publish alert
/opt/endpoint-scan.sh

# Verify on Repo-Controller:
cat /home/git/denylist.txt                                        # dev1 listed
sudo -u git git --git-dir=/home/git/repos/project.git log --oneline -3  # malicious commit gone

# Verify push is blocked:
# On Dev Workstation:
/root/push_clean.sh   # should be rejected by pre-receive hook
```

---

### System 3 – Trial Procedure

**Reset between trials:**
```bash
# On Firewall VM – remove dynamic DROP rule
sudo iptables -D FORWARD -s 10.0.0.50 -j DROP

# On Victim VM – unban attacker in Fail2Ban
sudo fail2ban-client set sshd unbanip 10.0.0.50
```

**Baseline trial:**
```bash
# Ensure mqtt-fw-subscriber.service is STOPPED on Firewall
sudo systemctl stop mqtt-fw-subscriber.service

# On Attacker VM – brute-force SSH
for i in {1..10}; do ssh -o StrictHostKeyChecking=no fakeuser@10.0.1.10; done

# Verify on Firewall – no DROP rule inserted
sudo iptables -L FORWARD -n -v

# Attacker can still ping victim (local ban only)
ping -c 3 10.0.1.10
```

**Collaborative trial:**
```bash
# On Firewall VM – start subscriber
sudo systemctl start mqtt-fw-subscriber.service

# On Attacker VM – brute-force SSH
for i in {1..10}; do ssh -o StrictHostKeyChecking=no fakeuser@10.0.1.10; done

# Verify on Firewall:
sudo iptables -L FORWARD -n -v          # DROP rule for 10.0.0.50 at position 1
tail /var/log/sec-reconfig.log           # blocked ip=10.0.0.50

# Attacker blocked at perimeter:
ping -c 5 10.0.1.10   # 100% packet loss
```

**Latency measurement (note clock drift between VMs):**
```bash
# Victim – Fail2Ban ban timestamp
tail /var/log/fail2ban.log | grep "Ban"

# Firewall – enforcement timestamp
tail /var/log/sec-reconfig.log
```

> **Note:** The Victim and Firewall VMs in System 3 are not NTP-synchronised. Timestamps from each VM are internally consistent but cannot be directly compared. Latency is characterised as sub-second based on the sequential and deterministic nature of the enforcement pipeline.

---

## Key Operational Notes

- **Always flush/reset dynamic state before each trial** — ipset entries, Fail2Ban bans, and denylist entries all persist until cleared manually.
- The MQTT broker must be running before starting any subscriber or publisher service. Verify with: `systemctl status mosquitto`
- In System 1, the PAM hook (`cache-attacker-ip.sh`) captures the attacker IP at SSH login time. If no IP is cached, check `/run/last_attacker_ip` exists after the SSH session opens.
- In System 2, `PermitUserEnvironment yes` must remain in the **global** section of `/etc/ssh/sshd_config` (not inside a `Match` block) — this is an OpenSSH limitation.
- In System 3, Fail2Ban uses the `systemd` backend to read SSH logs. If alerts are not triggering, verify with `journalctl -u ssh` that failed login attempts are being logged.
- The MQTT broker is deployed **without authentication or TLS** — this is acceptable in the isolated lab environment but would require hardening (mutual TLS, username/password, network ACLs) for any production deployment.

---

## Known Limitations

- Experiments were conducted in a controlled virtualised environment and may not reflect the complexity of real-world enterprise networks.
- Detection mechanisms are rule-based with fixed thresholds, which may produce false positives under legitimate high-rate activity.
- The MQTT broker is a single point of failure — if it becomes unavailable, coordination silently degrades to baseline standalone behaviour with no administrator notification.
- System 3 has no NTP synchronisation between VMs, which limits the precision of cross-VM latency measurements.
- The MQTT broker has no authentication or transport encryption in the current implementation.
