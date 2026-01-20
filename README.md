# ThirdYearProject

# Collaborative IDS–Firewall Adaptive Reconfiguration

## Project Overview
This project investigates whether **collaboration and adaptive reconfiguration**
between security controls improves system security compared to isolated controls.

A Suricata-based Intrusion Detection System (IDS) detects malicious activity and
publishes alert context via MQTT. A firewall subscribes to these alerts and
dynamically reconfigures itself using `ipset` to block detected attackers in
near real time.

The focus of the project is **coordination, context sharing, and adaptation**,
not perfect detection or firewall rules.

---

## Architecture

The system is implemented using three Debian virtual machines:

### Firewall VM
- Acts as:
  - Network gateway between attacker and victim
  - MQTT broker (Mosquitto)
  - Enforcement point (iptables + ipset)
- Interfaces:
  - NAT (internet access)
  - Attacker network: `10.0.1.0/24` (IP `10.0.1.1`)
  - Victim network: `10.0.3.0/24` (IP `10.0.3.1`)

### Victim VM (IDS)
- Runs Suricata IDS
- IP: `10.0.3.2`
- Publishes alert metadata (attacker IP, signature, timestamp) via MQTT

### Attacker VM
- IP: `10.0.1.2`
- Used to generate test traffic (ping, nmap)

---

## Bastion Firewall Design

The firewall VM also functions as an **SSH bastion host (jump host)** for the
internal victim network.

Direct administrative access (SSH) from the attacker network to victim hosts
is explicitly prohibited. All SSH access to internal hosts must traverse the
firewall, enforcing a single controlled entry point.

### Bastion Policy

- Attacker → Victim SSH: **Blocked**
- Attacker → Firewall SSH: **Allowed**
- Firewall → Victim SSH: **Allowed**

This ensures that:
- All administrative access crosses the firewall
- The firewall acts as a choke point for monitoring and enforcement
- Adaptive blocking at the firewall protects **all internal hosts**, not only
  the initially targeted system

---

## Core Components

### `suri_mqtt_publisher.py`
Runs on the victim VM.
- Monitors Suricata `eve.json`
- Extracts attacker IP and alert metadata
- Publishes alerts to MQTT topic `ids/alerts`

### `mqtt_blocker.py`
Runs on the firewall VM.
- Subscribes to MQTT alerts
- Adds attacker IPs to an `ipset` blocklist
- iptables drops traffic dynamically without restarting rules

---

## Demonstrated Behaviour

1. Attacker generates traffic toward the victim
2. Suricata detects the activity and logs an alert
3. IDS publishes alert context via MQTT
4. Firewall receives the alert
5. Firewall dynamically blocks the attacker IP
6. Subsequent attacker traffic is dropped

This demonstrates **collaborative detection and adaptive enforcement**.
When deployed as a bastion firewall, adaptive blocking at the gateway
immediately protects all internal hosts behind it, reducing the blast radius
of detected attacks.

---

## Reproducibility

### Manual VirtualBox Setup (Required)
Network interfaces must be configured manually in VirtualBox:

#### Firewall VM
- NAT interface (internet access)
- Internal network (victim): `10.0.3.1/24`
- Internal network (attacker): `10.0.1.1/24`

#### Victim VM
- Internal network (victim): `10.0.3.2/24`
- Default gateway: `10.0.3.1`

#### Attacker VM
- Internal network (attacker): `10.0.1.2/24`
- Default gateway: `10.0.1.1`

---

### Automated Setup Scripts
The `setup/` directory contains scripts to configure each VM:

- `setup/firewall_setup.sh`
- `setup/victim_ids_setup.sh`
- `setup/attacker_setup.sh`

Run the appropriate script on each VM as root:
```bash
sudo bash setup/<script_name>.sh

---

## Evaluation Direction

The system enables comparison between:

- Static firewall / bastion rules
- IDS-only detection without enforcement
- Collaborative IDS–firewall adaptive reconfiguration

Metrics include detection-to-block latency, residual attacker access after
first alert, and protection of additional internal hosts.
