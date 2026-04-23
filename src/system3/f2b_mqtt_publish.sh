#!/usr/bin/env bash
set -euo pipefail
IP="${1:-}"
JAIL="${2:-unknown}"
BROKER="10.0.1.1"
TOPIC="sec/fail2ban/ban"
HOST="$(hostname)"
TS="$(date -Is)"

[ -n "$IP" ] || exit 1
payload=$(printf '{"event":"ban","src_ip":"%s","jail":"%s","host":"%s","ts":"%s"}' "$IP" "$JAIL" "$HOST" "$TS")
mosquitto_pub -h "$BROKER" -t "$TOPIC" -m "$payload"
