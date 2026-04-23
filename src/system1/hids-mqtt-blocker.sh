#!/usr/bin/env bash
set -eu

BROKER="localhost"
TOPIC="hids/alerts"

logger -t hids-mqtt-blocker "Starting HIDS MQTT blocker"

mosquitto_sub -h "$BROKER" -t "$TOPIC" | while read -r payload; do
  ip="$(echo "$payload" | jq -r '.attacker_ip // empty' || true)"

  if [[ -n "$ip" && "$ip" != "unknown" ]]; then
    ipset add attacker_block "$ip" -exist
    logger -t hids-mqtt-blocker "Blocked attacker IP $ip"
  else
    logger -t hids-mqtt-blocker "Alert received but attacker_ip missing/unknown: $payload"
  fi
done
