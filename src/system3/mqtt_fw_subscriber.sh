#!/usr/bin/env bash
set -euo pipefail
TOPIC="sec/fail2ban/ban"

mosquitto_sub -h 127.0.0.1 -t "$TOPIC" | while read -r msg; do
  ip="$(echo "$msg" | sed -n 's/.*"src_ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [ -n "$ip" ]; then
    /usr/local/bin/fw_block_ip.sh "$ip"
  else
    echo "$(date -Is) bad_message msg=$msg" >> /var/log/sec-reconfig.log
  fi
done
