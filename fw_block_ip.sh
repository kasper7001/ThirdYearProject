#!/usr/bin/env bash
set -euo pipefail
IP="${1:-}"
[ -n "$IP" ] || exit 1

if iptables -C FORWARD -s "$IP" -j DROP 2>/dev/null; then
  echo "$(date -Is) already_blocked ip=$IP" >> /var/log/sec-reconfig.log
else
  iptables -I FORWARD 1 -s "$IP" -j DROP
  echo "$(date -Is) blocked ip=$IP" >> /var/log/sec-reconfig.log
fi
