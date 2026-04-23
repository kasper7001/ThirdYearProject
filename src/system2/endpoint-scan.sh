#!/usr/bin/env bash
set -euo pipefail

BROKER="10.0.3.1"
TOPIC="repo/alerts"
WORKDIR="$HOME/endpoint/project"

CLEANUP="${CLEANUP:-0}"

cd "$WORKDIR"
git pull --ff-only

commit="$(git rev-parse HEAD)"
author="$(git log -1 --pretty=format:%an)"
ts="$(date -Is)"
host="$(hostname)"

SCAN_OUT="$(clamscan -r --infected --no-summary . || true)"

if echo "$SCAN_OUT" | grep -q "FOUND"; then
  hit="$(echo "$SCAN_OUT" | grep "FOUND" | head -n 1 | sed 's/"/\\"/g')"

  payload="{\"event\":\"malware_detected\",\"commit\":\"$commit\",\"author\":\"$author\",\"host\":\"$host\",\"ts\":\"$ts\",\"hit\":\"$hit\"}"
  mosquitto_pub -h "$BROKER" -t "$TOPIC" -m "$payload"

  echo "[ALERT] $hit"
  echo "[ALERT] Published to $TOPIC (commit $commit)"

  if [ "$CLEANUP" = "1" ]; then
    find . -type f -iname "*eicar*" -delete || true
    echo "[CLEANUP] Deleted *eicar* files"
  else
    echo "[CLEANUP] Skipped (set CLEANUP=1 to delete)"
  fi
else
  echo "[OK] No malware detected (commit $commit)"
fi
