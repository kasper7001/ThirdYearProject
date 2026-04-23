#!/usr/bin/env bash
set -eu

WATCH_DIR="/srv/labdata"
BROKER="10.0.3.1"
TOPIC="hids/alerts"

WINDOW_SECONDS=10
THRESHOLD_EVENTS=50

VICTIM_IP="$(ip -4 addr show | awk '/inet / {print $2}' | grep -v '^127' | cut -d/ -f1 | head -n1)"


get_attacker_ip() {
  if [[ -f /run/last_attacker_ip ]]; then
    cat /run/last_attacker_ip
  else
    echo "unknown"
  fi
}
declare -a TIMES=()

publish_alert() {
  local attacker_ip="$1"
  local count="$2"
  local now_iso
  now_iso="$(date -Iseconds)"

  local payload
  payload=$(cat <<EOF
{"timestamp":"$now_iso","victim_ip":"$VICTIM_IP","attacker_ip":"$attacker_ip","reason":"mass_file_changes","watch_dir":"$WATCH_DIR","window_seconds":$WINDOW_SECONDS,"event_count":$count}
EOF
)

  mosquitto_pub -h "$BROKER" -t "$TOPIC" -m "$payload" -q 1
  logger -t mass-change-detector "ALERT published to $TOPIC: $payload"
}

logger -t mass-change-detector "Watching $WATCH_DIR for mass file changes"

while true; do
  inotifywait -m -r "$WATCH_DIR" \
    -e create -e modify -e delete -e moved_to -e moved_from -e close_write \
    --quiet | while read -r _; do

      ts="$(date +%s)"
      TIMES+=("$ts")

      cutoff=$(( ts - WINDOW_SECONDS ))
      new_times=()
      for t in "${TIMES[@]}"; do
        if (( t >= cutoff )); then
          new_times+=("$t")
        fi
      done
      TIMES=("${new_times[@]}")

      count="${#TIMES[@]}"
      if (( count >= THRESHOLD_EVENTS )); then
        attacker_ip="$(get_attacker_ip)"
        publish_alert "$attacker_ip" "$count"
        TIMES=()
      fi
  done

  # If inotifywait exits, log it and restart after a short pause
  logger -t mass-change-detector "inotifywait exited, restarting watcher"
  sleep 1
done
