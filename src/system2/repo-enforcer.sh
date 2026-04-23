#!/bin/bash
BROKER="10.0.3.10"
TOPIC="repo/alerts"
REPO_DIR="/home/git/repos/project.git"
WORK_TREE="/tmp/repo-work"
DENYLIST="/home/git/denylist.txt"

mkdir -p "$WORK_TREE"

mosquitto_sub -h "$BROKER" -t "$TOPIC" | while read -r payload; do
    echo "[*] Alert received: $payload"

    COMMIT=$(echo "$payload" | jq -r '.commit')

    echo "[*] Rolling back main..."

    CURRENT=$(git --git-dir="$REPO_DIR" rev-parse refs/heads/main)
    PREV=$(git --git-dir="$REPO_DIR" rev-parse refs/heads/main^)

    git --git-dir="$REPO_DIR" update-ref refs/heads/main "$PREV"

    echo "[*] Rolled back from $CURRENT to $PREV"

    echo "[*] Denylisting dev1 (for demo)..."
    AUTHOR=$(echo "$payload" | jq -r '.author // empty')
    if [ -n "$AUTHOR" ]; then
      grep -qx "$AUTHOR" "$DENYLIST" || echo "$AUTHOR" >> "$DENYLIST"
      echo "[*] Denylisted $AUTHOR"
    fi
done
