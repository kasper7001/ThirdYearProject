#!/usr/bin/env python3
import json
import subprocess
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

BROKER = "10.0.3.1"  # Bastion-MQTT IP
TOPIC = "repo/alerts"
BARE = "/home/git/repos/project.git"
DENYLIST = "/home/git/denylist.txt"  #used by pre-receive hook

def sh(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(f"{ts} {msg}", flush=True)

def tag_commit(commit: str) -> str:
    tag = f"quarantined/{int(time.time())}"
    sh(["git", "--git-dir", BARE, "tag", tag, commit])
    return tag

def rewind_main_if_tip_is(commit: str) -> bool:
    tip = sh(["git", "--git-dir", BARE, "rev-parse", "refs/heads/main"])
    if tip != commit:
        log(f"[SKIP] commit {commit} is not tip of main (tip is {tip})")
        return False

    prev = sh(["git", "--git-dir", BARE, "rev-parse", f"{commit}^"])
    sh(["git", "--git-dir", BARE, "update-ref", "refs/heads/main", prev])
    log(f"[ACTION] main rewound to {prev}")
    return True

def block_key_id(key_id: str) -> None:
    if not key_id:
        return
    # idempotent append
    try:
        with open(DENYLIST, "a+") as f:
            f.seek(0)
            existing = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}
            if key_id not in existing:
                f.write(key_id + "\n")
                log(f"[ENFORCE] blocked KEY_ID={key_id}")
            else:
                log(f"[ENFORCE] KEY_ID={key_id} already blocked")
    except Exception as e:
        log(f"[ERROR] denylist update failed: {e}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode("utf-8", errors="replace")
        data = json.loads(payload)

        bad_commit = data.get("commit", "")
        author = data.get("author", "")
        host = data.get("host", "")
        ts = data.get("ts", "")
        key_id = data.get("key_id", "")

        log(f"[ALERT] malware_detected commit={bad_commit} author={author} host={host} ts={ts} key_id={key_id}")

        if not bad_commit:
            log("[ERROR] alert missing 'commit'")
            return

        tag = tag_commit(bad_commit)
        log(f"[ACTION] tagged bad commit as {tag}")

        rewind_main_if_tip_is(bad_commit)
        if key_id:
            block_key_id(key_id)

    except Exception as e:
        log(f"[ERROR] {e}")

def main():
    client = mqtt.Client()
    client.on_message = on_message
    client.connect(BROKER, 1883, 60)
    client.subscribe(TOPIC)
    log(f"[START] subscribed to {TOPIC} on broker {BROKER}")
    client.loop_forever()

if __name__ == "__main__":
    main()
