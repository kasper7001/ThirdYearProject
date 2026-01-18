#!/usr/bin/env python3
import json
import time
import paho.mqtt.client as mqtt

EVE_FILE = "/var/log/suricata/eve.json"
BROKER = "10.0.3.1"  # Firewall
TOPIC = "ids/alerts"
BLOCK_TIMEOUT = 3600

def follow(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def main():
    client = mqtt.Client()
    client.connect(BROKER, 1883, 60)

    for line in follow(EVE_FILE):
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue

        if evt.get("event_type") != "alert":
            continue

        src_ip = evt.get("src_ip")
        signature = evt.get("alert", {}).get("signature", "unknown")

        if not src_ip:
            continue

        msg = {
            "timestamp": evt.get("timestamp"),
            "src_ip": src_ip,
            "signature": signature,
            "block_timeout": BLOCK_TIMEOUT,
            "sensor": "victim-suricata"
        }

        client.publish(TOPIC, json.dumps(msg), qos=0, retain=False)

if __name__ == "__main__":
    main()
