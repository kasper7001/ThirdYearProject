#!/usr/bin/env python3
import json
import subprocess
import time
import paho.mqtt.client as mqtt
from datetime import datetime

BROKER = "127.0.0.1"
TOPIC = "ids/alerts"
IPSET = "attacker_block"
DEFAULT_TIMEOUT = 3600

def block_ip(ip, timeout):
    subprocess.run(
        ["ipset", "add", IPSET, ip, "timeout", str(timeout), "-exist"],
        check=False
    )

def on_connect(client, userdata, flags, rc, properties=None):
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        ip = data.get("src_ip")
        timeout = int(data.get("block_timeout", DEFAULT_TIMOUT))
        sig = data.get("signature", "unkown")
        ts = datetime.utcnow().isoformat() + "Z"

        if ip:
            block_ip(ip, timeout)
            print(f"[{ts}] BLOCKED {ip} reason='{sig}' timeout={timeout}s")
    except Exception as e:
         print("Error:", e)

def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(BROKER, 1883, 60)
            client.loop_forever()
        except Exception as e:
            print("MQTT error, retrying:" e)

if __name__ == "__main__":
    main()
