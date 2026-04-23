#!/usr/bin/env bash
echo "$SSH_CONNECTION" | awk '{print $1}' > /run/last_attacker_ip
