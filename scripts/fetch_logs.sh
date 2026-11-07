#!/usr/bin/env bash
# Copy the honeypot's Cowrie JSON logs into data/raw. Read-only on the server.
set -euo pipefail
cd "$(dirname "$0")/.."

ip="$(terraform -chdir=infra output -raw public_ip)"
mkdir -p data/raw
# The glob runs in a root shell on the server, inside the root-owned log directory.
ssh -i ~/.ssh/panal_admin -p 22222 "ubuntu@${ip}" \
  "sudo sh -c 'cd /var/lib/docker/volumes/panal_cowrie-var/_data/log/cowrie && tar czf - cowrie.json*'" \
  | tar xzf - --no-same-owner -C data/raw
ls -lh data/raw
