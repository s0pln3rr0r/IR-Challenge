#!/usr/bin/env bash
set -euo pipefail
# Benign activity — realistic use of the same tools used in the attack.
# This prevents simple grep-based detection from immediately solving the challenge.

# curl — legitimate health checks
curl -fsS http://127.0.0.1/health >/dev/null 2>&1 || true
curl -sS http://127.0.0.1/api/status >/dev/null 2>&1 || true

# dig — legitimate DNS lookups
dig +short localhost >/dev/null 2>&1 || true
dig +short google.com >/dev/null 2>&1 || true
dig +short debian.org >/dev/null 2>&1 || true

# ping — legitimate connectivity checks
ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
ping -c 1 -W 1 10.10.20.50 >/dev/null 2>&1 || true

# gzip — legitimate log rotation
mkdir -p /var/log/app
echo "legitimate log entry $(date)" >>/var/log/app/application.log
gzip -c /var/log/app/application.log >/tmp/legit.log.gz

# base64 — legitimate encoding
base64 -w0 /var/log/app/application.log >/tmp/legit.log.b64

# openssl — legitimate certificate check
openssl version >/dev/null
openssl rand -hex 8 >/dev/null 2>&1 || true

# sha256sum — legitimate integrity check
sha256sum /var/log/app/application.log >/dev/null

# find — legitimate log discovery
find /var/log -type f -name '*.log' -mtime -1 | head >/dev/null

# System monitoring
df -h >/dev/null
free -m >/dev/null
ss -lntup >/dev/null 2>&1 || true
uptime >/dev/null
who >/dev/null

# Cleanup
rm -f /tmp/legit.log.gz /tmp/legit.log.b64
