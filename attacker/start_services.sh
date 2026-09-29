#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

mkdir -p "$ROOT/runtime/received"

# Configure IP aliases so all six logical destinations terminate on this VM
sudo bash "$ROOT/setup/configure_routing.sh" "${CAPTURE_INTERFACE:-eth0}"

# Generate QR code images (also used by smtp_sender.py at runtime)
python3 "$ROOT/attacker/generate_qr.py"

# Start HTTP receiver
nohup env SIXWAYS_RUNTIME="$ROOT/runtime" python3 "$ROOT/attacker/http_server.py" >"$ROOT/runtime/http.log" 2>&1 & echo $! >"$ROOT/runtime/http.pid"

# Start DNS receiver
nohup env SIXWAYS_RUNTIME="$ROOT/runtime" python3 "$ROOT/attacker/dns_server.py" >"$ROOT/runtime/dns.log" 2>&1 & echo $! >"$ROOT/runtime/dns.pid"

# Start WebSocket receiver
nohup python3 "$ROOT/attacker/websocket_server.py" >"$ROOT/runtime/websocket.log" 2>&1 & echo $! >"$ROOT/runtime/websocket.pid"

# Ensure FTP and SMTP services are running
systemctl restart vsftpd 2>/dev/null || service vsftpd restart 2>/dev/null || true
systemctl restart postfix 2>/dev/null || service postfix restart 2>/dev/null || true

echo "[+] All services started: HTTP, DNS, WebSocket, FTP, SMTP"
