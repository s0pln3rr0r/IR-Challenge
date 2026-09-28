#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"
mkdir -p "$ROOT/output/network" "$ROOT/runtime"
sudo tcpdump -i "$CAPTURE_INTERFACE" -s 0 -w "$ROOT/output/network/exfiltration.pcap" not port 22 &
echo $! > "$ROOT/runtime/capture.pid"
echo "[+] capture started"
