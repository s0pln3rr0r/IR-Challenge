#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/output/network/zeek"
cd "$ROOT/output/network/zeek"
zeek -r ../exfiltration.pcap LogAscii::use_json=T
echo "[+] Zeek processing complete"
