#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

mkdir -p "$ROOT/runtime/received" "$ROOT/output"

# Configure IP aliases so all six logical destinations terminate on this VM
sudo bash "$ROOT/setup/configure_routing.sh" "${CAPTURE_INTERFACE:-eth0}"

# Configure FTP server
sudo bash "$ROOT/setup/configure_ftp.sh"

# Configure Postfix for SMTP
sudo bash "$ROOT/setup/configure_postfix.sh"

echo "[+] attacker/capture directories ready"
echo "[+] IP routing, FTP, and Postfix configured"
