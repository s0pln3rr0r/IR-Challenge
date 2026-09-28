#!/usr/bin/env bash
set -euo pipefail
ROLE="${1:-victim}"
export DEBIAN_FRONTEND=noninteractive
apt-get update
if [[ "$ROLE" == victim ]]; then
  apt-get install -y auditd audispd-plugins rsyslog curl dnsutils ftp mailutils openssl gzip xxd vim-common tcpdump python3 python3-pip
  python3 -m pip install --break-system-packages openpyxl
else
  apt-get install -y tcpdump tshark python3 python3-pip dnsmasq postfix vsftpd
  python3 -m pip install --break-system-packages scapy dnslib websockets qrcode pillow
fi
