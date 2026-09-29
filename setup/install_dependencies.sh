#!/usr/bin/env bash
set -euo pipefail
ROLE="${1:-victim}"
export DEBIAN_FRONTEND=noninteractive
apt-get update
if [[ "$ROLE" == victim ]]; then
  apt-get install -y auditd audispd-plugins rsyslog curl dnsutils ftp mailutils openssl gzip xxd vim-common tcpdump python3 python3-pip
  python3 -m pip install openpyxl 2>/dev/null || apt-get install -y python3-openpyxl
else
  apt-get install -y tcpdump tshark python3 python3-pip dnsmasq postfix vsftpd curl
  # Ubuntu 14.04's pip/setuptools is too old to install modern packages.
  # Bootstrap a working pip via get-pip.py, then use it to install everything.
  if ! python3 -m pip install --upgrade pip setuptools 2>/dev/null; then
    echo "[*] Bootstrapping pip via get-pip.py..."
    curl -sS https://bootstrap.pypa.io/pip/3.4/get-pip.py -o /tmp/get-pip.py 2>/dev/null || \
    curl -sS https://bootstrap.pypa.io/pip/3.4/3.4/get-pip.py -o /tmp/get-pip.py 2>/dev/null || true
    if [ -f /tmp/get-pip.py ]; then
      python3 /tmp/get-pip.py 2>/dev/null || true
    fi
  fi
  # Install Python packages with version constraints for Python 3.4
  python3 -m pip install scapy dnslib "websockets<10" "qrcode<7" "pillow<10" 2>/dev/null || \
  apt-get install -y python3-scapy python3-pil 2>/dev/null; \
  python3 -m pip install dnslib "websockets<10" "qrcode<7" 2>/dev/null || true
fi
