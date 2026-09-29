#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"
hostnamectl set-hostname "$VICTIM_HOSTNAME" 2>/dev/null || hostname "$VICTIM_HOSTNAME" 2>/dev/null || true
# Install openpyxl for Python 3 (Ubuntu 14.04 only has it for Python 2)
# Bootstrap pip first if needed (Ubuntu 14.04 pip is too old)
python3 -m pip install --upgrade pip 2>/dev/null || \
  (curl -sS https://bootstrap.pypa.io/pip/3.4/get-pip.py -o /tmp/get-pip.py 2>/dev/null && \
   python3 /tmp/get-pip.py 2>/dev/null) || true
python3 -m pip install openpyxl 2>/dev/null || apt-get install -y python3-openpyxl 2>/dev/null || true
# Install websockets for WebSocket exfiltration channel
python3 -m pip install 'websockets<10' 2>/dev/null || true
mkdir -p /opt/app/config /opt/hr /var/backups /opt/finance /srv/app/releases /var/log/app
cat >/opt/app/config/production.env <<'EOF'
APP_ENV=production
DB_HOST=db-prod.internal
DB_USER=app_prod
DB_PASSWORD=Fake-Prod-Password-Only
API_ENDPOINT=https://api.internal.example/v2
MARKER=Q7k2mLp
EOF
cat >/opt/hr/employee_records.csv <<'EOF'
employee_id,name,department,status
1001,Aarav Shah,Engineering,active
1002,Meera Rao,Finance,active
1003,Kabir Mehta,HR,active
1004,Ishita Patel,Operations,active
1005,Rohan Desai,Engineering,active
record_integrity_marker,k91Xv2Qa,INTERNAL,do-not-share
EOF
printf 'DATABASE BACKUP HEADER\nschema=customer_portal\nrecords=18421\nbackup_marker=xP83LmQa\n' >/var/backups/db.dump
python3 "$ROOT/setup/generate_xlsx.py"
cat >/srv/app/releases/release-notes.txt <<'EOF'
Release 2026.09.27
- Updated dependency lockfile
- Reduced startup time
Release validation marker: Lm92Qx7P
EOF
printf '%s\n' '2026-09-27T18:00:01Z INFO application started' >/var/log/app/application.log
touch /root/.bash_history
chmod 600 /root/.bash_history
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/six-ways-out.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k sixways_exec
-w /opt/app/config/production.env -p rwxa -k sixways_sensitive
-w /opt/hr/employee_records.csv -p rwxa -k sixways_sensitive
-w /var/backups/db.dump -p rwxa -k sixways_sensitive
-w /opt/finance/q3_forecast.xlsx -p rwxa -k sixways_sensitive
-w /srv/app/releases/release-notes.txt -p rwxa -k sixways_sensitive
-w /tmp -p wa -k sixways_tmp
EOF
augenrules --load || true
systemctl restart auditd || true

# Configure routing so all six destination IPs route through the services machine
sudo bash "$ROOT/setup/configure_victim_routing.sh"

echo "[+] victim ready"
