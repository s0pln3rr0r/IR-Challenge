#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
O="$ROOT/output/endpoint"; mkdir -p "$O"
for pair in "/var/log/audit/audit.log audit.log" "/var/log/auth.log auth.log" "/var/log/syslog syslog.log" "/root/.bash_history bash_history.txt" "/var/log/app/application.log application.log"; do
  set -- $pair
  [[ -e "$1" ]] && cp -a "$1" "$O/$2"
done
{
for f in /opt/app/config/production.env /opt/hr/employee_records.csv /var/backups/db.dump /opt/finance/q3_forecast.xlsx /srv/app/releases/release-notes.txt; do
  [[ -e "$f" ]] && stat --printf='%n\t%s\t%y\t%a\n' "$f"
done
} >"$O/sensitive_file_metadata.tsv"
echo "[+] endpoint evidence collected"
