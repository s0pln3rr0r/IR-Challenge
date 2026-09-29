#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env" 2>/dev/null || true
O="$ROOT/output/endpoint"; mkdir -p "$O"

# Collect local endpoint evidence
for pair in "/var/log/audit/audit.log audit.log" "/var/log/auth.log auth.log" "/var/log/syslog syslog.log" "/root/.bash_history bash_history.txt" "/var/log/app/application.log application.log"; do
  set -- $pair
  [[ -e "$1" ]] && cp -a "$1" "$O/$2"
done

# Collect bash history from victim machine via SCP (if VICTIM_IP is set)
if [ -n "${VICTIM_IP:-}" ]; then
    echo "[*] Collecting bash history from victim at $VICTIM_IP..."
    # Try multiple possible locations for bash history on the victim
    for hist_path in "/root/.bash_history" "/home/*/.bash_history"; do
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VICTIM_IP:$hist_path" "$O/victim_bash_history.txt" 2>/dev/null && {
            echo "[+] Victim bash history collected from $hist_path"
            break
        } || true
    done
    # If SCP failed, try using ssh + cat
    if [ ! -f "$O/victim_bash_history.txt" ]; then
        echo "[*] Trying ssh to collect victim bash history..."
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VICTIM_IP" "cat /root/.bash_history" > "$O/victim_bash_history.txt" 2>/dev/null || {
            echo "[-] Could not collect victim bash history (expected if victim is not reachable)"
            touch "$O/victim_bash_history.txt"
        }
    fi
fi

{
for f in /opt/app/config/production.env /opt/hr/employee_records.csv /var/backups/db.dump /opt/finance/q3_forecast.xlsx /srv/app/releases/release-notes.txt; do
  [[ -e "$f" ]] && stat --printf='%n\t%s\t%y\t%a\n' "$f"
done
} >"$O/sensitive_file_metadata.tsv"
echo "[+] endpoint evidence collected"
