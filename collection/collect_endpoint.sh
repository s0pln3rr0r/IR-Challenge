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
    # Use timeout to prevent hanging on password prompts
    TIMEOUT_CMD="timeout 10"
    
    # Check if SSH key-based auth works first (non-interactive)
    if $TIMEOUT_CMD ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VICTIM_IP" "echo connected" 2>/dev/null; then
        echo "[*] SSH key auth works, collecting bash history..."
        $TIMEOUT_CMD scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VICTIM_IP:/root/.bash_history" "$O/victim_bash_history.txt" 2>/dev/null && {
            echo "[+] Victim bash history collected via SCP"
        } || {
            # Fallback: use ssh + cat
            $TIMEOUT_CMD ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VICTIM_IP" "cat /root/.bash_history" > "$O/victim_bash_history.txt" 2>/dev/null && {
                echo "[+] Victim bash history collected via SSH"
            } || {
                echo "[-] Could not collect victim bash history"
                touch "$O/victim_bash_history.txt"
            }
        }
    else
        echo "[-] SSH key auth not available for root@$VICTIM_IP"
        echo "[-] To set up: ssh-copy-id root@$VICTIM_IP (enter password when prompted)"
        echo "[-] Or manually copy from victim: scp root@$VICTIM_IP:/root/.bash_history $O/victim_bash_history.txt"
        touch "$O/victim_bash_history.txt"
    fi
fi

{
for f in /opt/app/config/production.env /opt/hr/employee_records.csv /var/backups/db.dump /opt/finance/q3_forecast.xlsx /srv/app/releases/release-notes.txt; do
  [[ -e "$f" ]] && stat --printf='%n\t%s\t%y\t%a\n' "$f"
done
} >"$O/sensitive_file_metadata.tsv"
echo "[+] endpoint evidence collected"
