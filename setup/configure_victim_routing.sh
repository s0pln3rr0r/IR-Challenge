#!/usr/bin/env bash
set -euo pipefail
# Configure routing on the victim machine so that the six logical destination
# IPs are routed through the services/capture machine.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

echo "[*] Configuring routes on victim machine ($VICTIM_IP)"
echo "[*] Services machine: $SERVICES_IP"

# Add routes for each logical destination IP via the services machine
for dest in "$HTTP_IP" "$DNS_IP" "$SMTP_IP" "$ICMP_IP" "$FTP_IP" "$WS_IP"; do
    # Check if route already exists
    if ip route get "$dest" 2>/dev/null | grep -q "$SERVICES_IP"; then
        echo "[*] Route to $dest already via $SERVICES_IP"
    else
        sudo ip route add "$dest/32" via "$SERVICES_IP" 2>/dev/null && \
            echo "[+] Added route: $dest -> $SERVICES_IP" || \
            echo "[!] Failed to add route for $dest (may already exist)"
    fi
done

echo "[+] Victim routing configured. All six destinations now route through $SERVICES_IP"