#!/usr/bin/env bash
set -euo pipefail
# Configure IP aliases on the services/capture VM so that the six logical
# destination IPs are locally reachable and terminate on this machine.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

INTERFACE="${1:-eth1}"

add_alias() {
    local ip="$1"
    local idx="$2"
    # Check if alias already exists
    if ip addr show "$INTERFACE" | grep -q "inet $ip/"; then
        echo "[*] $ip already assigned to $INTERFACE"
    else
        sudo ip addr add "$ip/32" dev "$INTERFACE" 2>/dev/null && echo "[+] Added $ip to $INTERFACE" || echo "[!] Failed to add $ip"
    fi
}

echo "[*] Configuring IP aliases on $INTERFACE for services VM ($SERVICES_IP)"

add_alias "$HTTP_IP" 0
add_alias "$DNS_IP" 1
add_alias "$SMTP_IP" 2
add_alias "$ICMP_IP" 3
add_alias "$FTP_IP" 4
add_alias "$WS_IP" 5

# Enable IP forwarding (should already be on, but ensure)
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] IP aliases configured. All six logical destinations now terminate on $SERVICES_IP"
echo ""
echo "    HTTP:      $HTTP_IP"
echo "    DNS:       $DNS_IP"
echo "    SMTP:      $SMTP_IP"
echo "    ICMP:      $ICMP_IP"
echo "    FTP:       $FTP_IP"
echo "    WebSocket: $WS_IP"