#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/output/network/zeek"
cd "$ROOT/output/network/zeek"

if command -v zeek &>/dev/null; then
    zeek -r ../exfiltration.pcap LogAscii::use_json=T
    echo "[+] Zeek processing complete"
elif command -v tshark &>/dev/null; then
    echo "[*] zeek not found, using tshark instead..."
    # Generate JSON output similar to zeek using tshark
    tshark -r ../exfiltration.pcap -T json > exfiltration_tshark.json 2>/dev/null || true
    # Extract DNS queries
    tshark -r ../exfiltration.pcap -Y "dns" -T fields -e frame.time -e dns.qry.name -e dns.qry.type 2>/dev/null > dns_queries.log || true
    # Extract HTTP requests
    tshark -r ../exfiltration.pcap -Y "http" -T fields -e frame.time -e http.request.method -e http.request.uri -e http.host 2>/dev/null > http_requests.log || true
    # Extract TCP conversations
    tshark -r ../exfiltration.pcap -Y "tcp" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.payload 2>/dev/null > tcp_streams.log || true
    # Extract ICMP
    tshark -r ../exfiltration.pcap -Y "icmp" -T fields -e frame.time -e ip.src -e ip.dst -e icmp.type -e icmp.payload 2>/dev/null > icmp_echo.log || true
    # Extract FTP data
    tshark -r ../exfiltration.pcap -Y "ftp" -T fields -e frame.time -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null > ftp_commands.log || true
    # Extract WebSocket (TCP payload on port 8080)
    tshark -r ../exfiltration.pcap -Y "tcp.port==8080" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.payload 2>/dev/null > websocket_data.log || true
    echo "[+] tshark processing complete (zeek not available)"
else
    echo "[-] Neither zeek nor tshark found. Install with: sudo apt-get install tshark"
    echo "[-] Skipping network protocol analysis"
fi
