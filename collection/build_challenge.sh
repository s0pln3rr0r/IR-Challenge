#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

P="$ROOT/output/player"
O="$ROOT/output/organizer"
rm -rf "$P" "$O"
mkdir -p "$P" "$O/recovered_payloads"

# ---- Player package ----
cat >"$P/CHALLENGE.md" <<'EOF'
# Six Ways Out

A production Linux endpoint (`prod-web-03`) was compromised and the attacker obtained root access.

You have endpoint evidence and one packet capture. No files from the compromised host are provided.

Determine:
1. Sensitive files accessed/staged.
2. The six exfiltration mechanisms.
3. Encoding/encryption used by each.
4. Reconstruct the recovered fragments.
5. Submit the final `FLAG{...}`.

All timestamps are UTC.
EOF

cp -a "$ROOT/output/endpoint" "$P/endpoint"
cp -a "$ROOT/output/network" "$P/network"

# ---- Organizer package ----
cat >"$O/ANSWERS.md" <<EOF
# Six Ways Out — Answers

## Channels

| # | Channel | Source | Transformation | Key | Destination | Recovered |
|---|---------|--------|---------------|-----|-------------|-----------|
| 1 | HTTP | /opt/app/config/production.env | XOR + Base64 | mango-47 | $HTTP_IP | Q7k2mLp |
| 2 | DNS | /opt/hr/employee_records.csv | Base32 + 30-char chunks | — | $DNS_IP | k91Xv2Qa |
| 3 | SMTP | QR PNGs (3 pieces) | QR codes | — | $SMTP_IP | HncfuEY92kL |
| 4 | ICMP | /var/backups/db.dump | XOR + hex | raven-19 | $ICMP_IP | xP83LmQa |
| 5 | FTP | /opt/finance/q3_forecast.xlsx | gzip + Base64 | — | $FTP_IP | 7vQm91Xe |
| 6 | WebSocket | /srv/app/releases/release-notes.txt | AES-256-CBC + PBKDF2 + Base64 | Storm-Wind-2026 | $WS_IP | Lm92Qx7P |

## Final Flag

\`\`\`
FLAG{Q7k2mLpk91Xv2QaHncfuEY92kLxP83LmQa7vQm91XeLm92Qx7P}
\`\`\`

## Timeline

See timeline.csv for the full event timeline.
EOF

# Copy recovered payloads from runtime
if [[ -d "$ROOT/runtime/received" ]]; then
    cp -a "$ROOT/runtime/received" "$O/recovered_payloads/"
fi
if [[ -d "$ROOT/runtime/qr" ]]; then
    cp -a "$ROOT/runtime/qr" "$O/recovered_payloads/"
fi

cp -a "$ROOT/output/endpoint" "$O/endpoint"
cp -a "$ROOT/output/network" "$O/network"

# Create ZIPs
cd "$ROOT/output"
zip -qr six_ways_out_player.zip player
zip -qr six_ways_out_full.zip organizer
echo "[+] Player package: $ROOT/output/six_ways_out_player.zip"
echo "[+] Organizer package: $ROOT/output/six_ways_out_full.zip"
