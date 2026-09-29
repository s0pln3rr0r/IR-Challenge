#!/usr/bin/env python3
"""
Timeline verification for Six Ways Out.
Checks that the bash history contains expected patterns and produces a timeline.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
BASH_HIST = ROOT / "output/endpoint/bash_history.txt"
AUDIT_LOG = ROOT / "output/endpoint/audit.log"

if not BASH_HIST.exists():
    print("[-] Run collection/collect_endpoint.sh first")
    sys.exit(1)

with open(str(BASH_HIST), 'rb') as f:
    raw = f.read()
lines = raw.decode("utf-8", errors="replace").splitlines()
print("bash history lines: {}".format(len(lines)))

# Check for expected patterns
checks = {
    "production.env": "HTTP source file accessed",
    "employee_records.csv": "DNS source file accessed",
    "db.dump": "ICMP source file accessed",
    "q3_forecast.xlsx": "FTP source file accessed",
    "release-notes.txt": "WebSocket source file accessed",
    "exfil.example": "DNS exfiltration domain",
    "192.0.2.91": "ICMP destination",
    "203.0.113.88": "FTP destination",
    "203.0.113.25": "SMTP destination",
    "203.0.113.123": "WebSocket destination",
    "198.51.100.77": "HTTP destination",
    "203.0.113.53": "DNS destination",
    "base32 -w0": "Base32 encoding (DNS)",
    "base64 -d": "Base64 decoding (key recovery)",
    "base64 -w0": "Base64 encoding",
    "openssl enc": "OpenSSL encryption (WebSocket)",
    "gzip -c": "Gzip compression (FTP)",
    "xxd -p": "Hex encoding (ICMP)",
    "xor": "XOR operation",
    "curl -sS -X POST": "HTTP POST exfiltration",
    "dig +short": "DNS query exfiltration",
    "ftp -inv": "FTP upload",
    "ping -c 1": "ICMP ping",
}

print("\n=== Pattern Analysis ===")
all_found = True
for pattern, desc in checks.items():
    count = sum(1 for l in lines if pattern in l)
    status = "[+]" if count > 0 else "[!]"
    if count == 0:
        all_found = False
    print("  {} {}".format(status, desc.ljust(40)) + " ({}x)".format(count))

# Check for key hiding (base64 -d patterns)
key_patterns = {
    "bWFuZ28tNDc=": "HTTP key (mango-47) hidden in base64",
    "cmF2ZW4tMTk=": "ICMP key (raven-19) hidden in base64",
    "U3Rvcm0tV2luZC0yMDI2": "WebSocket password hidden in base64",
}

print("\n=== Key Discovery ===")
for pattern, desc in key_patterns.items():
    found = any(pattern in l for l in lines)
    status = "[+]" if found else "[!]"
    if not found:
        all_found = False
    print("  {} {}".format(status, desc))

# Check that plaintext keys do NOT appear directly
plaintext_danger = {
    "mango-47": "HTTP key in plaintext",
    "raven-19": "ICMP key in plaintext",
    "Storm-Wind-2026": "WebSocket password in plaintext",
}

print("\n=== Key Exposure Check (should NOT find plaintext) ===")
for pattern, desc in plaintext_danger.items():
    found = any(pattern in l for l in lines)
    status = "[!] EXPOSED" if found else "[✓] hidden"
    print("  {} {}".format(status, desc))

if all_found:
    print("\n[+] All timeline patterns verified successfully")
else:
    print("\n[!] Some patterns missing — review above")
    sys.exit(1)
