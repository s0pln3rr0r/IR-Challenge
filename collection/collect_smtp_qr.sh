#!/usr/bin/env bash
set -euo pipefail
# Extract QR code PNG attachments from Postfix mail queue
# The emails were sent to finance.archive@external.example which is
# mapped to local user 'finance-archive' via canonical mapping.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QR_DIR="$ROOT/runtime/qr"
mkdir -p "$QR_DIR"

# Check various possible mail storage locations
MAIL_DIRS=(
    "/home/finance-archive/Maildir/new"
    "/home/finance-archive/Maildir/cur"
    "/var/mail/finance-archive"
    "/var/spool/mail/finance-archive"
    "/var/mail/finance-archive/Maildir/new"
    "/var/mail/finance-archive/Maildir/cur"
)

found=false
for dir in "${MAIL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "[*] Checking $dir..."
        # Look for PNG attachments in mail files
        for mail_file in "$dir"/*; do
            [ -f "$mail_file" ] || continue
            # Extract PNG data from the email using awk/csplit
            # PNGs are base64 encoded in the email body
            count=0
            while IFS= read -r line; do
                if echo "$line" | grep -q "^Content-Type: image/png"; then
                    # Next lines after blank line are base64 data until boundary
                    in_png=1
                    continue
                fi
                if [ "${in_png:-0}" = "1" ]; then
                    if echo "$line" | grep -q "^--==============="; then
                        in_png=0
                    elif [ -n "$line" ] && ! echo "$line" | grep -q "^Content-"; then
                        # This is base64 data - decode it
                        count=$((count + 1))
                        echo "$line" >> "/tmp/qr_b64_$$_${count}"
                    fi
                fi
            done < "$mail_file"
            
            # Decode any found PNGs
            for b64_file in /tmp/qr_b64_$$_*; do
                [ -f "$b64_file" ] || continue
                base64 -d "$b64_file" 2>/dev/null > "$QR_DIR/IMG_18${count}.png" && {
                    echo "[+] Extracted QR PNG to $QR_DIR/IMG_18${count}.png"
                    found=true
                    count=$((count + 1))
                } || true
                rm -f "$b64_file"
            done
        done
    fi
done

# Alternative: use Postfix's mailq and save individual emails
if ! $found; then
    echo "[*] Trying Postfix maildrop extraction..."
    # Postfix stores queue files in /var/spool/postfix/
    for qdir in incoming active deferred; do
        for qfile in /var/spool/postfix/$qdir/*; do
            [ -f "$qfile" ] || continue
            if grep -q "Content-Type: image/png" "$qfile" 2>/dev/null; then
                echo "[*] Found email with PNG in $qdir queue"
                # Extract PNGs using Python
                python3 -c "
import base64, os, re, sys
data = open('$qfile', 'rb').read()
# Find all base64-encoded PNGs
text = data.decode('utf-8', errors='replace')
pngs = re.findall(r'Content-Type: image/png.*?filename=(IMG_\d+\.png).*?\n\n(.*?)\n--===============', text, re.DOTALL)
for fname, b64_data in pngs:
    b64_data = b64_data.replace('\n', '').replace('\r', '')
    try:
        png_bytes = base64.b64decode(b64_data)
        outpath = os.path.join('$QR_DIR', fname)
        open(outpath, 'wb').write(png_bytes)
        print('[+] Extracted: ' + outpath)
    except Exception as e:
        print('[-] Failed: ' + str(e))
" 2>/dev/null || true
            fi
        done
    done
fi

echo "[+] SMTP QR extraction complete"