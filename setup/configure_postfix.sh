#!/usr/bin/env bash
set -euo pipefail
# Configure Postfix to accept SMTP traffic from the victim for exfiltration
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

# Stop and disable any existing Postfix
systemctl stop postfix 2>/dev/null || true

# Use a minimal Postfix config that listens on all interfaces
postconf -e "inet_interfaces = all"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, external.example"
postconf -e "myorigin = \$myhostname"
postconf -e "mynetworks = 0.0.0.0/0"
postconf -e "smtpd_banner = \$myhostname ESMTP"
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_helo_required = no"
postconf -e "smtpd_delay_reject = yes"
postconf -e "home_mailbox = Maildir/"

# Create mail directories
for user in root "$FTP_USER"; do
    maildirmake.dovecot "/home/$user/Maildir" 2>/dev/null || mkdir -p "/home/$user/Maildir"
done

systemctl restart postfix || service postfix restart || true
echo "[+] Postfix configured on $SERVICES_IP"