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

# Create the recipient user and mail directory
if ! id "$SMTP_RECIPIENT" &>/dev/null; then
    useradd -m -s /usr/sbin/nologin "finance-archive" 2>/dev/null || true
fi
maildirmake.dovecot "/home/finance-archive/Maildir" 2>/dev/null || mkdir -p "/home/finance-archive/Maildir"

# Add canonical mapping so the external address is delivered locally
postconf -e "canonical_maps = hash:/etc/postfix/canonical"
echo "finance.archive@external.example finance-archive" >/etc/postfix/canonical
postmap /etc/postfix/canonical

# Also create mail directories for other users
for user in root "$FTP_USER"; do
    maildirmake.dovecot "/home/$user/Maildir" 2>/dev/null || mkdir -p "/home/$user/Maildir"
done

systemctl restart postfix || service postfix restart || true
echo "[+] Postfix configured on $SERVICES_IP"