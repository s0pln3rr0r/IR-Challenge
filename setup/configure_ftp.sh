#!/usr/bin/env bash
set -euo pipefail
# Configure vsftpd for the isolated lab FTP exfiltration server
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/config.env"

# Create FTP user with upload-only access
if ! id "$FTP_USER" &>/dev/null; then
    useradd -m -s /usr/sbin/nologin "$FTP_USER"
fi
# Force password reset — use chpasswd with single-quoted string to avoid shell expansion
echo "$FTP_USER:DailyBackup!2026" | chpasswd 2>/dev/null || true
# Also try via passwd if chpasswd had issues
printf '%s\n%s\n' 'DailyBackup!2026' 'DailyBackup!2026' | passwd "$FTP_USER" 2>/dev/null || true

# Ensure /usr/sbin/nologin is in /etc/shells for vsftpd
if ! grep -q /usr/sbin/nologin /etc/shells 2>/dev/null; then
    echo /usr/sbin/nologin >>/etc/shells
fi

# Create FTP root and set permissions
FTP_ROOT="/srv/ftp/exfil"
mkdir -p "$FTP_ROOT"
chown "$FTP_USER:$FTP_USER" "$FTP_ROOT"
chmod 755 "$FTP_ROOT"

# Configure vsftpd
cat >/etc/vsftpd.conf <<FTPCONF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=NO
xferlog_enable=YES
connect_from_port_20=YES
seccomp_sandbox=NO
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30100
local_root=$FTP_ROOT
chroot_local_user=YES
allow_writeable_chroot=YES
FTPCONF

# Restart vsftpd
systemctl restart vsftpd || service vsftpd restart || true
echo "[+] FTP server configured: $FTP_USER@$SERVICES_IP -> $FTP_ROOT"