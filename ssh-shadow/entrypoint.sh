#!/usr/bin/env bash
set -euo pipefail

SSH_SHADOW_PASSWORD="${SSH_SHADOW_PASSWORD:-gcs123!}"

echo "gcs:${SSH_SHADOW_PASSWORD}" | chpasswd

mkdir -p /run/sshd /shadow/base /shadow/sessions /shadow/state /logs/ssh-shadow/sessions /var/log/ssh-shadow
mkdir -p /shadow/jails
chown -R gcs:gcs /shadow/sessions /logs/ssh-shadow /shadow/state /shadow/jails || true

mkdir -p /shadow/state/active-workspace/var/log/qgc /shadow/state/active-workspace/var/log/mavproxy
rm -rf /var/log/qgc /var/log/mavproxy
ln -s /shadow/state/active-workspace/var/log/qgc /var/log/qgc
ln -s /shadow/state/active-workspace/var/log/mavproxy /var/log/mavproxy

if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -A
fi

echo "[ssh-shadow] sshd listening on :2222 (host mapped by compose)"
exec /bin/bash -lc '/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config 2>&1 | /usr/bin/python3 /opt/ssh-shadow/preauth_logger.py'
