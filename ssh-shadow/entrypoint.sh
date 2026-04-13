#!/usr/bin/env bash
set -euo pipefail

SSH_SHADOW_PASSWORD="${SSH_SHADOW_PASSWORD:-gcs123!}"

echo "gcs:${SSH_SHADOW_PASSWORD}" | chpasswd

mkdir -p /run/sshd /shadow/base /shadow/sessions /shadow/state /logs/ssh-shadow/sessions /var/log/ssh-shadow
chown -R gcs:gcs /shadow/sessions /logs/ssh-shadow /shadow/state || true

if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -A
fi

echo "[ssh-shadow] sshd listening on :2222 (host mapped by compose)"
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
