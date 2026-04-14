#!/usr/bin/env bash
set -euo pipefail

SSH_SHADOW_PASSWORD="${SSH_SHADOW_PASSWORD:-gcs123!}"
SSH_SHADOW_USERS="${SSH_SHADOW_USERS:-gcs admin ubuntu pi support operator guest test}"

if ! getent group honeypot >/dev/null; then
  groupadd --system honeypot
fi

for u in ${SSH_SHADOW_USERS}; do
  if ! id -u "$u" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -g honeypot "$u"
  fi
  usermod -a -G honeypot "$u" >/dev/null 2>&1 || true
  echo "${u}:${SSH_SHADOW_PASSWORD}" | chpasswd
  mkdir -p "/home/${u}/Documents/QGroundControl" "/home/${u}/.config" "/home/${u}/.cache"
  chown -R "${u}:honeypot" "/home/${u}"
done

mkdir -p /run/sshd /shadow/base /shadow/sessions /shadow/state /shadow/jails /logs/ssh-shadow/sessions /var/log/ssh-shadow
chown -R root:honeypot /shadow/sessions /logs/ssh-shadow /shadow/state /shadow/jails || true
chmod -R g+rwX /shadow/sessions /logs/ssh-shadow /shadow/state /shadow/jails || true

if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -A
fi

echo "[ssh-shadow] sshd listening on :2222 (host mapped by compose)"
exec /bin/bash -lc '/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config 2>&1 | /usr/bin/python3 /opt/ssh-shadow/preauth_logger.py'
