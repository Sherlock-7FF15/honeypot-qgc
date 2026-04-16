#!/usr/bin/env bash
set -euo pipefail

# Space-separated username:password weak credential pairs.
SSH_SHADOW_CREDENTIALS="${SSH_SHADOW_CREDENTIALS:-gcs:gcs123! admin:admin ubuntu:ubuntu pi:raspberry support:support operator:operator guest:guest test:test user:user deploy:deploy postgres:postgres debian:debian oracle:oracle openclaw:openclaw odoo:odoo mysql:mysql web:web}"
HONEYPOT_HOSTNAME="${HONEYPOT_HOSTNAME:-gcs-shadow}"

if ! getent group honeypot >/dev/null; then
  groupadd --system honeypot
fi

for pair in ${SSH_SHADOW_CREDENTIALS}; do
  u="${pair%%:*}"
  p="${pair#*:}"
  [[ -z "$u" || -z "$p" ]] && continue

  if ! id -u "$u" >/dev/null 2>&1; then
    # -N avoids per-user group creation (prevents operator group collision issues)
    useradd -m -s /bin/bash -g honeypot -N "$u"
  fi
  usermod -a -G honeypot "$u" >/dev/null 2>&1 || true
  echo "${u}:${p}" | chpasswd
  mkdir -p "/home/${u}/Documents/QGroundControl" "/home/${u}/.config" "/home/${u}/.cache"
  chown -R "${u}:honeypot" "/home/${u}"
done

mkdir -p /run/sshd /shadow/base /shadow/sessions /shadow/state /shadow/jails /logs/ssh-shadow/sessions /var/log/ssh-shadow
chown -R root:honeypot /shadow/sessions /logs/ssh-shadow /shadow/state /shadow/jails || true
chmod -R g+rwX /shadow/sessions /logs/ssh-shadow /shadow/state /shadow/jails || true

# Keep kernel nodename, /etc/hostname and shell-visible identity aligned.
echo "$HONEYPOT_HOSTNAME" > /etc/hostname
hostname "$HONEYPOT_HOSTNAME" >/dev/null 2>&1 || true

# Keep attacker-visible workstation log paths stable and readable.
mkdir -p /shadow/base/var/log/qgc /shadow/base/var/log/mavproxy
rm -rf /var/log/qgc /var/log/mavproxy
ln -s /shadow/base/var/log/qgc /var/log/qgc
ln -s /shadow/base/var/log/mavproxy /var/log/mavproxy

if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -A
fi

echo "[ssh-shadow] sshd listening on :2222 (host mapped by compose)"
exec /bin/bash -lc '/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config 2>&1 | /usr/bin/python3 /opt/ssh-shadow/preauth_logger.py'
