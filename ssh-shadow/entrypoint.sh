#!/usr/bin/env bash
set -euo pipefail

SSH_SHADOW_PASSWORD="${SSH_SHADOW_PASSWORD:-gcs123!}"
SSH_SHADOW_CREDENTIALS="${SSH_SHADOW_CREDENTIALS:-gcs:${SSH_SHADOW_PASSWORD},admin:admin,ubuntu:ubuntu,pi:raspberry,support:support,operator:operator,guest:guest,test:test}"

mkdir -p /run/sshd /shadow/base /shadow/sessions /shadow/state /logs/ssh-shadow/sessions /var/log/ssh-shadow
groupadd -f honeypot || true

create_or_update_user() {
  local user="$1"
  local pass="$2"

  if ! id "$user" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -N -g honeypot "$user"
  else
    usermod -g honeypot "$user" || true
  fi

  echo "${user}:${pass}" | chpasswd
}

IFS=',' read -ra PAIRS <<< "$SSH_SHADOW_CREDENTIALS"
for pair in "${PAIRS[@]}"; do
  user="${pair%%:*}"
  pass="${pair#*:}"
  create_or_update_user "$user" "$pass"
done

mkdir -p /home/gcs /var/log

# Make shared bind mounts writable by all honeypot users.
chown -R root:honeypot /shadow/sessions /logs/ssh-shadow /shadow/state /home/gcs || true
chmod -R 2775 /shadow/sessions /logs/ssh-shadow /shadow/state /home/gcs || true

rm -rf /home/gcs/Documents /home/gcs/.config /home/gcs/.cache
rm -rf /var/log/qgc /var/log/mavproxy

ln -sfn /shadow/state/active-workspace/home/gcs/Documents /home/gcs/Documents
ln -sfn /shadow/state/active-workspace/home/gcs/.config /home/gcs/.config
ln -sfn /shadow/state/active-workspace/home/gcs/.cache /home/gcs/.cache
ln -sfn /shadow/state/active-workspace/var/log/qgc /var/log/qgc
ln -sfn /shadow/state/active-workspace/var/log/mavproxy /var/log/mavproxy

if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
  ssh-keygen -A
fi

echo "[ssh-shadow] sshd listening on :2222 (host mapped by compose)"
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
