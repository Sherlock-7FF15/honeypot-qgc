#!/usr/bin/env bash
set -euo pipefail

# Space-separated username:password weak credential pairs.
SSH_SHADOW_CREDENTIALS="${SSH_SHADOW_CREDENTIALS:-gcs:gcs123! admin:admin ubuntu:ubuntu pi:raspberry support:support operator:operator guest:guest test:test user:user deploy:deploy openclaw:openclaw}"
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

# Build immutable minimal rootfs template used for per-session chroot execution.
/opt/ssh-shadow/prepare-rootfs.sh /opt/ssh-shadow/session-rootfs

# Start root-managed launch daemon (avoids sudo/setuid dependency on nosuid filesystems).
mkdir -p /run/ssh-shadow /var/log/ssh-shadow
touch /var/log/ssh-shadow/root-session-daemon.log
/usr/bin/python3 /opt/ssh-shadow/root-session-daemon.py >> /var/log/ssh-shadow/root-session-daemon.log 2>&1 &
ROOT_DAEMON_PID=$!

for _ in $(seq 1 50); do
  [[ -S /run/ssh-shadow/root-launch.sock ]] && break
  sleep 0.1
done
if [[ ! -S /run/ssh-shadow/root-launch.sock ]]; then
  echo "[ssh-shadow] fatal: root-session-daemon socket did not appear" >&2
  exit 43
fi

# Allow honeypot users to invoke root-owned session launcher only.
cat > /etc/sudoers.d/ssh-shadow-session-launch <<'SUDOERS'
Defaults:%honeypot !requiretty
%honeypot ALL=(root) NOPASSWD: /opt/ssh-shadow/root-session-launch.sh
SUDOERS
chmod 0440 /etc/sudoers.d/ssh-shadow-session-launch

# Fail-fast if root chroot path is unusable on this host.
/opt/ssh-shadow/root-session-launch.sh --selftest /opt/ssh-shadow/session-rootfs
if ! su -s /bin/bash -c "/usr/bin/python3 /opt/ssh-shadow/root-session-client.py selftest /opt/ssh-shadow/session-rootfs" gcs >/dev/null 2>&1; then
  echo "[ssh-shadow] fatal: honeypot user cannot reach required root-managed chroot launcher" >&2
  exit 42
fi

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
