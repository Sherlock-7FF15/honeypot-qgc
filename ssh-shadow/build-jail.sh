#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
SESSION_ROOTFS="${2:?session_rootfs}"
LOGIN_USER="${3:?login_user}"
ROOTFS_TEMPLATE="${ROOTFS_TEMPLATE:-/opt/ssh-shadow/session-rootfs}"

rm -rf "$SESSION_ROOTFS"
mkdir -p "$SESSION_ROOTFS"
rsync -a --delete "$ROOTFS_TEMPLATE"/ "$SESSION_ROOTFS"/

mkdir -p \
  "$SESSION_ROOTFS/home/$LOGIN_USER/Documents/QGroundControl" \
  "$SESSION_ROOTFS/home/$LOGIN_USER/.config" \
  "$SESSION_ROOTFS/home/$LOGIN_USER/.cache" \
  "$SESSION_ROOTFS/root/.ssh" \
  "$SESSION_ROOTFS/etc/ssh" \
  "$SESSION_ROOTFS/dev/shm" \
  "$SESSION_ROOTFS/var/log/qgc" \
  "$SESSION_ROOTFS/var/log/mavproxy" \
  "$SESSION_ROOTFS/var/run"

chmod 1777 "$SESSION_ROOTFS/tmp" "$SESSION_ROOTFS/var/tmp" "$SESSION_ROOTFS/dev/shm"

SRC_HOME="$BASE_ROOT/home/gcs"
DST_HOME="$SESSION_ROOTFS/home/$LOGIN_USER"

if [[ -d "$SRC_HOME/Documents/QGroundControl" ]]; then
  rsync -a --delete --ignore-errors "$SRC_HOME/Documents/QGroundControl/" "$DST_HOME/Documents/QGroundControl/"
fi
if [[ -d "$SRC_HOME/.config" ]]; then
  rsync -a --delete --ignore-errors "$SRC_HOME/.config/" "$DST_HOME/.config/"
fi
if [[ -d "$SRC_HOME/.cache" ]]; then
  rsync -a --delete --ignore-errors \
    --exclude 'mesa_shader_cache/***' \
    --exclude 'gstreamer-1.0/***' \
    --exclude 'dconf/***' \
    --exclude '*.tmp' \
    --exclude '*.lock' \
    "$SRC_HOME/.cache/" "$DST_HOME/.cache/" || true
fi

if [[ -d "$BASE_ROOT/var/log/qgc" ]]; then
  rsync -a --delete --ignore-errors "$BASE_ROOT/var/log/qgc/" "$SESSION_ROOTFS/var/log/qgc/"
fi
if [[ -d "$BASE_ROOT/var/log/mavproxy" ]]; then
  rsync -a --delete --ignore-errors "$BASE_ROOT/var/log/mavproxy/" "$SESSION_ROOTFS/var/log/mavproxy/"
fi

cat > "$SESSION_ROOTFS/etc/passwd" <<PASSWD
root:x:0:0:root:/root:/bin/bash
${LOGIN_USER}:x:1000:1000:${LOGIN_USER}:/home/${LOGIN_USER}:/bin/bash
PASSWD

cat > "$SESSION_ROOTFS/etc/group" <<GROUP
root:x:0:
honeypot:x:1000:${LOGIN_USER}
${LOGIN_USER}:x:1000:
GROUP

cp -f /etc/resolv.conf "$SESSION_ROOTFS/etc/resolv.conf"
cp -f /etc/hosts "$SESSION_ROOTFS/etc/hosts"
cp -f /etc/nsswitch.conf "$SESSION_ROOTFS/etc/nsswitch.conf"

if [[ ! -f "$SESSION_ROOTFS/etc/ssh/sshd_config" ]]; then
  cat > "$SESSION_ROOTFS/etc/ssh/sshd_config" <<CFG
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
CFG
fi
if [[ ! -f "$SESSION_ROOTFS/etc/crontab" ]]; then
  cat > "$SESSION_ROOTFS/etc/crontab" <<CRON
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
CRON
fi
: > "$SESSION_ROOTFS/root/.ssh/authorized_keys"

chown -R root:root "$SESSION_ROOTFS/etc" "$SESSION_ROOTFS/root" >/dev/null 2>&1 || true
chmod -R go-w "$SESSION_ROOTFS/etc" "$SESSION_ROOTFS/root" >/dev/null 2>&1 || true
chown -R "$LOGIN_USER:honeypot" "$DST_HOME" >/dev/null 2>&1 || true
chmod -R u+rwX,go-rwx "$DST_HOME" >/dev/null 2>&1 || true
chmod -R go+rX "$SESSION_ROOTFS/var/log/qgc" "$SESSION_ROOTFS/var/log/mavproxy" >/dev/null 2>&1 || true
