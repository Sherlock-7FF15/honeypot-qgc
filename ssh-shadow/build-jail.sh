#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
WORKSPACE_ROOT="${2:?workspace_root}"
LOGIN_USER="${3:?login_user}"
ROOTFS_TEMPLATE="${ROOTFS_TEMPLATE:-/opt/ssh-shadow/session-rootfs}"

rm -rf "$WORKSPACE_ROOT"
mkdir -p "$WORKSPACE_ROOT"
rsync -a --delete "$ROOTFS_TEMPLATE"/ "$WORKSPACE_ROOT"/

mkdir -p \
  "$WORKSPACE_ROOT/home/$LOGIN_USER/Documents/QGroundControl" \
  "$WORKSPACE_ROOT/home/$LOGIN_USER/.config" \
  "$WORKSPACE_ROOT/home/$LOGIN_USER/.cache" \
  "$WORKSPACE_ROOT/root/.ssh" \
  "$WORKSPACE_ROOT/etc/ssh" \
  "$WORKSPACE_ROOT/dev/shm" \
  "$WORKSPACE_ROOT/var/log/qgc" \
  "$WORKSPACE_ROOT/var/log/mavproxy" \
  "$WORKSPACE_ROOT/var/run"

chmod 1777 "$WORKSPACE_ROOT/tmp" "$WORKSPACE_ROOT/var/tmp" "$WORKSPACE_ROOT/dev/shm"

SRC_HOME="$BASE_ROOT/home/gcs"
DST_HOME="$WORKSPACE_ROOT/home/$LOGIN_USER"

# Keep login-time build light: copy only what attacker workflow needs writable.
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
  rsync -a --delete --ignore-errors "$BASE_ROOT/var/log/qgc/" "$WORKSPACE_ROOT/var/log/qgc/"
fi
if [[ -d "$BASE_ROOT/var/log/mavproxy" ]]; then
  rsync -a --delete --ignore-errors "$BASE_ROOT/var/log/mavproxy/" "$WORKSPACE_ROOT/var/log/mavproxy/"
fi

# session-local fake root filesystem surfaces
if [[ ! -f "$WORKSPACE_ROOT/etc/ssh/sshd_config" ]]; then
  cat > "$WORKSPACE_ROOT/etc/ssh/sshd_config" <<CFG
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
CFG
fi
if [[ ! -f "$WORKSPACE_ROOT/etc/crontab" ]]; then
  cat > "$WORKSPACE_ROOT/etc/crontab" <<CRON
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
CRON
fi
: > "$WORKSPACE_ROOT/root/.ssh/authorized_keys"

chown -R "$LOGIN_USER:honeypot" "$DST_HOME" "$WORKSPACE_ROOT/root" "$WORKSPACE_ROOT/etc" "$WORKSPACE_ROOT/tmp" "$WORKSPACE_ROOT/var/tmp" "$WORKSPACE_ROOT/dev/shm" "$WORKSPACE_ROOT/var/run"
chmod -R u+rwX,go-rwx "$DST_HOME" "$WORKSPACE_ROOT/root" "$WORKSPACE_ROOT/etc" "$WORKSPACE_ROOT/var/run"
chmod -R go+rX "$WORKSPACE_ROOT/var/log/qgc" "$WORKSPACE_ROOT/var/log/mavproxy" || true
