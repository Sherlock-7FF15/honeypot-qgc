#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
WORKSPACE_ROOT="${2:?workspace_root}"
LOGIN_USER="${3:?login_user}"

rm -rf "$WORKSPACE_ROOT"
mkdir -p "$WORKSPACE_ROOT/home/$LOGIN_USER/Documents/QGroundControl" "$WORKSPACE_ROOT/home/$LOGIN_USER/.config" "$WORKSPACE_ROOT/home/$LOGIN_USER/.cache" "$WORKSPACE_ROOT/var/log/qgc" "$WORKSPACE_ROOT/var/log/mavproxy"

SRC_HOME="$BASE_ROOT/home/gcs"
DST_HOME="$WORKSPACE_ROOT/home/$LOGIN_USER"

# Keep login-time build light: copy only what the attacker workflow needs.
if [[ -d "$SRC_HOME/Documents/QGroundControl" ]]; then
  rsync -a --delete --ignore-errors "$SRC_HOME/Documents/QGroundControl/" "$DST_HOME/Documents/QGroundControl/"
fi

if [[ -d "$SRC_HOME/.config" ]]; then
  rsync -a --delete --ignore-errors "$SRC_HOME/.config/" "$DST_HOME/.config/"
fi

# Cache is noisy and can contain unreadable runtime artifacts; keep only sanitized subset.
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

chown -R "$LOGIN_USER:honeypot" "$DST_HOME"
chmod -R u+rwX,go-rwx "$DST_HOME"
chmod -R go+rX "$WORKSPACE_ROOT/var/log/qgc" "$WORKSPACE_ROOT/var/log/mavproxy" || true
