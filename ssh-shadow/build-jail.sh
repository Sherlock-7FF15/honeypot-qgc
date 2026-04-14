#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
WORKSPACE_ROOT="${2:?workspace_root}"
LOGIN_USER="${3:?login_user}"

rm -rf "$WORKSPACE_ROOT"
mkdir -p "$WORKSPACE_ROOT"

# Session-local copy of mirrored state.
rsync -a --delete "$BASE_ROOT/" "$WORKSPACE_ROOT/"

# Ensure expected structure exists.
mkdir -p "$WORKSPACE_ROOT/var/log/qgc" "$WORKSPACE_ROOT/var/log/mavproxy"

for u in gcs admin ubuntu pi support operator guest test; do
  mkdir -p "$WORKSPACE_ROOT/home/$u"
  if [[ "$u" != "gcs" ]]; then
    rsync -a --delete "$WORKSPACE_ROOT/home/gcs/" "$WORKSPACE_ROOT/home/$u/" || true
  fi
  mkdir -p "$WORKSPACE_ROOT/home/$u/Documents/QGroundControl" "$WORKSPACE_ROOT/home/$u/.config" "$WORKSPACE_ROOT/home/$u/.cache"
done

chown -R "$LOGIN_USER:honeypot" "$WORKSPACE_ROOT/home/$LOGIN_USER"
chmod -R u+rwX,go-rwx "$WORKSPACE_ROOT/home/$LOGIN_USER"
chmod -R go+rX "$WORKSPACE_ROOT/var/log/qgc" "$WORKSPACE_ROOT/var/log/mavproxy" || true
