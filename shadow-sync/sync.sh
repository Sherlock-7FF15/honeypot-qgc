#!/usr/bin/env bash
set -euo pipefail

SYNC_INTERVAL_SEC="${SYNC_INTERVAL_SEC:-3}"

SRC_QGC_DATA="${SRC_QGC_DATA:-/src/qgc-data}"
SRC_QGC_LOGS="${SRC_QGC_LOGS:-/src/logs-qgc}"
SRC_MAVPROXY_LOGS="${SRC_MAVPROXY_LOGS:-/src/logs-mavproxy}"

DST_BASE="${DST_BASE:-/shadow/base}"

mkdir -p \
  "$DST_BASE/home/gcs/Documents/QGroundControl" \
  "$DST_BASE/home/gcs/.config" \
  "$DST_BASE/home/gcs/.cache" \
  "$DST_BASE/var/log/qgc" \
  "$DST_BASE/var/log/mavproxy"

sync_tree() {
  local src="$1"
  local dst="$2"
  shift 2

  if [[ -d "$src" ]]; then
    rsync -a --delete \
      --chmod=Du=rwx,Dg=rx,Do=rx,Fu=rw,Fg=r,Fo=r \
      "$@" \
      "$src/" "$dst/"
  else
    mkdir -p "$dst"
  fi
}

while true; do
  sync_tree \
    "$SRC_QGC_DATA/Documents/QGroundControl" \
    "$DST_BASE/home/gcs/Documents/QGroundControl"

  sync_tree \
    "$SRC_QGC_DATA/.config" \
    "$DST_BASE/home/gcs/.config"

  sync_tree \
    "$SRC_QGC_DATA/.cache" \
    "$DST_BASE/home/gcs/.cache" \
    --exclude 'mesa_shader_cache/' \
    --exclude 'gstreamer-1.0/' \
    --exclude '*.lock' \
    --exclude '*.tmp'

  sync_tree \
    "$SRC_QGC_LOGS" \
    "$DST_BASE/var/log/qgc"

  sync_tree \
    "$SRC_MAVPROXY_LOGS" \
    "$DST_BASE/var/log/mavproxy"

  chmod -R a+rX "$DST_BASE" || true
  sleep "$SYNC_INTERVAL_SEC"
done
