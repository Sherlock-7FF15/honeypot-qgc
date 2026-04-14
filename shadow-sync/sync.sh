#!/usr/bin/env bash
set -euo pipefail

SYNC_INTERVAL_SEC="${SYNC_INTERVAL_SEC:-3}"

SRC_QGC_DATA="${SRC_QGC_DATA:-/src/qgc-data}"
SRC_QGC_LOGS="${SRC_QGC_LOGS:-/src/logs-qgc}"
SRC_MAVPROXY_LOGS="${SRC_MAVPROXY_LOGS:-/src/logs-mavproxy}"

DST_BASE="${DST_BASE:-/shadow/base}"

RSYNC_COMMON=(rsync -a --delete --no-owner --no-group --chmod=Du+rwx,Dgo+rx,Fu+rw,Fgo+r)
RSYNC_CACHE=("${RSYNC_COMMON[@]}" --exclude 'mesa_shader_cache/***' --exclude 'gstreamer-1.0/***' --exclude 'dconf/***' --exclude '*.tmp' --exclude '*.lock')

sync_tree() {
  local src="$1"
  local dst="$2"
  shift 2
  mkdir -p "$dst"
  if [[ -d "$src" ]]; then
    if ! "$@" "$src/" "$dst/"; then
      echo "[shadow-sync] warning: partial sync failure for $src -> $dst" >&2
    fi
  fi
}

mkdir -p \
  "$DST_BASE/home/gcs/Documents/QGroundControl" \
  "$DST_BASE/home/gcs/.config" \
  "$DST_BASE/home/gcs/.cache" \
  "$DST_BASE/var/log/qgc" \
  "$DST_BASE/var/log/mavproxy"

while true; do
  sync_tree "$SRC_QGC_DATA/Documents/QGroundControl" "$DST_BASE/home/gcs/Documents/QGroundControl" "${RSYNC_COMMON[@]}"
  sync_tree "$SRC_QGC_DATA/.config" "$DST_BASE/home/gcs/.config" "${RSYNC_COMMON[@]}"
  sync_tree "$SRC_QGC_DATA/.cache" "$DST_BASE/home/gcs/.cache" "${RSYNC_CACHE[@]}"
  sync_tree "$SRC_QGC_LOGS" "$DST_BASE/var/log/qgc" "${RSYNC_COMMON[@]}"
  sync_tree "$SRC_MAVPROXY_LOGS" "$DST_BASE/var/log/mavproxy" "${RSYNC_COMMON[@]}"

  sleep "$SYNC_INTERVAL_SEC"
done
