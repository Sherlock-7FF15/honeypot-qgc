#!/usr/bin/env bash
set -euo pipefail

SYNC_INTERVAL_SEC="${SYNC_INTERVAL_SEC:-3}"

SRC_QGC_DATA="${SRC_QGC_DATA:-/src/qgc-data}"
SRC_QGC_LOGS="${SRC_QGC_LOGS:-/src/logs-qgc}"
SRC_MAVPROXY_LOGS="${SRC_MAVPROXY_LOGS:-/src/logs-mavproxy}"

DST_BASE="${DST_BASE:-/shadow/base}"

mkdir -p \
  "$DST_BASE/home/gcs/Documents/QGroundControl" \
  "$DST_BASE/home/gcs/.config/QGroundControl" \
  "$DST_BASE/home/gcs/.cache/QGroundControl" \
  "$DST_BASE/var/log/qgc" \
  "$DST_BASE/var/log/mavproxy"

while true; do
  if [[ -d "$SRC_QGC_DATA" ]]; then
    rsync -a --delete "$SRC_QGC_DATA/" "$DST_BASE/home/gcs/Documents/QGroundControl/"
  fi

  if [[ -d "$SRC_QGC_LOGS" ]]; then
    rsync -a --delete "$SRC_QGC_LOGS/" "$DST_BASE/var/log/qgc/"
  fi

  if [[ -d "$SRC_MAVPROXY_LOGS" ]]; then
    rsync -a --delete "$SRC_MAVPROXY_LOGS/" "$DST_BASE/var/log/mavproxy/"
  fi

  sleep "$SYNC_INTERVAL_SEC"
done
