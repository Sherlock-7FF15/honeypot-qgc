#!/usr/bin/env bash
set -euo pipefail

mkdir -p /logs/watcher
mkdir -p /uploads/fs

echo "[watcher] starting"
echo "[watcher] WATCH_DIRS=${WATCH_DIRS:-/qgc-data/Documents/QGroundControl:/qgc-data/tmp}"
python /app/watcher.py
