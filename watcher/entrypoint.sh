#!/usr/bin/env bash
set -euo pipefail

mkdir -p /logs/watcher
mkdir -p /uploads/fs

echo "[watcher] starting"
echo "[watcher] WATCH_DIRS=${WATCH_DIRS:-}"
python /app/watcher.py
