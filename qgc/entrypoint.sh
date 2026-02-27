#!/usr/bin/env bash
set -euo pipefail

exec >> /logs/qgc.stdout 2>&1

export HOME=/data
export XDG_CONFIG_HOME=/data/.config
export XDG_CACHE_HOME=/data/.cache
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

echo "=== ENTRYPOINT START ==="
date
id
echo "HOME=$HOME"
echo "XDG_CONFIG_HOME=$XDG_CONFIG_HOME"
echo "XDG_CACHE_HOME=$XDG_CACHE_HOME"

while true; do
  echo "=== LAUNCH QGC ==="
  date
  xvfb-run -a -s "-screen 0 1280x720x24" /opt/qgc/usr/bin/QGroundControl
  rc=$?
  echo "=== QGC EXITED rc=$rc ==="
  date
  sleep 2
done
