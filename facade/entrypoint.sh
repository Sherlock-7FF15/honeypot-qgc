#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${LOG_ROOT}/sessions"

echo "[facade] starting"
echo "[facade] PUBLIC_BIND=${PUBLIC_BIND} PUBLIC_PORT=${PUBLIC_PORT}"
echo "[facade] QGC_HOST=${QGC_HOST} QGC_PORT=${QGC_PORT}"
echo "[facade] LOG_ROOT=${LOG_ROOT}"
python /app/app.py
