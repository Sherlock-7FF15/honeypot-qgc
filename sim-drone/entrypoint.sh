#!/usr/bin/env bash
set -euo pipefail

LOG_DIR=/logs
SIM_LOG="$LOG_DIR/sim-drone.log"
PX4_AUTOPILOT_DIR="${PX4_AUTOPILOT_DIR:-/opt/PX4-Autopilot}"
PX4_SIM_TARGET="${PX4_SIM_TARGET:-gz_x500}"
PX4_GIT_REF="${PX4_GIT_REF:-v1.16.0}"
SIM_GCS_HOST="${SIM_GCS_HOST:-mavproxy}"
SIM_GCS_PORT="${SIM_GCS_PORT:-14570}"
HEADLESS="${HEADLESS:-1}"
PX4_HOME_LAT="${PX4_HOME_LAT:-47.397742}"
PX4_HOME_LON="${PX4_HOME_LON:-8.545594}"
PX4_HOME_ALT="${PX4_HOME_ALT:-488.0}"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$SIM_LOG") 2>&1

cleanup() {
  set +e
  [[ -n "${FORWARDER_PID:-}" ]] && kill "$FORWARDER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cd "$PX4_AUTOPILOT_DIR"

echo "=== sim-drone entrypoint start ==="
date
echo "PX4_SIM_TARGET=$PX4_SIM_TARGET PX4_GIT_REF=$PX4_GIT_REF"
echo "SIM_GCS_HOST=$SIM_GCS_HOST SIM_GCS_PORT=$SIM_GCS_PORT HEADLESS=$HEADLESS"
echo "=== preflight ==="
git rev-parse --is-inside-work-tree
command -v python3
command -v gz
make --version

until getent hosts "$SIM_GCS_HOST" >/dev/null 2>&1; do
  echo "waiting for $SIM_GCS_HOST DNS..."
  sleep 1
done

echo "=== starting UDP forwarder 127.0.0.1:14550 -> ${SIM_GCS_HOST}:${SIM_GCS_PORT} ==="
python3 -u - <<'PY' &
import os
import socket

target = (os.environ["SIM_GCS_HOST"], int(os.environ["SIM_GCS_PORT"]))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 14550))

while True:
    payload, _ = sock.recvfrom(65535)
    if payload:
        sock.sendto(payload, target)
PY
FORWARDER_PID=$!

export HEADLESS
export PX4_HOME_LAT
export PX4_HOME_LON
export PX4_HOME_ALT

echo "=== launching PX4 SITL + Gazebo ==="
exec make px4_sitl "${PX4_SIM_TARGET}"
