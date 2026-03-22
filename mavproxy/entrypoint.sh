#!/usr/bin/env sh
set -eu

mkdir -p /logs/mavproxy

MAVPROXY_STDOUT_LOG="/logs/mavproxy/mavproxy.stdout.log"
MAVPROXY_SIM_UDP_PORT="${MAVPROXY_SIM_UDP_PORT:-14570}"
MAVPROXY_QGC_OUT="${MAVPROXY_QGC_OUT:-udp:qgc:14550}"
touch "$MAVPROXY_STDOUT_LOG"

# keep state/logs on host-mounted ./logs/mavproxy
exec python /app/run_logged.py "$MAVPROXY_STDOUT_LOG" \
  mavproxy.py \
  --non-interactive \
  --master=udpin:0.0.0.0:14550 \
  --master=udpin:0.0.0.0:${MAVPROXY_SIM_UDP_PORT} \
  --master=tcpin:0.0.0.0:14550 \
  --master=tcpin:0.0.0.0:5760 \
  --out="${MAVPROXY_QGC_OUT}" \
  --state-basedir=/logs/mavproxy \
  --aircraft=honeypot \
  --default-modules="link"
