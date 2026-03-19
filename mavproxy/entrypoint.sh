#!/usr/bin/env sh
set -eu

mkdir -p /logs/mavproxy

MAVPROXY_STDOUT_LOG="/logs/mavproxy/mavproxy.stdout.log"
touch "$MAVPROXY_STDOUT_LOG"

# keep state/logs on host-mounted ./logs/mavproxy
exec mavproxy.py \
  --non-interactive \
  --master=udpin:0.0.0.0:14550 \
  --master=tcpin:0.0.0.0:14550 \
  --master=tcpin:0.0.0.0:5760 \
  --state-basedir=/logs/mavproxy \
  --aircraft=honeypot \
  --default-modules="link" \
  >>"$MAVPROXY_STDOUT_LOG" 2>&1
