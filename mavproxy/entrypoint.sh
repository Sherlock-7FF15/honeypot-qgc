#!/usr/bin/env sh
set -eu

mkdir -p /data/mavproxy /logs

exec mavproxy.py \
  --non-interactive \
  --master=udpin:0.0.0.0:14550 \
  --master=tcpin:0.0.0.0:14550 \
  --master=tcpin:0.0.0.0:5760 \
  --state-basedir=/data/mavproxy \
  --aircraft=honeypot \
  --default-modules="link"
