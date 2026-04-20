#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--selftest" ]]; then
  ws="${2:-/opt/ssh-shadow/session-rootfs}"
  [[ -d "$ws" ]] || { echo "[ssh-shadow] selftest failed: missing rootfs $ws" >&2; exit 1; }
  exec chroot "$ws" /bin/bash -lc "true"
fi

WORKSPACE="${1:?workspace}"
LOGIN_USER="${2:?login_user}"
shift 2

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[ssh-shadow] root-session-launch must run as root" >&2
  exit 126
fi

if [[ ! -d "$WORKSPACE" ]]; then
  echo "[ssh-shadow] workspace not found: $WORKSPACE" >&2
  exit 127
fi

exec chroot --userspec="${LOGIN_USER}" "$WORKSPACE" \
  /usr/bin/env -i \
    HOME="/home/${LOGIN_USER}" \
    USER="${LOGIN_USER}" \
    LOGNAME="${LOGIN_USER}" \
    PATH="/opt/ssh-shadow/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SSH_SHADOW_SANDBOX=1 \
    HONEYPOT_HOSTNAME="${HONEYPOT_HOSTNAME:-gcs-shadow}" \
    "$@"
