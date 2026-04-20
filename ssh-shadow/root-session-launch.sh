#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--selftest" ]]; then
  ws="${2:-/opt/ssh-shadow/session-rootfs}"
  [[ -d "$ws" ]] || { echo "[ssh-shadow] selftest failed: missing rootfs $ws" >&2; exit 1; }
  exec chroot "$ws" /bin/bash -lc "true"
fi

SESSION_ROOTFS="${1:?session_rootfs}"
LOGIN_USER="${2:?login_user}"
shift 2

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[ssh-shadow] root-session-launch must run as root" >&2
  exit 126
fi

if [[ ! -d "$SESSION_ROOTFS" ]]; then
  echo "[ssh-shadow] session rootfs not found: $SESSION_ROOTFS" >&2
  exit 127
fi

HOME_IN_CHROOT="/home/${LOGIN_USER}"
if [[ ! -d "${SESSION_ROOTFS}${HOME_IN_CHROOT}" ]]; then
  HOME_IN_CHROOT="/"
fi

exec chroot --userspec="${LOGIN_USER}" "$SESSION_ROOTFS" \
  /usr/bin/env -i \
    HOME="$HOME_IN_CHROOT" \
    USER="${LOGIN_USER}" \
    LOGNAME="${LOGIN_USER}" \
    PATH="/opt/ssh-shadow/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SSH_SHADOW_SANDBOX=1 \
    HONEYPOT_HOSTNAME="${HONEYPOT_HOSTNAME:-gcs-shadow}" \
    SESSION_DIR="${SESSION_DIR:-}" \
    WORKSPACE="/" \
    BASELINE_FILE="${BASELINE_FILE:-}" \
    BASELINE_META="${BASELINE_META:-}" \
    LOGIN_USER="${LOGIN_USER}" \
    SHADOW_WORKSPACE="/" \
    SHADOW_LOGIN_USER="${LOGIN_USER}" \
    CMD_LOG="${CMD_LOG:-}" \
    "$@"
