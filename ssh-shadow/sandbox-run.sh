#!/usr/bin/env bash
set -euo pipefail

SESSION_ROOTFS="${1:?session_rootfs}"
SESSION_DIR="${2:?session_dir}"
LOGIN_USER="${3:?login_user}"
shift 3

if [[ ! -x /opt/ssh-shadow/root-session-launch.sh ]]; then
  echo "[ssh-shadow] root-session-launch helper missing; cannot start session chroot" >&2
  exit 127
fi

if ! /usr/bin/sudo -n true >/dev/null 2>&1; then
  echo "[ssh-shadow] root-managed chroot is required but sudo elevation is unavailable" >&2
  exit 125
fi

exec /usr/bin/sudo -n /opt/ssh-shadow/root-session-launch.sh "$SESSION_ROOTFS" "$LOGIN_USER" "$@"
