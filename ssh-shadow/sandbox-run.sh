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

# Invoke the only allowed sudo command directly so the caller sees the real failure reason.
exec /usr/bin/sudo -n /opt/ssh-shadow/root-session-launch.sh "$SESSION_ROOTFS" "$LOGIN_USER" "$@"
