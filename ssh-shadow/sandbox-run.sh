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

if [[ ! -S /run/ssh-shadow/root-launch.sock ]]; then
  echo "[ssh-shadow] root-session-daemon socket missing; cannot start session chroot" >&2
  exit 127
fi

exec /usr/bin/python3 /opt/ssh-shadow/root-session-client.py launch "$SESSION_ROOTFS" "$LOGIN_USER" "$@"
