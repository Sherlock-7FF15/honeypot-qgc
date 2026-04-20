#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:?workspace}"
SESSION_DIR="${2:?session_dir}"
LOGIN_USER="${3:?login_user}"
shift 3

if [[ ! -x /opt/ssh-shadow/root-session-launch.sh ]]; then
  echo "[ssh-shadow] root-session-launch helper missing; cannot start session sandbox" >&2
  exit 127
fi

exec /usr/bin/sudo -n /opt/ssh-shadow/root-session-launch.sh "$WORKSPACE" "$LOGIN_USER" "$@"
