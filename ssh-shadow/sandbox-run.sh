#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:?workspace}"
SESSION_DIR="${2:?session_dir}"
LOGIN_USER="${3:?login_user}"
shift 3

if [[ ! -x /opt/ssh-shadow/session-exec ]]; then
  echo "[ssh-shadow] session-exec helper missing; cannot start session sandbox" >&2
  exit 127
fi

exec /opt/ssh-shadow/session-exec "$WORKSPACE" "$LOGIN_USER" "$@"
