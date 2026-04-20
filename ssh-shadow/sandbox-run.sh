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

if /usr/bin/sudo -n true >/dev/null 2>&1; then
  exec /usr/bin/sudo -n /opt/ssh-shadow/root-session-launch.sh "$WORKSPACE" "$LOGIN_USER" "$@"
fi

echo "[ssh-shadow] WARN: sudo elevation unavailable (likely nosuid/no-new-privileges); using direct session mode" >&2
cd "/home/${LOGIN_USER}" 2>/dev/null || true
exec env SSH_SHADOW_SANDBOX=0 "$@"
