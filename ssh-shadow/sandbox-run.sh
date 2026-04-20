#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:?workspace}"
SESSION_DIR="${2:?session_dir}"
LOGIN_USER="${3:?login_user}"
shift 3

# Prefer bubblewrap when available, but gracefully fall back to proot if
# kernel/userns policy rejects unprivileged namespaces.
if command -v bwrap >/dev/null 2>&1; then
  set +e
  env SSH_SHADOW_SANDBOX=1 bwrap \
    --die-with-parent \
    --new-session \
    --unshare-pid \
    --bind "$WORKSPACE" / \
    --ro-bind /bin /bin \
    --ro-bind /sbin /sbin \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 \
    --ro-bind /opt/ssh-shadow /opt/ssh-shadow \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --ro-bind /etc/hosts /etc/hosts \
    --bind "$WORKSPACE/dev/shm" /dev/shm \
    --dev-bind /dev /dev \
    --proc /proc \
    --bind "$SESSION_DIR" "$SESSION_DIR" \
    --chdir "/home/${LOGIN_USER}" \
    "$@"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    exit 0
  fi
  echo "[ssh-shadow] bwrap unavailable in current kernel policy; falling back to proot" >&2
fi

exec env SSH_SHADOW_SANDBOX=1 proot -R "$WORKSPACE" \
  -b /bin:/bin \
  -b /sbin:/sbin \
  -b /usr:/usr \
  -b /lib:/lib \
  -b /lib64:/lib64 \
  -b /opt/ssh-shadow:/opt/ssh-shadow \
  -b /dev:/dev \
  -b /proc:/proc \
  -b /sys:/sys \
  -b /etc/resolv.conf:/etc/resolv.conf \
  -b /etc/hosts:/etc/hosts \
  -b "$SESSION_DIR":"$SESSION_DIR" \
  -w "/home/${LOGIN_USER}" \
  "$@"
