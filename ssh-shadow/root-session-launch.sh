#!/usr/bin/env bash
set -euo pipefail

bootstrap_log() {
  local session_dir="${1:-}"
  local step="${2:-}"
  local status="${3:-info}"
  local message="${4:-}"
  local rc="${5:-}"
  [[ -z "$session_dir" ]] && return 0
  mkdir -p "$session_dir" >/dev/null 2>&1 || true
  local out="${session_dir}/bootstrap.jsonl"
  python3 - <<'PY' "$out" "$step" "$status" "$message" "$rc"
import json,sys,time
path,step,status,message,rc=sys.argv[1:]
obj={"ts":time.time(),"step":step,"status":status}
if message:
    obj["message"]=message
if rc not in ("", "None", "null"):
    try:
        obj["rc"]=int(rc)
    except Exception:
        obj["rc"]=rc
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY
}

if [[ "${1:-}" == "--selftest" ]]; then
  ws="${2:-/opt/ssh-shadow/session-rootfs}"
  [[ -d "$ws" ]] || { echo "[ssh-shadow] selftest failed: missing rootfs $ws" >&2; exit 1; }
  exec chroot "$ws" /bin/bash -lc "true"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[ssh-shadow] root-session-launch must run as root" >&2
  exit 126
fi

if [[ "${1:-}" == "--prepare-session-rootfs" ]]; then
  BASE_ROOT="${2:?base_root}"
  SESSION_ROOTFS="${3:?session_rootfs}"
  LOGIN_USER="${4:?login_user}"
  HOST_SESSION_DIR="${5:-}"
  bootstrap_log "$HOST_SESSION_DIR" "rootfs_template_prepare" "start" "prepare-session-rootfs invoked"
  bootstrap_log "$HOST_SESSION_DIR" "build_jail" "start" "invoking build-jail.sh"
  if /opt/ssh-shadow/build-jail.sh "$BASE_ROOT" "$SESSION_ROOTFS" "$LOGIN_USER"; then
    bootstrap_log "$HOST_SESSION_DIR" "build_jail" "ok" "build-jail.sh completed"
    bootstrap_log "$HOST_SESSION_DIR" "rootfs_template_prepare" "ok" "prepare-session-rootfs completed"
  else
    rc=$?
    bootstrap_log "$HOST_SESSION_DIR" "build_jail" "fail" "build-jail.sh failed" "$rc"
    bootstrap_log "$HOST_SESSION_DIR" "rootfs_template_prepare" "fail" "prepare-session-rootfs failed" "$rc"
    exit "$rc"
  fi
  exit 0
fi

if [[ "${1:-}" == "--cleanup-session-rootfs" ]]; then
  SESSION_WORK_DIR="${2:?session_work_dir}"
  case "$SESSION_WORK_DIR" in
    /shadow/sessions/*) ;;
    *)
      echo "[ssh-shadow] refusing cleanup outside /shadow/sessions: $SESSION_WORK_DIR" >&2
      exit 124
      ;;
  esac
  cleanup_devpts_bind "${SESSION_WORK_DIR}/rootfs"
  exec rm -rf -- "$SESSION_WORK_DIR"
fi

SESSION_ROOTFS="${1:?session_rootfs}"
LOGIN_USER="${2:?login_user}"
shift 2
CHROOT_SESSION_DIR="${SESSION_ROOTFS}/tmp/.ssh-shadow/session"

if [[ ! -d "$SESSION_ROOTFS" ]]; then
  echo "[ssh-shadow] session rootfs not found: $SESSION_ROOTFS" >&2
  exit 127
fi

# Ensure /dev/tty is a real character device inside session rootfs.
if [[ ! -c "${SESSION_ROOTFS}/dev/tty" ]]; then
  rm -f "${SESSION_ROOTFS}/dev/tty" >/dev/null 2>&1 || true
  mknod -m 666 "${SESSION_ROOTFS}/dev/tty" c 5 0 >/dev/null 2>&1 || true
fi

rm -rf "${CHROOT_SESSION_DIR}" >/dev/null 2>&1 || true
mkdir -p "${CHROOT_SESSION_DIR}"
# Keep session metadata dir writable for the in-chroot login uid/gid (1000:1000),
# independent of host user/group name resolution.
chown -R 1000:1000 "${CHROOT_SESSION_DIR}" >/dev/null 2>&1 || true
chmod 755 "${CHROOT_SESSION_DIR}" >/dev/null 2>&1 || true
install -o 1000 -g 1000 -m 644 /dev/null "${CHROOT_SESSION_DIR}/commands.jsonl" >/dev/null 2>&1 || true
install -o 1000 -g 1000 -m 644 /dev/null "${CHROOT_SESSION_DIR}/events.jsonl" >/dev/null 2>&1 || true
if [[ ! -f "${CHROOT_SESSION_DIR}/provenance.json" ]]; then
  printf '{}\n' > "${CHROOT_SESSION_DIR}/provenance.json" || true
fi
chown 1000:1000 "${CHROOT_SESSION_DIR}/provenance.json" >/dev/null 2>&1 || true
chmod 644 "${CHROOT_SESSION_DIR}/provenance.json" >/dev/null 2>&1 || true

HOME_IN_CHROOT="/home/${LOGIN_USER}"
if [[ ! -d "${SESSION_ROOTFS}${HOME_IN_CHROOT}" ]]; then
  HOME_IN_CHROOT="/"
fi

if [[ -n "${HOST_SESSION_DIR:-}" ]]; then
  bootstrap_log "$HOST_SESSION_DIR" "chroot_launch" "start" "launching chroot command"
fi

launch_stderr_file=""
if [[ -n "${HOST_SESSION_DIR:-}" ]]; then
  launch_stderr_file="${HOST_SESSION_DIR}/chroot_launch.stderr"
  : > "$launch_stderr_file" || true
fi

if [[ -n "$launch_stderr_file" ]]; then
  chroot --userspec="${LOGIN_USER}" "$SESSION_ROOTFS" \
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
      "$@" \
      2> >(tee -a "$launch_stderr_file" >&2)
else
  chroot --userspec="${LOGIN_USER}" "$SESSION_ROOTFS" \
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
fi
rc=$?
if [[ -n "${HOST_SESSION_DIR:-}" ]]; then
  if [[ $rc -eq 0 ]]; then
    bootstrap_log "$HOST_SESSION_DIR" "chroot_launch" "ok" "chroot command exited cleanly" "$rc"
  else
    summary=""
    if [[ -n "$launch_stderr_file" ]]; then
      summary="$(tail -n 20 "$launch_stderr_file" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | cut -c1-600 || true)"
    fi
    bootstrap_log "$HOST_SESSION_DIR" "chroot_launch" "fail" "${summary:-chroot command failed}" "$rc"
  fi
fi
exit "$rc"
