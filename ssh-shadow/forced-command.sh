#!/usr/bin/env bash
set -euo pipefail

LOG_ROOT="/logs/ssh-shadow"
SESS_ROOT="${LOG_ROOT}/sessions"
STATE_ROOT="/shadow/state"
BASE_ROOT="/shadow/base"
JAILS_ROOT="/shadow/jails"

mkdir -p "$SESS_ROOT" "$STATE_ROOT" "$JAILS_ROOT"

REMOTE_IP="unknown"
REMOTE_PORT="0"
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  REMOTE_IP="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
  REMOTE_PORT="$(awk '{print $2}' <<<"$SSH_CONNECTION")"
fi

LOGIN_USER="${USER:-gcs}"
[[ -z "$LOGIN_USER" ]] && LOGIN_USER="gcs"

NOW_TS="$(date -u +%s)"
SESSION_ID="${NOW_TS}_${REMOTE_IP//:/_}_${REMOTE_PORT}_sshshadow"
SESSION_DIR="${SESS_ROOT}/${SESSION_ID}"
JAIL_ROOT="${JAILS_ROOT}/${SESSION_ID}/rootfs"
mkdir -p "$SESSION_DIR" "$JAIL_ROOT"

META_FILE="${SESSION_DIR}/session.json"
cat > "$META_FILE" <<JSON
{
  "session_id": "${SESSION_ID}",
  "username": "${LOGIN_USER}",
  "remote_ip": "${REMOTE_IP}",
  "remote_port": ${REMOTE_PORT},
  "jail_root": "${JAIL_ROOT}",
  "login_time_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ssh_original_command": $(python3 - <<'PY' "${SSH_ORIGINAL_COMMAND:-}"
import json,sys
print(json.dumps(sys.argv[1]))
PY
)
}
JSON

LOCK_FILE="${STATE_ROOT}/active_session.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[ssh-shadow] console busy, try again later."
  python3 - <<'PY' "$LOG_ROOT" "$REMOTE_IP" "$REMOTE_PORT" "$LOGIN_USER"
import json,sys,time
root,ip,port,username=sys.argv[1:]
with open(f"{root}/busy.jsonl","a",encoding="utf-8") as f:
    f.write(json.dumps({"ts":time.time(),"event":"busy_reject","remote_ip":ip,"remote_port":int(port),"username":username})+"\n")
PY
  exit 1
fi

cleanup() {
  local rc=$?
  local reason="normal_exit"
  if [[ -f "${SESSION_DIR}/termination_reason.txt" ]]; then
    reason="$(cat "${SESSION_DIR}/termination_reason.txt")"
  elif [[ $rc -ne 0 ]]; then
    reason="exit_code_${rc}"
  fi

  /opt/ssh-shadow/trace-agent.sh capture-evidence >/dev/null 2>&1 || true

  python3 - <<'PY' "$META_FILE" "$reason"
import json,sys,time
path,reason=sys.argv[1:]
with open(path,'r',encoding='utf-8') as f:
    obj=json.load(f)
obj['logout_time_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
obj['termination_reason']=reason
with open(path,'w',encoding='utf-8') as f:
    json.dump(obj,f,ensure_ascii=False,indent=2)
PY
}
trap cleanup EXIT

if [[ -n "${SSH_ORIGINAL_COMMAND:-}" ]]; then
  if [[ "${SSH_ORIGINAL_COMMAND}" =~ (^|[[:space:]])(scp|sftp)([[:space:]]|$) ]]; then
    export SESSION_DIR WORKSPACE="$JAIL_ROOT" BASELINE_FILE="${SESSION_DIR}/baseline_files.txt"
    echo "blocked_ssh_original_command:${SSH_ORIGINAL_COMMAND}" > "${SESSION_DIR}/termination_reason.txt"
    /opt/ssh-shadow/trace-agent.sh check-command "${SSH_ORIGINAL_COMMAND}" >/dev/null 2>&1 || true
    echo "[ssh-shadow] file transfer channels are disabled."
    exit 1
  fi
fi

/opt/ssh-shadow/build-jail.sh "${BASE_ROOT}" "${JAIL_ROOT}"

export SESSION_DIR WORKSPACE="$JAIL_ROOT" BASELINE_FILE="${SESSION_DIR}/baseline_files.txt" LOGIN_USER

echo "[ssh-shadow] connected to shadow GCS workstation"
/opt/ssh-shadow/interactive-shell.sh "$SESSION_DIR" "$JAIL_ROOT" "$LOGIN_USER"
