#!/usr/bin/env bash
set -euo pipefail

LOG_ROOT="/logs/ssh-shadow"
SESS_ROOT="${LOG_ROOT}/sessions"
STATE_ROOT="/shadow/state"
BASE_ROOT="/shadow/base"
SESS_WORK_ROOT="/shadow/sessions"

mkdir -p "$SESS_ROOT" "$STATE_ROOT" "$SESS_WORK_ROOT"

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
WORKSPACE="${SESS_WORK_ROOT}/${SESSION_ID}/workspace"
mkdir -p "$SESSION_DIR" "$WORKSPACE"

META_FILE="${SESSION_DIR}/session.json"
cat > "$META_FILE" <<JSON
{
  "session_id": "${SESSION_ID}",
  "username": "${LOGIN_USER}",
  "remote_ip": "${REMOTE_IP}",
  "remote_port": ${REMOTE_PORT},
  "workspace": "${WORKSPACE}",
  "isolation_mode": "session-workspace-no-proot",
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

HOME_PATH="/home/${LOGIN_USER}"
ORIG_HOME_PATH="/home/${LOGIN_USER}.__orig"

setup_projection() {
  /opt/ssh-shadow/build-jail.sh "$BASE_ROOT" "$WORKSPACE" "$LOGIN_USER"

  rm -rf "$ORIG_HOME_PATH"

  if [[ -L "$HOME_PATH" ]]; then
    rm -f "$HOME_PATH"
  elif [[ -d "$HOME_PATH" ]]; then
    mv "$HOME_PATH" "$ORIG_HOME_PATH"
  else
    rm -f "$HOME_PATH" || true
  fi

  ln -s "$WORKSPACE/home/${LOGIN_USER}" "$HOME_PATH"
}

cleanup_projection() {
  if [[ -L "$HOME_PATH" ]]; then
    rm -f "$HOME_PATH"
  fi
  if [[ -d "$ORIG_HOME_PATH" ]]; then
    mv "$ORIG_HOME_PATH" "$HOME_PATH"
  else
    mkdir -p "$HOME_PATH"
    chown "${LOGIN_USER}:honeypot" "$HOME_PATH" || true
  fi
}

cleanup() {
  local rc=$?
  local reason="normal_exit"
  if [[ -f "${SESSION_DIR}/termination_reason.txt" ]]; then
    reason="$(cat "${SESSION_DIR}/termination_reason.txt")"
  elif [[ $rc -ne 0 ]]; then
    reason="exit_code_${rc}"
  fi

  /opt/ssh-shadow/trace-agent.sh capture-evidence >/dev/null 2>&1 || true
  cleanup_projection || true

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
    export SESSION_DIR WORKSPACE BASELINE_FILE="${SESSION_DIR}/baseline_files.txt"
    echo "blocked_ssh_original_command:${SSH_ORIGINAL_COMMAND}" > "${SESSION_DIR}/termination_reason.txt"
    /opt/ssh-shadow/trace-agent.sh check-command "${SSH_ORIGINAL_COMMAND}" >/dev/null 2>&1 || true
    echo "[ssh-shadow] file transfer channels are disabled."
    exit 1
  fi
fi

setup_projection
export SESSION_DIR WORKSPACE BASELINE_FILE="${SESSION_DIR}/baseline_files.txt" LOGIN_USER SHADOW_WORKSPACE="$WORKSPACE" SHADOW_LOGIN_USER="$LOGIN_USER"

echo "[ssh-shadow] connected to shadow GCS workstation"
/opt/ssh-shadow/interactive-shell.sh "$SESSION_DIR" "$WORKSPACE" "$LOGIN_USER"
