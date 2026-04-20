#!/usr/bin/env bash
set -euo pipefail

LOG_ROOT="/logs/ssh-shadow"
SESS_ROOT="${LOG_ROOT}/sessions"
STATE_ROOT="/shadow/state"
BASE_ROOT="/shadow/base"
SESS_WORK_ROOT="/shadow/sessions"
HONEYPOT_HOSTNAME="${HONEYPOT_HOSTNAME:-gcs-shadow}"

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
SESSION_ROOTFS="${SESS_WORK_ROOT}/${SESSION_ID}/rootfs"
SESSION_WORK_DIR="${SESS_WORK_ROOT}/${SESSION_ID}"
mkdir -p "$SESSION_DIR" "$SESSION_ROOTFS"

META_FILE="${SESSION_DIR}/session.json"
cat > "$META_FILE" <<JSON
{
  "session_id": "${SESSION_ID}",
  "username": "${LOGIN_USER}",
  "remote_ip": "${REMOTE_IP}",
  "remote_port": ${REMOTE_PORT},
  "session_rootfs": "${SESSION_ROOTFS}",
  "isolation_mode": "session-chroot-rootfs",
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

setup_projection() {
  /opt/ssh-shadow/build-jail.sh "$BASE_ROOT" "$SESSION_ROOTFS" "$LOGIN_USER"

  BASELINE_META="${SESSION_DIR}/baseline_meta.json"
  python3 - <<'PY' "$SESSION_ROOTFS" "$BASELINE_META" "${SESSION_DIR}/baseline_files.txt"
import json,sys
from pathlib import Path
root=Path(sys.argv[1])
out=Path(sys.argv[2])
list_out=Path(sys.argv[3])
rows={}
for p in root.rglob('*'):
    if not p.is_file():
        continue
    rel=str(p.relative_to(root))
    st=p.stat()
    rows[rel]={"size":st.st_size,"mtime_ns":st.st_mtime_ns}
out.write_text(json.dumps(rows,ensure_ascii=False),encoding='utf-8')
list_out.write_text('\n'.join(sorted(rows.keys())) + ('\n' if rows else ''), encoding='utf-8')
PY
}

cleanup_projection() {
  true
}

cleanup() {
  local rc=$?
  local reason="normal_exit"
  if [[ -f "${SESSION_DIR}/termination_reason.txt" ]]; then
    reason="$(cat "${SESSION_DIR}/termination_reason.txt")"
  elif [[ $rc -ne 0 ]]; then
    reason="exit_code_${rc}"
  fi

  if [[ "$reason" == payload_captured:* || "$reason" == *"sensitive"* ]]; then
    /opt/ssh-shadow/trace-agent.sh capture-evidence >/dev/null 2>&1 || true
  fi
  python3 - <<'PY' "$SESSION_ROOTFS" "${SESSION_DIR}/baseline_meta.json" "${SESSION_DIR}/diff"
import json,sys,shutil
from pathlib import Path

rootfs=Path(sys.argv[1])
baseline_path=Path(sys.argv[2])
diff_dir=Path(sys.argv[3])
files_dir=diff_dir/"files"
files_dir.mkdir(parents=True,exist_ok=True)

baseline={}
if baseline_path.exists():
    baseline=json.loads(baseline_path.read_text(encoding='utf-8',errors='replace'))

current={}
for p in rootfs.rglob('*'):
    if not p.is_file():
        continue
    rel=str(p.relative_to(rootfs))
    st=p.stat()
    current[rel]={"size":st.st_size,"mtime_ns":st.st_mtime_ns}

created=[]
modified=[]
deleted=[]

for rel,meta in current.items():
    b=baseline.get(rel)
    if b is None:
        created.append(rel)
    elif b.get("size")!=meta.get("size") or b.get("mtime_ns")!=meta.get("mtime_ns"):
        modified.append(rel)

for rel in baseline.keys():
    if rel not in current:
        deleted.append(rel)

for rel in created+modified:
    src=rootfs/rel
    dst=files_dir/rel
    dst.parent.mkdir(parents=True,exist_ok=True)
    try:
        shutil.copy2(src,dst)
    except Exception:
        pass

summary={
    "created": sorted(created),
    "modified": sorted(modified),
    "deleted": sorted(deleted),
    "counts": {
        "created": len(created),
        "modified": len(modified),
        "deleted": len(deleted),
    }
}
(diff_dir/"diff_summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
PY
  cleanup_projection || true

  rm -rf "$SESSION_WORK_DIR" "/shadow/jails/${SESSION_ID}" || true

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

setup_projection
export SESSION_DIR SESSION_ROOTFS WORKSPACE="$SESSION_ROOTFS" BASELINE_FILE="${SESSION_DIR}/baseline_files.txt" BASELINE_META="${SESSION_DIR}/baseline_meta.json" LOGIN_USER SHADOW_WORKSPACE="$SESSION_ROOTFS" SHADOW_LOGIN_USER="$LOGIN_USER" HONEYPOT_HOSTNAME

if [[ -n "${SSH_ORIGINAL_COMMAND:-}" ]]; then
  echo "non_interactive_exec" > "${SESSION_DIR}/session_mode.txt"
  /opt/ssh-shadow/exec-original-command.sh "$SESSION_DIR" "$SESSION_ROOTFS" "$LOGIN_USER" "$SSH_ORIGINAL_COMMAND"
else
  echo "interactive_shell" > "${SESSION_DIR}/session_mode.txt"
  echo "[ssh-shadow] connected to shadow GCS workstation"
  /opt/ssh-shadow/interactive-shell.sh "$SESSION_DIR" "$SESSION_ROOTFS" "$LOGIN_USER"
fi
