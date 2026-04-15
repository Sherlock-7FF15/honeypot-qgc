#!/usr/bin/env bash
set -euo pipefail

SESSION_DIR="${SESSION_DIR:?}"
WORKSPACE="${WORKSPACE:?}"
BASELINE_FILE="${BASELINE_FILE:?}"

EVENTS_FILE="${SESSION_DIR}/events.jsonl"
TERM_FILE="${SESSION_DIR}/termination_reason.txt"
EVIDENCE_DIR="${SESSION_DIR}/evidence"

log_event() {
  local event_name="$1"
  local detail="${2:-}"
  local extra="${3:-{}}"
  local ts
  ts="$(date -u +%s.%N)"
  python3 - <<'PY' "$EVENTS_FILE" "$ts" "$event_name" "$detail" "$extra"
import json,sys
path,ts,name,detail,extra = sys.argv[1:]
obj={"ts":float(ts),"event":name,"detail":detail}
try:
    obj.update(json.loads(extra))
except Exception:
    obj["extra_raw"]=extra
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY
}

capture_evidence() {
  mkdir -p "$EVIDENCE_DIR/files"
  python3 - <<'PY' "$WORKSPACE" "$BASELINE_FILE" "$EVIDENCE_DIR"
import os,sys,hashlib,json,shutil
from pathlib import Path
workspace=Path(sys.argv[1])
baseline=Path(sys.argv[2])
ev=Path(sys.argv[3])
known=set()
if baseline.exists():
    for line in baseline.read_text(encoding='utf-8',errors='replace').splitlines():
        if line.strip():
            known.add(line.strip())
rows=[]
for p in workspace.rglob('*'):
    if not p.is_file():
        continue
    rel=str(p.relative_to(workspace))
    if rel.startswith('var/log/qgc/') or rel.startswith('var/log/mavproxy/'):
        continue
    st=p.stat()
    is_new=rel not in known
    is_exe=bool(st.st_mode & 0o111)
    suspicious_suffix=rel.endswith(('.sh','.py','.elf','.bin'))
    with p.open('rb') as f:
        head=f.read(4)
    is_elf=head==b'\x7fELF'
    if is_new or is_exe or suspicious_suffix or is_elf:
        h=hashlib.sha256()
        with p.open('rb') as f:
            for ch in iter(lambda:f.read(1024*1024),b''):
                h.update(ch)
        rows.append({"path":rel,"sha256":h.hexdigest(),"size":st.st_size,"is_new":is_new,"is_executable":is_exe,"is_elf":is_elf})
        out=ev/"files"/rel
        out.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(p,out)
(ev/"file_hashes.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
PY
}

terminate_with_reason() {
  local reason="$1"
  log_event "payload_captured" "$reason" '{"severity":"high","action":"terminate"}'
  capture_evidence || true
  echo "$reason" > "$TERM_FILE"
  return 99
}

check_sensitive_command() {
  local cmd="$1"
  if [[ "$cmd" =~ (^|[[:space:]])(scp|sftp|wget|curl|tftp|nc|ncat)([[:space:]]|$) ]]; then
    log_event "suspicious" "network_tool:${cmd}" '{"severity":"medium","action":"observe"}'
  fi
  if [[ "$cmd" =~ chmod[[:space:]]+\+x ]]; then
    log_event "suspicious" "chmod_plus_x:${cmd}" '{"severity":"medium","action":"observe"}'
  fi
  if [[ "$cmd" =~ (python|python3|bash|sh)[[:space:]]+-c[[:space:]] ]]; then
    log_event "suspicious" "inline_exec:${cmd}" '{"severity":"medium","action":"observe"}'
  fi
  if [[ "$cmd" =~ (/dev/tcp|reverse|bash[[:space:]]+-i) ]]; then
    log_event "suspicious" "reverse_shell_like:${cmd}" '{"severity":"medium","action":"observe"}'
  fi
  return 0
}

scan_workspace_payload() {
  python3 - <<'PY' "$WORKSPACE" "$BASELINE_FILE"
import sys
from pathlib import Path

ws=Path(sys.argv[1])
baseline=Path(sys.argv[2])
known=set()
if baseline.exists():
    known=set(x.strip() for x in baseline.read_text(encoding='utf-8',errors='replace').splitlines() if x.strip())

watch_prefixes=(
    'home/',
    'tmp/',
    'var/tmp/',
    'opt/',
    'usr/local/',
)
ignore_prefixes=(
    'var/log/qgc/',
    'var/log/mavproxy/',
)
ignore_names=('qgc.stdout','qgc.stderr','ffmpeg.stdout','ffmpeg.stderr','mavproxy.stdout','mavproxy.stderr')

for p in ws.rglob('*'):
    if not p.is_file():
        continue
    rel=str(p.relative_to(ws))
    if rel in known:
        continue
    if rel.startswith(ignore_prefixes):
        continue
    if p.name in ignore_names:
        continue
    if not rel.startswith(watch_prefixes):
        continue

    st=p.stat()
    is_exe=bool(st.st_mode & 0o111)
    suspicious_suffix=rel.endswith(('.sh','.py','.elf','.bin'))
    with p.open('rb') as f:
        head=f.read(256)
    is_elf=head[:4]==b'\x7fELF'
    shebang=head.startswith(b'#!')

    if is_elf or (is_exe and (suspicious_suffix or shebang or len(head) > 0)) or suspicious_suffix:
        print(f'payload_captured:{rel}')
        sys.exit(7)

sys.exit(0)
PY
}

case "${1:-}" in
  check-command)
    check_sensitive_command "${2:-}" ;;
  post-command)
    reason="$(scan_workspace_payload || true)"
    if [[ -n "$reason" ]]; then
      terminate_with_reason "$reason"
    fi
    ;;
  capture-evidence)
    capture_evidence ;;
  log-idle-timeout)
    log_event "idle_timeout" "session idle timeout reached" '{"severity":"low","action":"terminate"}'
    echo "idle_timeout" > "$TERM_FILE"
    ;;
  *)
    echo "usage: $0 {check-command|post-command|capture-evidence|log-idle-timeout}" >&2
    exit 2 ;;
esac
