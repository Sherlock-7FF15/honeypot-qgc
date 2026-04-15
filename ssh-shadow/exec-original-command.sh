#!/usr/bin/env bash
set -euo pipefail

SESSION_DIR="$1"
WORKSPACE="$2"
LOGIN_USER="$3"
ORIG_CMD="$4"

export SESSION_DIR WORKSPACE LOGIN_USER
export BASELINE_FILE="${SESSION_DIR}/baseline_files.txt"
export PATH="/opt/ssh-shadow/fakebin:${PATH}"
export HOME="/home/${LOGIN_USER}"

python3 - <<'PY' "$SESSION_DIR/commands.jsonl" "$ORIG_CMD" "/home/${LOGIN_USER}" "ssh_exec"
import json,sys,time
path,cmd,cwd,event = sys.argv[1:]
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps({"ts":time.time(),"event":event,"cmd":cmd,"cwd":cwd},ensure_ascii=False)+"\n")
PY


/opt/ssh-shadow/trace-agent.sh check-command "$ORIG_CMD" >/dev/null 2>&1 || true

OUT_FILE="${SESSION_DIR}/exec.stdout"
ERR_FILE="${SESSION_DIR}/exec.stderr"
: > "$OUT_FILE"
: > "$ERR_FILE"

set +e
strace -ff -tt -s 256 -o "${SESSION_DIR}/strace_exec" -e trace=%file,execve \
  /bin/bash -lc "$ORIG_CMD" >"$OUT_FILE" 2>"$ERR_FILE"
RC=$?
set -e

cat "$OUT_FILE"
cat "$ERR_FILE" >&2

python3 - <<'PY' "$SESSION_DIR/events.jsonl" "$ORIG_CMD" "$RC" "$OUT_FILE" "$ERR_FILE"
import json,sys,time,os
events,cmd,rc,outf,errf = sys.argv[1:]
obj={
  "ts":time.time(),
  "event":"ssh_exec_complete",
  "cmd":cmd,
  "exit_code":int(rc),
  "stdout_bytes":os.path.getsize(outf) if os.path.exists(outf) else 0,
  "stderr_bytes":os.path.getsize(errf) if os.path.exists(errf) else 0,
}
with open(events,"a",encoding="utf-8") as f:
  f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY

/opt/ssh-shadow/trace-agent.sh post-command >/dev/null 2>&1 || true
exit "$RC"
