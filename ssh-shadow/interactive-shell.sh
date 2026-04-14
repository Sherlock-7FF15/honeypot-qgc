#!/usr/bin/env bash
set -euo pipefail

SESSION_DIR="$1"
JAIL_ROOT="$2"

export SESSION_DIR
export WORKSPACE="$JAIL_ROOT"
export BASELINE_FILE="${SESSION_DIR}/baseline_files.txt"
export PATH="/opt/ssh-shadow/fakebin:${PATH}"
export HOME="/home/gcs"

find "$JAIL_ROOT" -xdev -type f -printf '%P\n' | sort > "$BASELINE_FILE"

CMD_LOG="${SESSION_DIR}/commands.jsonl"
export CMD_LOG

cat > "${SESSION_DIR}/bashrc" <<'BRC'
export HISTFILE=/dev/null
__SSH_SHADOW_LAST=""

__ssh_shadow_log_cmd() {
  local cmd
  cmd="$(history 1 | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == "$__SSH_SHADOW_LAST" ]] && return 0
  __SSH_SHADOW_LAST="$cmd"

  /opt/ssh-shadow/trace-agent.sh check-command "$cmd" || {
    echo "[ssh-shadow] sensitive behavior detected, disconnecting" >&2
    exit 99
  }

  python3 - <<'PY' "$CMD_LOG" "$cmd" "$PWD"
import json,sys,time
path,cmd,cwd=sys.argv[1:]
obj={"ts":time.time(),"event":"command","cmd":cmd,"cwd":cwd}
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY

  /opt/ssh-shadow/trace-agent.sh post-command || {
    echo "[ssh-shadow] suspicious file behavior detected, disconnecting" >&2
    exit 98
  }
}

PROMPT_COMMAND='history -a; __ssh_shadow_log_cmd'
PS1='gcs@gcs-shadow:\w$ '
BRC

exec strace -ff -tt -s 256 -o "${SESSION_DIR}/strace" -e trace=%file,execve \
  script -qf "${SESSION_DIR}/tty.transcript" -c "proot -R ${JAIL_ROOT} -b /bin:/bin -b /usr/bin:/usr/bin -b /lib:/lib -b /lib64:/lib64 -b /usr/lib:/usr/lib -b /proc:/proc -b /dev:/dev -b /tmp:/tmp -w /home/gcs /bin/bash --noprofile --rcfile ${SESSION_DIR}/bashrc -i"
