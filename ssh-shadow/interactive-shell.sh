#!/usr/bin/env bash
set -euo pipefail

SESSION_DIR="$1"
WORKSPACE="$2"
LOGIN_USER="${3:-gcs}"

export SESSION_DIR WORKSPACE LOGIN_USER
export BASELINE_FILE="${SESSION_DIR}/baseline_files.txt"
export PATH="/opt/ssh-shadow/fakebin:${PATH}"
export HOME="/home/${LOGIN_USER}"

CMD_LOG="${SESSION_DIR}/commands.jsonl"
export CMD_LOG

cat > "${SESSION_DIR}/bashrc" <<'BRC'
export HISTFILE=/dev/null
__SSH_SHADOW_LAST=""
export TMOUT="${SSH_SHADOW_IDLE_TIMEOUT:-900}"

__ssh_shadow_mark_idle_timeout() {
  if [[ ! -f "${SESSION_DIR}/termination_reason.txt" ]]; then
    /opt/ssh-shadow/trace-agent.sh log-idle-timeout >/dev/null 2>&1 || true
  fi
}

trap '__ssh_shadow_mark_idle_timeout' ALRM

__ssh_shadow_log_cmd() {
  local cmd
  cmd="$(history 1 | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == "$__SSH_SHADOW_LAST" ]] && return 0
  __SSH_SHADOW_LAST="$cmd"

  /opt/ssh-shadow/trace-agent.sh check-command "$cmd" "$PWD" || true

  python3 - <<'PY' "$CMD_LOG" "$cmd" "$PWD"
import json,sys,time
path,cmd,cwd=sys.argv[1:]
obj={"ts":time.time(),"event":"command","cmd":cmd,"cwd":cwd}
with open(path,"a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
PY

  /opt/ssh-shadow/trace-agent.sh post-command || exit 98
}

PROMPT_COMMAND='history -a; __ssh_shadow_log_cmd'
PS1="\u@${HONEYPOT_HOSTNAME:-gcs-shadow}:\w$ "
alias ls='/opt/ssh-shadow/fakebin/ls'
BRC

exec strace -ff -tt -s 256 -o "${SESSION_DIR}/strace" -e trace=%file,execve \
  script -qf "${SESSION_DIR}/tty.transcript" -c "cd /home/${LOGIN_USER} && /bin/bash --noprofile --rcfile ${SESSION_DIR}/bashrc -i"
