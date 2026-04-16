export HISTFILE=/dev/null
export USER=root
export LOGNAME=root
export HOME=/root

__SSH_SHADOW_REAL_ROOT_HOME="${SHADOW_FAKE_ROOT_HOME:-/tmp}"
__ssh_shadow_fake_pwd() {
  local cur
  cur="$(builtin pwd)"
  if [[ "$cur" == "$__SSH_SHADOW_REAL_ROOT_HOME"* ]]; then
    printf '/root%s\n' "${cur#$__SSH_SHADOW_REAL_ROOT_HOME}"
  else
    printf '%s\n' "$cur"
  fi
}

cd() {
  local target="${1:-$HOME}"
  case "$target" in
    "~"|"~/"*)
      target="${__SSH_SHADOW_REAL_ROOT_HOME}${target#\~}"
      ;;
    /root|/root/*)
      target="${__SSH_SHADOW_REAL_ROOT_HOME}${target#/root}"
      ;;
  esac
  builtin cd "$target"
}

pwd() {
  __ssh_shadow_fake_pwd
}

cd "$HOME" 2>/dev/null || builtin cd "$__SSH_SHADOW_REAL_ROOT_HOME" 2>/dev/null || true
PS1="root@${HONEYPOT_HOSTNAME:-gcs-shadow}:~# "
alias ls='/opt/ssh-shadow/fakebin/ls'
