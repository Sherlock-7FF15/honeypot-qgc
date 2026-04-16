export HISTFILE=/dev/null
export USER=root
export LOGNAME=root
export HOME=/root
cd "${SHADOW_FAKE_ROOT_HOME:-/tmp}" 2>/dev/null || true
PS1="root@${HONEYPOT_HOSTNAME:-gcs-shadow}:~# "
alias ls='/opt/ssh-shadow/fakebin/ls'
