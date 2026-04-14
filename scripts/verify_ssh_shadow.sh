#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

require_cmd docker
require_cmd ssh
require_cmd sshpass

export SSH_SHADOW_HOST_PORT="${SSH_SHADOW_HOST_PORT:-2222}"

login_cmd() {
  local user="$1" pass="$2" cmd="$3"
  sshpass -p "$pass" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$user"@127.0.0.1 "$cmd"
}

cleanup() {
  docker compose --profile ssh-shadow down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/10] docker compose config"
docker compose config >/tmp/ssh-shadow.compose.out

echo "[2/10] build + start services"
docker compose --profile ssh-shadow build shadow-sync ssh-shadow qgc watcher
docker compose --profile ssh-shadow up -d qgc watcher shadow-sync ssh-shadow

echo "[3/10] verify qgc + ssh-shadow are up"
docker compose ps qgc ssh-shadow | tee /tmp/ssh-shadow.ps.out
grep -q 'qgc' /tmp/ssh-shadow.ps.out
grep -q 'ssh-shadow' /tmp/ssh-shadow.ps.out

echo "wait for SSH readiness"
for _ in $(seq 1 30); do
  if login_cmd gcs 'gcs123!' 'echo ready' >/tmp/ssh-shadow.ready 2>/tmp/ssh-shadow.ready.err; then
    break
  fi
  sleep 1
done
grep -q 'ready' /tmp/ssh-shadow.ready

echo "[4/10] failed login is captured in preauth log"
set +e
login_cmd support 'wrong-pass' 'echo should_fail' >/tmp/ssh-shadow.bad.log 2>&1
BAD_RC=$?
set -e
[[ "$BAD_RC" -ne 0 ]]
grep -q '"event_type": "auth_failed"' logs/ssh-shadow/preauth.jsonl
grep -q '"username": "support"' logs/ssh-shadow/preauth.jsonl

echo "[5/10] successful login works for gcs/admin/ubuntu with per-user passwords"
login_cmd gcs 'gcs123!' 'pwd; whoami; ls /; ls /var/log/qgc; ls /home/gcs/Documents/QGroundControl; exit' >/tmp/ssh-shadow.gcs.log 2>&1
login_cmd admin 'admin' 'pwd; whoami; ls /; ls /var/log/qgc; ls /home/admin/Documents/QGroundControl; exit' >/tmp/ssh-shadow.admin.log 2>&1
login_cmd ubuntu 'ubuntu' 'pwd; whoami; ls /; ls /var/log/qgc; ls /home/ubuntu/Documents/QGroundControl; exit' >/tmp/ssh-shadow.ubuntu.log 2>&1
grep -q '^gcs$' /tmp/ssh-shadow.gcs.log
grep -q '^admin$' /tmp/ssh-shadow.admin.log
grep -q '^ubuntu$' /tmp/ssh-shadow.ubuntu.log

echo "[6/10] session logs exist + username recorded"
LATEST_SESSION_DIR="$(ls -1dt logs/ssh-shadow/sessions/* | head -n1)"
[[ -f "$LATEST_SESSION_DIR/session.json" ]]
[[ -f "$LATEST_SESSION_DIR/tty.transcript" ]]
[[ -f "$LATEST_SESSION_DIR/commands.jsonl" ]]
grep -q '"username": "ubuntu"' "$LATEST_SESSION_DIR/session.json"

echo "[7/10] no .cache rsync permission denied during login"
! rg -n "mesa_shader_cache|gstreamer-1.0|Permission denied" /tmp/ssh-shadow.*.log

echo "[8/10] sensitive behavior disconnect still works"
set +e
login_cmd guest 'guest' 'wget http://example.com/a' >/tmp/ssh-shadow.blocked.log 2>&1
BLOCK_RC=$?
set -e
[[ "$BLOCK_RC" -ne 0 ]]
LATEST_BLOCK_SESSION="$(ls -1dt logs/ssh-shadow/sessions/* | head -n1)"
grep -q 'blocked_command:wget http://example.com/a' "$LATEST_BLOCK_SESSION/termination_reason.txt"

echo "[9/10] isolation check"
login_cmd test 'test' 'echo attacker-file > ~/Documents/QGroundControl/attacker_only.txt; exit' >/tmp/ssh-shadow.iso.log 2>&1
[[ ! -f qgc/data/Documents/QGroundControl/attacker_only.txt ]]

echo "[10/10] watcher still running"
docker compose ps watcher | tee /tmp/ssh-shadow.watcher.ps.out
grep -q 'watcher' /tmp/ssh-shadow.watcher.ps.out

echo "All ssh-shadow verification checks passed."
