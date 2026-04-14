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
export SSH_SHADOW_PASSWORD="${SSH_SHADOW_PASSWORD:-gcs123!}"

cleanup() {
  docker compose --profile ssh-shadow down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/12] docker compose config"
docker compose config >/tmp/ssh-shadow.compose.out

echo "[2/12] build ssh-shadow profile"
docker compose --profile ssh-shadow build shadow-sync ssh-shadow qgc watcher

echo "[3/12] start services"
docker compose --profile ssh-shadow up -d qgc watcher shadow-sync ssh-shadow

echo "[4/12] verify qgc + ssh-shadow are up"
docker compose ps qgc ssh-shadow | tee /tmp/ssh-shadow.ps.out
grep -q 'qgc' /tmp/ssh-shadow.ps.out
grep -q 'ssh-shadow' /tmp/ssh-shadow.ps.out

echo "waiting for ssh-shadow to listen on ${SSH_SHADOW_HOST_PORT}..."
for _ in $(seq 1 30); do
  if sshpass -p "$SSH_SHADOW_PASSWORD" ssh -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 gcs@127.0.0.1 'echo ready' >/tmp/ssh-shadow.ready 2>/tmp/ssh-shadow.ready.err; then
    break
  fi
  sleep 1
done

if ! grep -q 'ready' /tmp/ssh-shadow.ready; then
  echo "ssh-shadow did not become ready" >&2
  exit 1
fi

echo "[5/12] verify sync from live source to shadow/base"
mkdir -p qgc/data/Documents/QGroundControl logs/qgc logs/mavproxy
printf 'verify-shadow-sync\n' > qgc/data/Documents/QGroundControl/verify_shadow.txt
printf 'verify-qgc-log\n' > logs/qgc/verify_qgc.log
for _ in $(seq 1 20); do
  [[ -f shadow/base/home/gcs/Documents/QGroundControl/verify_shadow.txt ]] && break
  sleep 1
done
[[ -f shadow/base/home/gcs/Documents/QGroundControl/verify_shadow.txt ]]
grep -q 'verify-shadow-sync' shadow/base/home/gcs/Documents/QGroundControl/verify_shadow.txt

echo "[6/12] one-session lock (second session must be busy/disconnected)"
sshpass -p "$SSH_SHADOW_PASSWORD" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null gcs@127.0.0.1 'echo first_session_ready; sleep 15' > /tmp/ssh-shadow.first.log 2>&1 &
FIRST_PID=$!
sleep 2
set +e
sshpass -p "$SSH_SHADOW_PASSWORD" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 gcs@127.0.0.1 'echo second' > /tmp/ssh-shadow.second.log 2>&1
SECOND_RC=$?
set -e
wait "$FIRST_PID" || true
[[ "$SECOND_RC" -ne 0 ]]
grep -qi 'console busy' /tmp/ssh-shadow.second.log

echo "[7/12] successful login lands in jail + normal paths work"
sshpass -p "$SSH_SHADOW_PASSWORD" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null gcs@127.0.0.1 'pwd; ls /; ls /home/gcs/Documents/QGroundControl; ls /var/log/qgc; test ! -e /shadow; test ! -e /shadow/sessions; cat /var/log/qgc/verify_qgc.log >/dev/null; exit'

LATEST_SESSION_DIR="$(ls -1dt logs/ssh-shadow/sessions/* | head -n1)"
[[ -f "$LATEST_SESSION_DIR/session.json" ]]
[[ -f "$LATEST_SESSION_DIR/tty.transcript" ]]
[[ -f "$LATEST_SESSION_DIR/commands.jsonl" ]]
ls "$LATEST_SESSION_DIR"/strace* >/dev/null 2>&1
grep -q '"cmd": "pwd"' "$LATEST_SESSION_DIR/commands.jsonl"

echo "[8/12] failed login attempt appears in preauth log"
set +e
sshpass -p 'wrong-pass' ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 gcs@127.0.0.1 'echo should_fail' >/tmp/ssh-shadow.failed-auth.log 2>&1
FAIL_RC=$?
set -e
[[ "$FAIL_RC" -ne 0 ]]
grep -q '"event_type": "auth_failed"' logs/ssh-shadow/preauth.jsonl

echo "[9/12] successful login appears in preauth log"
grep -q '"event_type": "auth_success"' logs/ssh-shadow/preauth.jsonl

echo "[10/12] sensitive behavior disconnect (wget)"
set +e
sshpass -p "$SSH_SHADOW_PASSWORD" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null gcs@127.0.0.1 'wget http://example.com/a' > /tmp/ssh-shadow.blocked.log 2>&1
BLOCK_RC=$?
set -e
[[ "$BLOCK_RC" -ne 0 ]]
LATEST_BLOCK_SESSION="$(ls -1dt logs/ssh-shadow/sessions/* | head -n1)"
grep -q 'blocked_command:wget http://example.com/a' "$LATEST_BLOCK_SESSION/termination_reason.txt"

echo "[11/12] isolation check (session write must not appear in live qgc/data)"
sshpass -p "$SSH_SHADOW_PASSWORD" ssh -tt -p "$SSH_SHADOW_HOST_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null gcs@127.0.0.1 'echo attacker-file > ~/Documents/QGroundControl/attacker_only.txt; exit'
[[ ! -f qgc/data/Documents/QGroundControl/attacker_only.txt ]]

echo "[12/12] watcher still running and bounded"
docker compose ps watcher | tee /tmp/ssh-shadow.watcher.ps.out
grep -q 'watcher' /tmp/ssh-shadow.watcher.ps.out
tail -n 200 logs/watcher/events.fs.jsonl >/tmp/ssh-shadow.watcher.tail || true

echo "All ssh-shadow verification checks passed."
