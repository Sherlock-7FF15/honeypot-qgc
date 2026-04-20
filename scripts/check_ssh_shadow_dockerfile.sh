#!/usr/bin/env bash
set -euo pipefail

FILE="ssh-shadow/Dockerfile"

if [[ ! -f "$FILE" ]]; then
  echo "[check] missing $FILE" >&2
  exit 1
fi

bad_patterns=(
  "session-exec.c"
  "gcc -O2"
  "/opt/ssh-shadow/session-exec"
)

failed=0
for p in "${bad_patterns[@]}"; do
  if grep -nF "$p" "$FILE" >/dev/null 2>&1; then
    echo "[check] forbidden pattern found in $FILE: $p" >&2
    grep -nF "$p" "$FILE" >&2 || true
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo "[check] ssh-shadow Dockerfile still references removed session-exec build path." >&2
  exit 2
fi

echo "[check] OK: ssh-shadow Dockerfile has no session-exec/gcc compile path."
