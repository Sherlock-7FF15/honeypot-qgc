#!/usr/bin/env bash
set -euo pipefail

exec >> /logs/qgc.stdout 2>&1

export HOME=/data
export XDG_CONFIG_HOME=/data/.config
export XDG_CACHE_HOME=/data/.cache
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

DISPLAY_NUM="${DISPLAY_NUM:-:99}"
SCREEN_GEOM="${SCREEN_GEOM:-1280x720x24}"
VNC_BIND="${VNC_BIND:-0.0.0.0}"
VNC_PORT="${VNC_PORT:-5900}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
NOVNC_BIND="${NOVNC_BIND:-0.0.0.0}"
ENABLE_NOVNC="${ENABLE_NOVNC:-true}"

cleanup() {
  set +e
  [[ -n "${NOVNC_PID:-}" ]] && kill "$NOVNC_PID" 2>/dev/null || true
  [[ -n "${X11VNC_PID:-}" ]] && kill "$X11VNC_PID" 2>/dev/null || true
  [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== ENTRYPOINT START ==="
date
id
echo "HOME=$HOME"
echo "DISPLAY_NUM=$DISPLAY_NUM"
echo "SCREEN_GEOM=$SCREEN_GEOM"
echo "VNC_BIND=$VNC_BIND VNC_PORT=$VNC_PORT NOVNC_BIND=$NOVNC_BIND NOVNC_PORT=$NOVNC_PORT ENABLE_NOVNC=$ENABLE_NOVNC"

echo "=== START XVFB ==="
Xvfb "$DISPLAY_NUM" -screen 0 "$SCREEN_GEOM" -nolisten tcp &
XVFB_PID=$!
export DISPLAY="$DISPLAY_NUM"
sleep 1

echo "=== START X11VNC ==="
x11vnc -display "$DISPLAY_NUM" -rfbport "$VNC_PORT" -listen "$VNC_BIND" -forever -shared -nopw -xkb -o /logs/x11vnc.log &
X11VNC_PID=$!

if [[ "$ENABLE_NOVNC" == "true" ]]; then
  echo "=== START noVNC ==="
  NOVNC_PROXY="$(command -v novnc_proxy || true)"
  if [[ -z "$NOVNC_PROXY" ]]; then
    for c in /usr/share/novnc/utils/novnc_proxy /usr/share/novnc/utils/launch.sh; do
      if [[ -x "$c" ]]; then
        NOVNC_PROXY="$c"
        break
      fi
    done
  fi

  if [[ -n "$NOVNC_PROXY" ]]; then
    "$NOVNC_PROXY" --vnc "127.0.0.1:${VNC_PORT}" --listen "${NOVNC_BIND}:${NOVNC_PORT}" >/logs/novnc.log 2>&1 &
    NOVNC_PID=$!
  elif command -v websockify >/dev/null 2>&1 && [[ -d /usr/share/novnc ]]; then
    websockify --web /usr/share/novnc "${NOVNC_BIND}:${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" >/logs/novnc.log 2>&1 &
    NOVNC_PID=$!
  else
    echo "ERROR: ENABLE_NOVNC=true but no novnc_proxy/websockify runtime found"
    exit 1
  fi
fi

while true; do
  echo "=== LAUNCH QGC ==="
  date
  /opt/qgc/usr/bin/QGroundControl
  rc=$?

  echo "=== QGC EXITED rc=$rc ==="
  date
  sleep 2
done
