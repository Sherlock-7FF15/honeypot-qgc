#!/usr/bin/env bash
set -euo pipefail

LOG_DIR=/logs
QGC_STDOUT_LOG="$LOG_DIR/qgc.stdout"
X11VNC_LOG="$LOG_DIR/x11vnc.log"
NOVNC_LOG="$LOG_DIR/novnc.log"
FFMPEG_LOG="$LOG_DIR/ffmpeg-stream.log"

mkdir -p "$LOG_DIR"
exec >>"$QGC_STDOUT_LOG" 2>&1

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
ENABLE_VNC_STACK="${ENABLE_VNC_STACK:-true}"
ENABLE_RTSP_STREAM="${ENABLE_RTSP_STREAM:-auto}"
RTSP_PUBLISH_URL="${RTSP_PUBLISH_URL:-rtsp://rtsp-server:554/qgc}"
STREAM_FPS="${STREAM_FPS:-10}"

cleanup() {
  set +e
  [[ -n "${NOVNC_PID:-}" ]] && kill "$NOVNC_PID" 2>/dev/null || true
  [[ -n "${NOVNC_LOOP_PID:-}" ]] && kill "$NOVNC_LOOP_PID" 2>/dev/null || true
  [[ -n "${X11VNC_PID:-}" ]] && kill "$X11VNC_PID" 2>/dev/null || true
  [[ -n "${X11VNC_LOOP_PID:-}" ]] && kill "$X11VNC_LOOP_PID" 2>/dev/null || true
  [[ -n "${XVFB_PID:-}" ]] && kill "$XVFB_PID" 2>/dev/null || true
  [[ -n "${FFMPEG_PID:-}" ]] && kill "$FFMPEG_PID" 2>/dev/null || true
  [[ -n "${FFMPEG_LOOP_PID:-}" ]] && kill "$FFMPEG_LOOP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== ENTRYPOINT START ==="
date
id
echo "HOME=$HOME"
echo "DISPLAY_NUM=$DISPLAY_NUM"
echo "SCREEN_GEOM=$SCREEN_GEOM"
echo "VNC_BIND=$VNC_BIND VNC_PORT=$VNC_PORT NOVNC_BIND=$NOVNC_BIND NOVNC_PORT=$NOVNC_PORT ENABLE_NOVNC=$ENABLE_NOVNC ENABLE_VNC_STACK=$ENABLE_VNC_STACK ENABLE_RTSP_STREAM=$ENABLE_RTSP_STREAM RTSP_PUBLISH_URL=$RTSP_PUBLISH_URL STREAM_FPS=$STREAM_FPS"

should_enable_rtsp() {
  case "$ENABLE_RTSP_STREAM" in
    true|TRUE|1|yes|YES)
      return 0
      ;;
    false|FALSE|0|no|NO)
      return 1
      ;;
    auto|AUTO)
      getent hosts rtsp-server >/dev/null 2>&1
      ;;
    *)
      echo "WARN: unknown ENABLE_RTSP_STREAM=$ENABLE_RTSP_STREAM, treating as false"
      return 1
      ;;
  esac
}

start_x11vnc_loop() {
  (
    while true; do
      echo "=== START X11VNC ==="
      x11vnc \
        -display "$DISPLAY_NUM" \
        -rfbport "$VNC_PORT" \
        -listen "$VNC_BIND" \
        -forever \
        -shared \
        -nopw \
        -xkb \
        -o "$X11VNC_LOG"
      rc=$?
      echo "=== X11VNC EXITED rc=$rc ==="
      sleep 2
    done
  ) &
  X11VNC_LOOP_PID=$!
}

start_novnc_loop() {
  (
    while true; do
      echo "=== START noVNC/websockify ==="
      if command -v websockify >/dev/null 2>&1 && [[ -d /usr/share/novnc ]]; then
        websockify --web /usr/share/novnc "${NOVNC_BIND}:${NOVNC_PORT}" "127.0.0.1:${VNC_PORT}" >>"$NOVNC_LOG" 2>&1
      else
        NOVNC_PROXY="$(command -v novnc_proxy || true)"
        if [[ -z "$NOVNC_PROXY" ]]; then
          for c in /usr/share/novnc/utils/novnc_proxy /usr/share/novnc/utils/launch.sh; do
            if [[ -x "$c" ]]; then
              NOVNC_PROXY="$c"
              break
            fi
          done
        fi

        if [[ -z "$NOVNC_PROXY" ]]; then
          echo "ERROR: ENABLE_NOVNC=true but no novnc_proxy/websockify runtime found"
          exit 1
        fi

        "$NOVNC_PROXY" --vnc "127.0.0.1:${VNC_PORT}" --listen "${NOVNC_PORT}" >>"$NOVNC_LOG" 2>&1
      fi
      rc=$?
      echo "=== noVNC EXITED rc=$rc ==="
      sleep 2
    done
  ) &
  NOVNC_LOOP_PID=$!
}

start_ffmpeg_loop() {
  SCREEN_SIZE="${SCREEN_GEOM%x*}"
  (
    while true; do
      if ! should_enable_rtsp; then
        sleep 2
        continue
      fi

      echo "=== START FFmpeg RTSP PUBLISHER ==="
      ffmpeg \
        -nostdin \
        -f x11grab \
        -video_size "$SCREEN_SIZE" \
        -framerate "$STREAM_FPS" \
        -i "${DISPLAY_NUM}.0" \
        -an \
        -c:v libx264 \
        -preset veryfast \
        -tune zerolatency \
        -pix_fmt yuv420p \
        -f rtsp \
        -rtsp_transport tcp \
        "$RTSP_PUBLISH_URL" >>"$FFMPEG_LOG" 2>&1
      rc=$?
      echo "=== FFmpeg EXITED rc=$rc ==="
      sleep 2
    done
  ) &
  FFMPEG_LOOP_PID=$!
}

echo "=== START XVFB ==="
Xvfb "$DISPLAY_NUM" -screen 0 "$SCREEN_GEOM" -nolisten tcp &
XVFB_PID=$!
export DISPLAY="$DISPLAY_NUM"
sleep 1

if [[ "$ENABLE_VNC_STACK" == "true" ]]; then
  start_x11vnc_loop

  if [[ "$ENABLE_NOVNC" == "true" ]]; then
    start_novnc_loop
  fi
else
  echo "=== VNC STACK DISABLED (ENABLE_VNC_STACK=false) ==="
fi

if should_enable_rtsp || [[ "$ENABLE_RTSP_STREAM" =~ ^(auto|AUTO)$ ]]; then
  start_ffmpeg_loop
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
