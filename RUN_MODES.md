# Runtime modes

## Overview
This project now supports two optional UI exposure modes while keeping MAVLink capture in `facade`.

`facade` forwards attacker traffic to a dedicated `mavproxy` backend container (UDP/TCP) for protocol interaction.

- `vnc` profile: noVNC web access on `:6080` (interactive by default).
- `stream` profile: read-only RTSP/HLS-style viewing (`:554` RTSP and `:80` web gateway).

All new UI/stream logs are written under `./logs` and sessionized into per-session folders.

## Start modes

### 1) MAVLink only (no UI exposure)
```bash
docker compose up -d --build
```

### 2) VNC/noVNC mode
```bash
docker compose --profile vnc up -d --build
```

### 3) Read-only stream mode
Enable stream publishing from qgc and start stream stack:
```bash
ENABLE_RTSP_STREAM=true ENABLE_VNC_STACK=false docker compose --profile stream up -d --build
```

> `RTSP_PUBLISH_URL` defaults to `rtsp://rtsp-server:554/qgc` and usually doesn't need manual override.
> `ENABLE_RTSP_STREAM` defaults to `auto` inside `qgc`, which means the RTSP publisher will start automatically whenever the `rtsp-server` service is reachable.

### 4) Run both VNC and stream (optional)
```bash
ENABLE_RTSP_STREAM=true docker compose --profile vnc --profile stream up -d --build
```

## Ports
- MAVLink facade: UDP `14540`, `14550`, `14560` + TCP `14550`, `5760`
- noVNC (`vnc` profile): TCP `6080`
- RTSP (`stream` profile): TCP `554`
- Stream web gateway (`stream` profile): TCP `80`

### Browser entrypoints
- noVNC: `http://<host>:6080/vnc_auto.html`
- Read-only stream web page: `http://<host>/qgc`

## Sessionized log locations
- Facade MAVLink sessions (attacker <-> facade <-> mavproxy):
  - `logs/facade/sessions/<session_id>/events.jsonl`
- MAVProxy backend logs/state:
  - `logs/mavproxy/mavproxy.stdout.log` (filtered stdout/stderr; idle/no-link noise is dropped)
  - `logs/mavproxy/mavproxy.index.jsonl`
  - `logs/mavproxy/sessions/<session_id>/events.jsonl`
  - `logs/mavproxy/sessions/<session_id>/stats.json`
- QGC runtime logs:
  - `logs/qgc/qgc.stdout`
  - `logs/qgc/ffmpeg-stream.log` (present when `ENABLE_RTSP_STREAM=true`)
- noVNC UI sessions (`vnc` profile):
  - `logs/ui-gateway/sessions/<session_id>/events.jsonl`
  - `logs/ui-gateway/sessions/<session_id>/stats.json`
- Stream web sessions (`stream` profile):
  - `logs/stream-web/sessions/<session_id>/events.jsonl`
  - `logs/stream-web/sessions/<session_id>/stats.json`
- RTSP sessions (`stream` profile):
  - `logs/rtsp/sessions/<session_id>/events.jsonl`
  - `logs/rtsp/sessions/<session_id>/stats.json`
