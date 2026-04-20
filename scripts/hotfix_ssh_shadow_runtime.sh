#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${1:-ssh-shadow}"

echo "[hotfix] patching container: ${CONTAINER}"

docker exec -u 0 "${CONTAINER}" /bin/bash -lc '
set -euo pipefail

if ! command -v sudo >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends sudo
  rm -rf /var/lib/apt/lists/*
fi

cat > /opt/ssh-shadow/root-session-launch.sh <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--selftest" ]]; then
  ws="${2:-/opt/ssh-shadow/session-rootfs}"
  [[ -d "$ws" ]] || { echo "[ssh-shadow] selftest failed: missing rootfs $ws" >&2; exit 1; }
  exec chroot "$ws" /bin/bash -lc "true"
fi
WORKSPACE="${1:?workspace}"
LOGIN_USER="${2:?login_user}"
shift 2
exec chroot --userspec="${LOGIN_USER}" "$WORKSPACE" \
  /usr/bin/env -i \
    HOME="/home/${LOGIN_USER}" \
    USER="${LOGIN_USER}" \
    LOGNAME="${LOGIN_USER}" \
    PATH="/opt/ssh-shadow/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SSH_SHADOW_SANDBOX=1 \
    HONEYPOT_HOSTNAME="${HONEYPOT_HOSTNAME:-gcs-shadow}" \
    "$@"
EOF

cat > /opt/ssh-shadow/sandbox-run.sh <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="${1:?workspace}"
SESSION_DIR="${2:?session_dir}"
LOGIN_USER="${3:?login_user}"
shift 3
if /usr/bin/sudo -n true >/dev/null 2>&1; then
  exec /usr/bin/sudo -n /opt/ssh-shadow/root-session-launch.sh "$WORKSPACE" "$LOGIN_USER" "$@"
fi
echo "[ssh-shadow] WARN: sudo elevation unavailable (likely nosuid/no-new-privileges); using direct session mode" >&2
cd "/home/${LOGIN_USER}" 2>/dev/null || true
exec env SSH_SHADOW_SANDBOX=0 "$@"
EOF

chmod +x /opt/ssh-shadow/root-session-launch.sh /opt/ssh-shadow/sandbox-run.sh

mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/ssh-shadow-session-launch <<'"'"'EOF'"'"'
Defaults:%honeypot !requiretty
%honeypot ALL=(root) NOPASSWD: /opt/ssh-shadow/root-session-launch.sh
EOF
chmod 0440 /etc/sudoers.d/ssh-shadow-session-launch

if [[ -x /opt/ssh-shadow/prepare-rootfs.sh ]]; then
  /opt/ssh-shadow/prepare-rootfs.sh /opt/ssh-shadow/session-rootfs || true
fi
/opt/ssh-shadow/root-session-launch.sh --selftest /opt/ssh-shadow/session-rootfs || true
'

echo "[hotfix] restarting ${CONTAINER}"
docker restart "${CONTAINER}" >/dev/null
echo "[hotfix] done"
