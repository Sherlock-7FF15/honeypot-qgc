#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
JAIL_ROOT="${2:?jail_root}"
LOGIN_USER="${3:-gcs}"

mkdir -p "$JAIL_ROOT"

# 1) First copy the prepared/sanitized base into the jail root.
if [[ "$BASE_ROOT" != "$JAIL_ROOT" ]]; then
  set +e
  rsync -a --delete "$BASE_ROOT/" "$JAIL_ROOT/"
  rc=$?
  set -e
  if [[ $rc -ne 0 && $rc -ne 23 && $rc -ne 24 ]]; then
    exit $rc
  fi
fi

# 2) Ensure minimal filesystem structure exists.
mkdir -p \
  "$JAIL_ROOT/home" \
  "$JAIL_ROOT/var/log" \
  "$JAIL_ROOT/bin" \
  "$JAIL_ROOT/usr/bin" \
  "$JAIL_ROOT/lib" \
  "$JAIL_ROOT/lib64" \
  "$JAIL_ROOT/usr/lib" \
  "$JAIL_ROOT/etc" \
  "$JAIL_ROOT/tmp" \
  "$JAIL_ROOT/dev" \
  "$JAIL_ROOT/proc" \
  "$JAIL_ROOT/run" \
  "$JAIL_ROOT/opt/ssh-shadow/fakebin"

chmod 1777 "$JAIL_ROOT/tmp"

for f in /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/passwd /etc/group; do
  if [[ -f "$f" ]]; then
    cp -a "$f" "$JAIL_ROOT/etc/" || true
  fi
done

cp -a /opt/ssh-shadow/fakebin/. "$JAIL_ROOT/opt/ssh-shadow/fakebin/" || true

# 3) Make sure source GCS data really exists.
mkdir -p "$JAIL_ROOT/home/gcs"
mkdir -p "$JAIL_ROOT/home/gcs/Documents"
mkdir -p "$JAIL_ROOT/home/gcs/.config"
mkdir -p "$JAIL_ROOT/home/gcs/.cache"
mkdir -p "$JAIL_ROOT/home/gcs/Documents/QGroundControl"

# 4) Clone gcs home content into all weak-login users.
for u in gcs admin ubuntu pi support operator guest test; do
  mkdir -p "$JAIL_ROOT/home/$u"
  if [[ "$u" != "gcs" ]]; then
    rm -rf "$JAIL_ROOT/home/$u/Documents" "$JAIL_ROOT/home/$u/.config" "$JAIL_ROOT/home/$u/.cache"
    rsync -a "$JAIL_ROOT/home/gcs/" "$JAIL_ROOT/home/$u/" || true
  fi
done

# 5) Ensure the requested login user definitely has the expected paths.
mkdir -p "$JAIL_ROOT/home/${LOGIN_USER}/Documents/QGroundControl"
mkdir -p "$JAIL_ROOT/home/${LOGIN_USER}/.config"
mkdir -p "$JAIL_ROOT/home/${LOGIN_USER}/.cache"

# 6) Ensure log paths exist in the final jail.
mkdir -p "$JAIL_ROOT/var/log/qgc"
mkdir -p "$JAIL_ROOT/var/log/mavproxy"
