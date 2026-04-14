#!/usr/bin/env bash
set -euo pipefail

BASE_ROOT="${1:?base_root}"
JAIL_ROOT="${2:?jail_root}"

mkdir -p "$JAIL_ROOT"

# Minimal believable workstation filesystem
mkdir -p \
  "$JAIL_ROOT/home/gcs" \
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

rsync -a --delete "$BASE_ROOT/" "$JAIL_ROOT/"

# Minimal command surface (bind-mounted via proot later) also present for realism
for f in /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/passwd /etc/group; do
  if [[ -f "$f" ]]; then
    cp -a "$f" "$JAIL_ROOT/etc/" || true
  fi
done

cp -a /opt/ssh-shadow/fakebin/. "$JAIL_ROOT/opt/ssh-shadow/fakebin/"
