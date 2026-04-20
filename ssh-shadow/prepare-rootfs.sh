#!/usr/bin/env bash
set -euo pipefail

ROOTFS="${1:-/opt/ssh-shadow/session-rootfs}"
STAMP="${ROOTFS}/.prepared"

if [[ -f "$STAMP" ]]; then
  exit 0
fi

mkdir -p "$ROOTFS"

copy_file() {
  local src="$1"
  [[ -e "$src" ]] || return 0
  mkdir -p "$ROOTFS$(dirname "$src")"
  cp -L --preserve=mode,timestamps "$src" "$ROOTFS$src"
}

copy_bin_with_libs() {
  local bin="$1"
  [[ -x "$bin" ]] || return 0
  copy_file "$bin"
  while IFS= read -r lib; do
    [[ -n "$lib" ]] || continue
    copy_file "$lib"
  done < <(ldd "$bin" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u)
}

mkdir -p \
  "$ROOTFS"/{bin,sbin,usr/bin,usr/sbin,usr/lib,usr/lib64,lib,lib64,opt/ssh-shadow,etc,dev,proc,sys,tmp,var/tmp,var/log,run,root,home}

bins=(
  /bin/bash /bin/sh /bin/ls /bin/cat /bin/chmod /bin/chown /bin/cp /bin/mkdir /bin/mv /bin/rm /bin/ps /bin/hostname /bin/uname
  /usr/bin/env /usr/bin/id /usr/bin/whoami /usr/bin/find /usr/bin/tee /usr/bin/wget /usr/bin/curl /usr/bin/python3 /usr/bin/ss
  /usr/bin/dirname /usr/bin/awk /usr/bin/sed /usr/bin/flock /usr/bin/date /usr/bin/script /usr/bin/strace
  /usr/bin/tar /usr/bin/gzip /usr/bin/gunzip /usr/bin/unzip /usr/bin/zip /usr/bin/perl /usr/bin/git /usr/bin/file
)

for b in "${bins[@]}"; do
  copy_bin_with_libs "$b"
done

for f in /etc/passwd /etc/group /etc/nsswitch.conf /etc/hosts /etc/resolv.conf /etc/localtime; do
  copy_file "$f"
done

mkdir -p "$ROOTFS/opt/ssh-shadow"
cp -a /opt/ssh-shadow/fakebin "$ROOTFS/opt/ssh-shadow/"
cp -a /opt/ssh-shadow/fake-root.bashrc "$ROOTFS/opt/ssh-shadow/fake-root.bashrc"

# Minimal /dev surfaces for shell/tooling.
touch "$ROOTFS/dev/null" "$ROOTFS/dev/zero" "$ROOTFS/dev/random" "$ROOTFS/dev/urandom" "$ROOTFS/dev/tty"
chmod 666 "$ROOTFS/dev/null" "$ROOTFS/dev/zero" "$ROOTFS/dev/random" "$ROOTFS/dev/urandom" || true
chmod 666 "$ROOTFS/dev/tty" || true
chmod 1777 "$ROOTFS/tmp" "$ROOTFS/var/tmp"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$STAMP"
