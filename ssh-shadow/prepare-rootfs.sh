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

mkdir -p "$ROOTFS"/{bin,sbin,usr/bin,usr/sbin,usr/lib,usr/lib64,lib,lib64,opt/ssh-shadow,etc,dev,proc,sys,tmp,var/tmp,var/log,run,root,home,dev/pts,dev/shm}

bins=(
  /bin/bash /bin/sh /bin/dash /bin/ls /bin/cat /bin/chmod /bin/chown /bin/cp /bin/mkdir /bin/mv /bin/rm /bin/ps /bin/hostname /bin/uname /bin/pwd /bin/echo /bin/touch /bin/true /bin/false /bin/sleep
  /usr/bin/env /usr/bin/id /usr/bin/whoami /usr/bin/find /usr/bin/tee /usr/bin/wget /usr/bin/curl /usr/bin/python3 /usr/bin/ss
  /usr/bin/dirname /usr/bin/basename /usr/bin/awk /usr/bin/sed /usr/bin/flock /usr/bin/date /usr/bin/script /usr/bin/strace
  /usr/bin/tar /usr/bin/gzip /usr/bin/gunzip /usr/bin/unzip /usr/bin/zip /usr/bin/perl /usr/bin/git /usr/bin/file /usr/bin/xargs
  /usr/bin/which /usr/bin/stat /usr/bin/sha256sum /usr/bin/head /usr/bin/tail /usr/bin/tr
)

for b in "${bins[@]}"; do
  copy_bin_with_libs "$b"
done

for f in /etc/passwd /etc/group /etc/nsswitch.conf /etc/hosts /etc/resolv.conf /etc/localtime /etc/services /etc/protocols; do
  copy_file "$f"
done

mkdir -p "$ROOTFS/opt/ssh-shadow"
cp -a /opt/ssh-shadow/fakebin "$ROOTFS/opt/ssh-shadow/"
cp -a /opt/ssh-shadow/fake-root.bashrc "$ROOTFS/opt/ssh-shadow/fake-root.bashrc"

# Minimal device nodes for chroot userland.
mknod -m 666 "$ROOTFS/dev/null" c 1 3
mknod -m 666 "$ROOTFS/dev/zero" c 1 5
mknod -m 666 "$ROOTFS/dev/random" c 1 8
mknod -m 666 "$ROOTFS/dev/urandom" c 1 9
mknod -m 666 "$ROOTFS/dev/tty" c 5 0
chmod 1777 "$ROOTFS/tmp" "$ROOTFS/var/tmp" "$ROOTFS/dev/shm"

# chroot sees these as writable mount points from host namespace.
mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev/pts"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$STAMP"
