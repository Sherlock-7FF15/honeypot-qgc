#!/usr/bin/env bash
set -euo pipefail

# Shared path virtualization helpers used by both:
# - interactive shell (via --rcfile)
# - non-interactive ssh exec (via BASH_ENV)
#
# This does not rely on user namespaces, bwrap, or proot.

__shadow_ws="${SHADOW_WORKSPACE:-}"
__shadow_user="${SHADOW_LOGIN_USER:-${LOGIN_USER:-gcs}}"

if [[ -z "${__shadow_ws}" ]]; then
  return 0 2>/dev/null || exit 0
fi

export TMPDIR="${__shadow_ws}/tmp"
mkdir -p "${TMPDIR}" "${__shadow_ws}/var/tmp" "${__shadow_ws}/root"

shadow_map_path() {
  local p="${1:-}"
  if [[ -z "$p" ]]; then
    printf '%s' "$p"
    return 0
  fi

  case "$p" in
    /tmp|/tmp/*)
      printf '%s' "${__shadow_ws}/tmp${p#/tmp}"
      return 0
      ;;
    /var/tmp|/var/tmp/*)
      printf '%s' "${__shadow_ws}/var/tmp${p#/var/tmp}"
      return 0
      ;;
    /root|/root/*)
      printf '%s' "${__shadow_ws}/root${p#/root}"
      return 0
      ;;
    /etc/ssh/sshd_config)
      printf '%s' "${__shadow_ws}/etc/ssh/sshd_config"
      return 0
      ;;
    /etc/crontab)
      printf '%s' "${__shadow_ws}/etc/crontab"
      return 0
      ;;
    "/home/${__shadow_user}"|"/home/${__shadow_user}"/*)
      printf '%s' "${__shadow_ws}/home/${__shadow_user}${p#/home/${__shadow_user}}"
      return 0
      ;;
  esac

  printf '%s' "$p"
}

__shadow_virtual_pwd() {
  local cur
  cur="$(builtin pwd)"

  case "$cur" in
    "${__shadow_ws}/tmp"| "${__shadow_ws}/tmp"/*)
      printf '/tmp%s\n' "${cur#"${__shadow_ws}/tmp"}"
      return 0
      ;;
    "${__shadow_ws}/var/tmp"| "${__shadow_ws}/var/tmp"/*)
      printf '/var/tmp%s\n' "${cur#"${__shadow_ws}/var/tmp"}"
      return 0
      ;;
    "${__shadow_ws}/root"| "${__shadow_ws}/root"/*)
      printf '/root%s\n' "${cur#"${__shadow_ws}/root"}"
      return 0
      ;;
    "${__shadow_ws}/home/${__shadow_user}"| "${__shadow_ws}/home/${__shadow_user}"/*)
      printf '/home/%s%s\n' "${__shadow_user}" "${cur#"${__shadow_ws}/home/${__shadow_user}"}"
      return 0
      ;;
  esac

  printf '%s\n' "$cur"
}

cd() {
  local target="${1:-$HOME}"
  case "$target" in
    "~"|"~/"*)
      target="/home/${__shadow_user}${target#\~}"
      ;;
  esac
  target="$(shadow_map_path "$target")"
  builtin cd "$target"
}

pwd() {
  __shadow_virtual_pwd
}
