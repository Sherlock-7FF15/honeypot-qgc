#!/usr/bin/env bash
set -euo pipefail

map_shadow_path() {
  local p="${1:-}"

  # When running inside session sandbox rootfs, absolute paths are already sandbox-local.
  if [[ "${SSH_SHADOW_SANDBOX:-0}" == "1" ]]; then
    printf '%s' "$p"
    return 0
  fi

  local ws="${SHADOW_WORKSPACE:-}"
  local login_user="${SHADOW_LOGIN_USER:-gcs}"
  [[ -z "$p" || -z "$ws" ]] && { printf '%s' "$p"; return 0; }

  case "$p" in
    /tmp|/tmp/*)
      printf '%s' "${ws}/tmp${p#/tmp}"
      return 0
      ;;
    /var/tmp|/var/tmp/*)
      printf '%s' "${ws}/var/tmp${p#/var/tmp}"
      return 0
      ;;
    /root|/root/*)
      printf '%s' "${ws}/root${p#/root}"
      return 0
      ;;
    /etc/ssh/sshd_config)
      printf '%s' "${ws}/etc/ssh/sshd_config"
      return 0
      ;;
    /etc/crontab)
      printf '%s' "${ws}/etc/crontab"
      return 0
      ;;
    "/home/${login_user}"|"/home/${login_user}"/*)
      printf '%s' "${ws}/home/${login_user}${p#/home/${login_user}}"
      return 0
      ;;
  esac

  printf '%s' "$p"
}

map_shadow_args() {
  local out=()
  local login_user="${SHADOW_LOGIN_USER:-gcs}"
  local a
  for a in "$@"; do
    case "$a" in
      /tmp|/tmp/*|/var/tmp|/var/tmp/*|/root|/root/*|/etc/ssh/sshd_config|/etc/crontab|"/home/${login_user}"|"/home/${login_user}"/*)
        out+=("$(map_shadow_path "$a")")
        ;;
      *)
        out+=("$a")
        ;;
    esac
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\n' "${out[@]}"
}

map_shadow_args_into_array() {
  local __outvar="$1"
  shift || true
  local -n __out_ref="$__outvar"
  __out_ref=()
  local a
  for a in "$@"; do
    __out_ref+=("$(map_shadow_path "$a")")
  done
}
