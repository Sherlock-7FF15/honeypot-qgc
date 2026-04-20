#!/usr/bin/env bash
set -euo pipefail

map_shadow_path() {
  local p="${1:-}"
  local ws="${SHADOW_WORKSPACE:-}"
  [[ -z "$p" || -z "$ws" ]] && { printf '%s' "$p"; return 0; }

  case "$p" in
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
  esac

  printf '%s' "$p"
}

map_shadow_args() {
  local out=()
  local a
  for a in "$@"; do
    case "$a" in
      /root|/root/*|/etc/ssh/sshd_config|/etc/crontab)
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
