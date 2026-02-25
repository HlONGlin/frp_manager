#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_DIR="${BOOTSTRAP_DIR:-/opt/frp-manager}"
SERVICE_NAME="frp-manager"
SERVICE_FILE_SYSTEMD="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_FILE_INIT="/etc/init.d/${SERVICE_NAME}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

warn() {
  printf '[%s] WARN: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

die() {
  printf '[%s] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
  exit 1
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Please run with root privileges."
  fi
}

is_safe_remove_target() {
  local target="$1"
  case "$target" in
    ""|"/"|"/root"|"/home"|"/opt"|"/usr"|"/var"|"/etc"|"/bin"|"/sbin"|"/lib"|"/lib64"|"/usr/local")
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

cleanup_parent_if_empty() {
  local target="$1"
  local parent
  parent="$(dirname "$target")"
  if ! is_safe_remove_target "$parent"; then
    return
  fi
  if [[ -d "$parent" && -z "$(ls -A "$parent" 2>/dev/null || true)" ]]; then
    rmdir "$parent" || true
  fi
}

remove_dir_force() {
  local dir="$1"
  local resolved
  if [[ -z "$dir" || ! -e "$dir" ]]; then
    return
  fi

  resolved="$(readlink -f "$dir" 2>/dev/null || echo "$dir")"
  if ! is_safe_remove_target "$resolved"; then
    warn "Skip unsafe path: $resolved"
    return
  fi

  rm -rf "$resolved"
  log "Removed directory: $resolved"
  cleanup_parent_if_empty "$resolved"
}

stop_disable_service() {
  if has_cmd systemctl && [[ -d /run/systemd/system ]]; then
    if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
      systemctl stop "$SERVICE_NAME" || true
      systemctl disable "$SERVICE_NAME" || true
    fi
  fi

  if has_cmd rc-service && [[ -f "$SERVICE_FILE_INIT" ]]; then
    rc-service "$SERVICE_NAME" stop || true
    if has_cmd rc-update; then
      rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || true
    fi
  fi

  if has_cmd service && [[ -f "$SERVICE_FILE_INIT" ]]; then
    service "$SERVICE_NAME" stop || true
    if has_cmd update-rc.d; then
      update-rc.d -f "$SERVICE_NAME" remove >/dev/null 2>&1 || true
    fi
  fi
}

remove_service_files() {
  local reloaded=0
  if [[ -f "$SERVICE_FILE_SYSTEMD" ]]; then
    rm -f "$SERVICE_FILE_SYSTEMD"
    reloaded=1
  fi

  if [[ -f "$SERVICE_FILE_INIT" ]]; then
    rm -f "$SERVICE_FILE_INIT"
  fi

  if [[ "$reloaded" -eq 1 ]] && has_cmd systemctl; then
    systemctl daemon-reload || true
  fi
}

remove_all_data_dirs() {
  remove_dir_force "$APP_DIR"

  if [[ "$BOOTSTRAP_DIR" != "$APP_DIR" ]]; then
    remove_dir_force "$BOOTSTRAP_DIR"
  fi

  remove_dir_force "/var/lib/${SERVICE_NAME}"
  remove_dir_force "/var/log/${SERVICE_NAME}"
  remove_dir_force "/etc/${SERVICE_NAME}"
}

main() {
  require_root
  stop_disable_service
  remove_service_files
  remove_all_data_dirs
  log "Uninstall complete. All controller data directories have been removed."
}

main "$@"
