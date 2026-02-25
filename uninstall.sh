#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="frp-manager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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

ensure_systemd() {
  if ! has_cmd systemctl || [[ ! -d /run/systemd/system ]]; then
    die "This uninstaller currently supports systemd only."
  fi
}

stop_disable_service() {
  if systemctl list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    systemctl stop "$SERVICE_NAME" || true
    systemctl disable "$SERVICE_NAME" || true
  fi
}

remove_service_file() {
  if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
  fi
}

remove_project_dir() {
  local project_parent
  project_parent="$(dirname "$APP_DIR")"

  if [[ "$APP_DIR" == "/" || "$APP_DIR" == "/root" || "$APP_DIR" == "/home" ]]; then
    die "Refusing to remove unsafe directory: $APP_DIR"
  fi

  rm -rf "$APP_DIR"
  log "Removed project directory: $APP_DIR"

  if [[ -d "$project_parent" && -z "$(ls -A "$project_parent" 2>/dev/null || true)" ]]; then
    rmdir "$project_parent" || true
  fi
}

main() {
  require_root
  ensure_systemd
  stop_disable_service
  remove_service_file
  remove_project_dir
  log "Uninstall complete."
}

main "$@"
