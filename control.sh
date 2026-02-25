#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

resolve_script_path() {
  if [[ -n "${BASH_SOURCE[0]-}" ]]; then
    printf '%s\n' "${BASH_SOURCE[0]}"
    return
  fi
  if [[ -n "${0-}" ]]; then
    printf '%s\n' "$0"
    return
  fi
  printf '.\n'
}

SCRIPT_PATH="$(resolve_script_path)"
if [[ "$SCRIPT_PATH" == "bash" || "$SCRIPT_PATH" == "-bash" || "$SCRIPT_PATH" == "sh" || "$SCRIPT_PATH" == "-sh" ]]; then
  SCRIPT_PATH="."
fi
APP_DIR="$(cd "$(dirname "$SCRIPT_PATH")" 2>/dev/null && pwd || pwd)"
ENV_FILE="$APP_DIR/config.env"
SERVICE_NAME="frp-manager"
SERVICE_FILE_SYSTEMD="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_FILE_OPENRC="/etc/init.d/${SERVICE_NAME}"
SERVICE_FILE_SYSV="/etc/init.d/${SERVICE_NAME}"
PYTHON_BIN="${PYTHON_BIN:-}"
REPO_URL="${REPO_URL:-https://github.com/HlONGlin/frp_manager.git}"
BRANCH="${BRANCH:-main}"
BOOTSTRAP_DIR="${BOOTSTRAP_DIR:-/opt/frp-manager}"
BOOTSTRAP_FORCE_UPDATE="${BOOTSTRAP_FORCE_UPDATE:-0}"

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

detect_pkg_manager() {
  if has_cmd apt-get; then echo "apt"; return; fi
  if has_cmd dnf; then echo "dnf"; return; fi
  if has_cmd yum; then echo "yum"; return; fi
  if has_cmd zypper; then echo "zypper"; return; fi
  if has_cmd pacman; then echo "pacman"; return; fi
  if has_cmd apk; then echo "apk"; return; fi
  echo "none"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Please run with root privileges: sudo bash control.sh"
  fi
}

ensure_git() {
  if has_cmd git; then
    return
  fi

  local pm
  pm="$(detect_pkg_manager)"
  warn "git not found, trying to install with package manager: $pm"

  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y git
      ;;
    dnf) dnf -y install git ;;
    yum) yum -y install git ;;
    zypper) zypper --non-interactive install git ;;
    pacman) pacman -Sy --noconfirm git ;;
    apk) apk add --no-cache git ;;
    *) die "git not found, and package manager is unsupported. Install git manually first." ;;
  esac
}

repo_has_local_changes() {
  local repo_dir="$1"
  local status_output=""
  if ! status_output="$(git -C "$repo_dir" status --porcelain 2>/dev/null)"; then
    return 2
  fi
  [[ -n "$status_output" ]]
}

sync_repo_to_origin() {
  local repo_dir="$1"
  local backup_env=""
  local backup_config_file=""
  local synced=0

  if [[ "$BOOTSTRAP_FORCE_UPDATE" == "1" && -f "$repo_dir/config.env" ]]; then
    backup_env="$(mktemp 2>/dev/null || true)"
    if [[ -n "$backup_env" ]]; then
      cp -f "$repo_dir/config.env" "$backup_env"
    fi
  fi

  if [[ "$BOOTSTRAP_FORCE_UPDATE" == "1" && -f "$repo_dir/frp_manager/config.json" ]]; then
    backup_config_file="$(mktemp 2>/dev/null || true)"
    if [[ -n "$backup_config_file" ]]; then
      cp -f "$repo_dir/frp_manager/config.json" "$backup_config_file"
    fi
  fi

  if git -C "$repo_dir" fetch origin "$BRANCH" && \
     (git -C "$repo_dir" checkout -f "$BRANCH" || git -C "$repo_dir" checkout -f -B "$BRANCH" "origin/$BRANCH") && \
     git -C "$repo_dir" reset --hard "origin/$BRANCH"; then
    synced=1
  fi

  if [[ -n "$backup_env" && -f "$backup_env" ]]; then
    cp -f "$backup_env" "$repo_dir/config.env"
    rm -f "$backup_env"
  fi

  if [[ -n "$backup_config_file" && -f "$backup_config_file" ]]; then
    mkdir -p "$repo_dir/frp_manager"
    cp -f "$backup_config_file" "$repo_dir/frp_manager/config.json"
    rm -f "$backup_config_file"
  fi

  [[ "$synced" -eq 1 ]]
}

is_repo_ready() {
  local repo_dir="$1"
  [[ -f "$repo_dir/control.sh" && -f "$repo_dir/install.sh" && -f "$repo_dir/uninstall.sh" && -f "$repo_dir/app.py" ]]
}

is_bootstrap_mode() {
  local app_dir_real boot_dir_real
  app_dir_real="$(cd "${APP_DIR}" 2>/dev/null && pwd || echo "${APP_DIR}")"
  boot_dir_real="$(cd "${BOOTSTRAP_DIR}" 2>/dev/null && pwd || echo "${BOOTSTRAP_DIR}")"

  if [[ "$app_dir_real" != "$boot_dir_real" ]]; then
    return 0
  fi
  if ! is_repo_ready "$APP_DIR"; then
    return 0
  fi
  return 1
}

sync_repo_to_bootstrap_dir() {
  require_root
  ensure_git

  log "Bootstrap mode: using repository directory $BOOTSTRAP_DIR"
  log "Syncing repository to $BOOTSTRAP_DIR (branch: $BRANCH)"

  mkdir -p "$(dirname "$BOOTSTRAP_DIR")"
  if [[ -d "$BOOTSTRAP_DIR/.git" ]]; then
    local repo_state=1
    if repo_has_local_changes "$BOOTSTRAP_DIR"; then
      repo_state=0
    else
      repo_state="$?"
    fi

    if [[ "$repo_state" -eq 2 ]]; then
      die "Unable to inspect repository state for $BOOTSTRAP_DIR."
    elif [[ "$repo_state" -eq 0 && "$BOOTSTRAP_FORCE_UPDATE" != "1" ]]; then
      BOOTSTRAP_FORCE_UPDATE="1"
      warn "Local changes detected, auto-confirm force sync with preservation of config.env and frp_manager/ data."
    fi

    if ! sync_repo_to_origin "$BOOTSTRAP_DIR"; then
      die "Repository sync failed."
    fi
  else
    if [[ -e "$BOOTSTRAP_DIR" ]] && [[ -n "$(ls -A "$BOOTSTRAP_DIR" 2>/dev/null || true)" ]]; then
      die "Bootstrap target directory is not empty: $BOOTSTRAP_DIR"
    fi
    git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$BOOTSTRAP_DIR"
  fi

  chmod +x "$BOOTSTRAP_DIR/control.sh" "$BOOTSTRAP_DIR/install.sh" "$BOOTSTRAP_DIR/uninstall.sh" || true
}

detect_service_mgr() {
  if has_cmd systemctl && [[ -d /run/systemd/system ]]; then
    echo "systemd"
    return
  fi
  if has_cmd rc-service; then
    echo "openrc"
    return
  fi
  if has_cmd service; then
    echo "sysv"
    return
  fi
  echo "none"
}

SERVICE_MGR="$(detect_service_mgr)"

service_restart() {
  case "$SERVICE_MGR" in
    systemd) systemctl restart "$SERVICE_NAME" ;;
    openrc) rc-service "$SERVICE_NAME" restart ;;
    sysv) service "$SERVICE_NAME" restart ;;
    *) die "No supported service manager found." ;;
  esac
}

service_stop() {
  case "$SERVICE_MGR" in
    systemd) systemctl stop "$SERVICE_NAME" ;;
    openrc) rc-service "$SERVICE_NAME" stop ;;
    sysv) service "$SERVICE_NAME" stop ;;
    *) die "No supported service manager found." ;;
  esac
}

service_status() {
  case "$SERVICE_MGR" in
    systemd) systemctl status "$SERVICE_NAME" --no-pager ;;
    openrc) rc-service "$SERVICE_NAME" status ;;
    sysv) service "$SERVICE_NAME" status ;;
    *) die "No supported service manager found." ;;
  esac
}

service_is_running() {
  case "$SERVICE_MGR" in
    systemd) systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1 ;;
    openrc) rc-service "$SERVICE_NAME" status >/dev/null 2>&1 ;;
    sysv) service "$SERVICE_NAME" status >/dev/null 2>&1 ;;
    *) return 2 ;;
  esac
}

project_status_text() {
  if service_is_running; then
    echo "running"
    return
  fi

  if [[ "$?" -ne 1 ]]; then
    echo "unknown"
    return
  fi

  if is_bootstrap_mode; then
    echo "not deployed"
  else
    echo "stopped"
  fi
}

pick_python_bin() {
  if [[ -n "$PYTHON_BIN" ]] && has_cmd "$PYTHON_BIN"; then
    echo "$PYTHON_BIN"
    return
  fi
  if [[ -x "$APP_DIR/.venv/bin/python" ]]; then
    echo "$APP_DIR/.venv/bin/python"
    return
  fi
  if has_cmd python3; then
    echo "python3"
    return
  fi
  if has_cmd python; then
    echo "python"
    return
  fi
  die "python is not available"
}

set_env_key() {
  local key="$1"
  local value="$2"
  touch "$ENV_FILE"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

get_env_key() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return
  fi
  grep -E "^${key}=" "$ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '\r' | xargs || true
}

get_port() {
  local port
  port="$(get_env_key FRP_MANAGER_PORT)"
  if [[ -z "$port" ]]; then
    port="5000"
  fi
  echo "$port"
}

is_valid_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 ))
}

is_port_available() {
  local port="$1"
  local py
  py="$(pick_python_bin)"
  "$py" - <<PY
import socket
import sys
port = int(${port})
s = socket.socket()
try:
    s.bind(("0.0.0.0", port))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
}

detect_local_ip() {
  local ip=""
  if has_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}')"
  fi
  if [[ -z "$ip" ]] && has_cmd hostname; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  echo "${ip:-127.0.0.1}"
}

detect_public_ip() {
  if ! has_cmd curl; then
    return
  fi
  curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true
}

show_access_urls() {
  local port local_ip public_ip
  port="$(get_port)"
  local_ip="$(detect_local_ip)"
  public_ip="$(detect_public_ip)"

  echo "----------------------------------------"
  echo "Service: $SERVICE_NAME"
  echo "Port: $port"
  echo "Local URL:  http://${local_ip}:${port}/"
  if [[ -n "$public_ip" && "$public_ip" != "$local_ip" ]]; then
    echo "Public URL: http://${public_ip}:${port}/"
  fi
  echo "First setup: http://${local_ip}:${port}/setup"
  echo "Login page:  http://${local_ip}:${port}/login"
  echo "----------------------------------------"
}

show_logs() {
  case "$SERVICE_MGR" in
    systemd)
      journalctl -u "$SERVICE_NAME" -n 120 --no-pager
      ;;
    openrc|sysv)
      warn "Log tail via control script is not implemented for this service manager."
      ;;
    *)
      warn "No supported service manager found."
      ;;
  esac
}

reset_admin_credentials() {
  require_root
  local py
  py="$(pick_python_bin)"

  "$py" - <<PY
import os
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import clear_admin_credentials
clear_admin_credentials()
print("Admin credentials reset. Open /setup to initialize again.")
PY

  if service_is_running; then
    service_restart
  fi
}

show_menu() {
  local bootstrap_mode=0
  local status_text
  if is_bootstrap_mode; then
    bootstrap_mode=1
  fi
  status_text="$(project_status_text)"

  echo "=================================="
  echo " FRP Manager Controller"
  echo " Status: $status_text"
  echo "=================================="
  if [[ "$bootstrap_mode" -eq 1 ]]; then
    echo "1) Deploy environment (clone + install)"
  else
    echo "1) Install or update"
  fi
  echo "2) Uninstall service and remove files"
  echo "3) Restart service"
  echo "4) Stop service"
  echo "5) Show service status and access URLs"
  echo "6) Change panel port"
  echo "7) Show access URLs only"
  echo "8) Show recent logs"
  echo "9) Reset admin credentials (re-run setup)"
  echo "0) Exit"
  echo "----------------------------------"
}

prompt_choice() {
  local __var_name="$1"
  local prompt="$2"
  local input=""

  if [[ -r /dev/tty ]]; then
    if ! read -r -p "$prompt" input </dev/tty; then
      return 1
    fi
  else
    if ! read -r -p "$prompt" input; then
      return 1
    fi
  fi
  printf -v "$__var_name" '%s' "$input"
}

require_deployed_env() {
  if is_bootstrap_mode; then
    warn "Current run is bootstrap mode, please run option 1 first."
    return 1
  fi
  return 0
}

do_install() {
  require_root

  if is_bootstrap_mode; then
    sync_repo_to_bootstrap_dir
    bash "$BOOTSTRAP_DIR/install.sh"
    exec bash "$BOOTSTRAP_DIR/control.sh"
  fi

  bash "$APP_DIR/install.sh"
  show_access_urls
}

do_uninstall() {
  require_root
  local confirm=""
  if ! prompt_choice confirm "Confirm uninstall and remove all project files? [y/N]: "; then
    warn "Input not received."
    return
  fi
  confirm="$(printf '%s' "$confirm" | tr '[:upper:]' '[:lower:]')"
  if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo "Canceled."
    return
  fi
  bash "$APP_DIR/uninstall.sh"
  echo "Uninstalled."
  exit 0
}

do_restart() {
  require_root
  service_restart
  echo "Service restarted."
  show_access_urls
}

do_stop() {
  require_root
  service_stop
  echo "Service stopped."
}

do_status() {
  service_status || true
  show_access_urls
}

do_change_port() {
  require_root

  local current_port new_port
  current_port="$(get_port)"

  if ! prompt_choice new_port "Input new panel port (1-65535, 0 to cancel): "; then
    warn "Input not received."
    return
  fi
  new_port="$(printf '%s' "$new_port" | tr -d '[:space:]')"

  if [[ "$new_port" == "0" ]]; then
    echo "Canceled."
    return
  fi
  if ! is_valid_port "$new_port"; then
    warn "Invalid port."
    return
  fi
  if [[ "$new_port" == "$current_port" ]]; then
    echo "Port unchanged: $new_port"
    return
  fi
  if ! is_port_available "$new_port"; then
    warn "Port is already in use: $new_port"
    return
  fi

  set_env_key "FRP_MANAGER_PORT" "$new_port"
  service_restart
  echo "Port changed to $new_port"
  show_access_urls
}

main() {
  if is_bootstrap_mode && is_repo_ready "$BOOTSTRAP_DIR"; then
    log "Detected deployed repository, switching to local controller: $BOOTSTRAP_DIR/control.sh"
    exec bash "$BOOTSTRAP_DIR/control.sh" "$@"
  fi

  while true; do
    show_menu
    local choice=""
    if ! prompt_choice choice "Select: "; then
      warn "Input not received, run in an interactive terminal."
      exit 1
    fi

    case "$choice" in
      1) do_install ;;
      2)
        if require_deployed_env; then
          do_uninstall
        fi
        ;;
      3)
        if require_deployed_env; then
          do_restart
        fi
        ;;
      4)
        if require_deployed_env; then
          do_stop
        fi
        ;;
      5)
        if require_deployed_env; then
          do_status
        fi
        ;;
      6)
        if require_deployed_env; then
          do_change_port
        fi
        ;;
      7)
        if require_deployed_env; then
          show_access_urls
        fi
        ;;
      8)
        if require_deployed_env; then
          show_logs
        fi
        ;;
      9)
        if require_deployed_env; then
          reset_admin_credentials
        fi
        ;;
      0) exit 0 ;;
      *) echo "Invalid option." ;;
    esac
    echo
  done
}

main "$@"
