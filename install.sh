#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$APP_DIR/config.env"
VENV_DIR="$APP_DIR/.venv"
SERVICE_NAME="frp-manager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="${PYTHON_BIN:-python3}"

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

detect_pkg_manager() {
  if has_cmd apt-get; then echo "apt"; return; fi
  if has_cmd dnf; then echo "dnf"; return; fi
  if has_cmd yum; then echo "yum"; return; fi
  if has_cmd zypper; then echo "zypper"; return; fi
  if has_cmd pacman; then echo "pacman"; return; fi
  if has_cmd apk; then echo "apk"; return; fi
  echo "none"
}

install_python_dependencies() {
  if has_cmd "$PYTHON_BIN"; then
    return
  fi

  local pm
  pm="$(detect_pkg_manager)"
  warn "${PYTHON_BIN} not found, trying to install runtime dependencies with package manager: $pm"

  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y python3 python3-venv python3-pip
      ;;
    dnf) dnf -y install python3 python3-pip ;;
    yum) yum -y install python3 python3-pip ;;
    zypper) zypper --non-interactive install python3 python3-pip ;;
    pacman) pacman -Sy --noconfirm python python-pip ;;
    apk) apk add --no-cache python3 py3-pip ;;
    *) die "Unsupported package manager, install python manually." ;;
  esac
}

ensure_systemd() {
  if ! has_cmd systemctl || [[ ! -d /run/systemd/system ]]; then
    die "This installer currently supports systemd only."
  fi
}

generate_secret_key() {
  "$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
}

ensure_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    local secret
    secret="$(generate_secret_key)"
    cat >"$ENV_FILE" <<EOF
FRP_MANAGER_HOST=0.0.0.0
FRP_MANAGER_PORT=5000
FLASK_DEBUG=0
FRP_SESSION_SECURE=0
FRP_MANAGER_SECRET_KEY=${secret}
FRP_STATUS_TIMEOUT=1.0
FRP_STATUS_CACHE_TTL=20
FRP_STATUS_WORKERS=16
EOF
    return
  fi

  if ! grep -qE '^FRP_MANAGER_SECRET_KEY=' "$ENV_FILE"; then
    printf '\nFRP_MANAGER_SECRET_KEY=%s\n' "$(generate_secret_key)" >>"$ENV_FILE"
  fi
  if ! grep -qE '^FRP_MANAGER_HOST=' "$ENV_FILE"; then
    printf '\nFRP_MANAGER_HOST=0.0.0.0\n' >>"$ENV_FILE"
  fi
  if ! grep -qE '^FRP_MANAGER_PORT=' "$ENV_FILE"; then
    printf '\nFRP_MANAGER_PORT=5000\n' >>"$ENV_FILE"
  fi
  if ! grep -qE '^FLASK_DEBUG=' "$ENV_FILE"; then
    printf '\nFLASK_DEBUG=0\n' >>"$ENV_FILE"
  fi
}

install_python_venv() {
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi

  "$VENV_DIR/bin/pip" install --upgrade pip wheel
  "$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"
}

write_systemd_service() {
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=FRP Manager Web Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/app.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

service_enable_start() {
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

main() {
  require_root
  ensure_systemd
  install_python_dependencies

  if [[ ! -f "$APP_DIR/requirements.txt" ]]; then
    die "requirements.txt not found in ${APP_DIR}"
  fi

  ensure_env_file
  install_python_venv
  write_systemd_service
  service_enable_start

  log "Install complete."
  log "Service: ${SERVICE_NAME}"
  log "Config: ${ENV_FILE}"
}

main "$@"
