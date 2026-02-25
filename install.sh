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
  printf '[%s] 警告: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

die() {
  printf '[%s] 错误: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
  exit 1
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请使用 root 权限运行安装脚本。"
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
  warn "未检测到 ${PYTHON_BIN}，尝试通过包管理器安装运行环境：$pm"

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
    *) die "当前包管理器不受支持，请手动安装 Python 运行环境。" ;;
  esac
}

ensure_systemd() {
  if ! has_cmd systemctl || [[ ! -d /run/systemd/system ]]; then
    die "当前安装脚本仅支持 systemd。"
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
FRP_REPORT_ONLINE_TTL=90
FRP_MANAGER_PUBLIC_URL=
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
  if ! grep -qE '^FRP_REPORT_ONLINE_TTL=' "$ENV_FILE"; then
    printf '\nFRP_REPORT_ONLINE_TTL=90\n' >>"$ENV_FILE"
  fi
  if ! grep -qE '^FRP_MANAGER_PUBLIC_URL=' "$ENV_FILE"; then
    printf '\nFRP_MANAGER_PUBLIC_URL=\n' >>"$ENV_FILE"
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

get_env_key() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return
  fi
  grep -E "^${key}=" "$ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '\r' | xargs || true
}

get_bind_host() {
  local host
  host="$(get_env_key FRP_MANAGER_HOST)"
  if [[ -z "$host" ]]; then
    host="0.0.0.0"
  fi
  echo "$host"
}

get_port() {
  local port
  port="$(get_env_key FRP_MANAGER_PORT)"
  if [[ -z "$port" ]]; then
    port="5000"
  fi
  echo "$port"
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
  local bind_host port local_ip public_ip
  bind_host="$(get_bind_host)"
  port="$(get_port)"
  local_ip="$(detect_local_ip)"
  public_ip="$(detect_public_ip)"

  echo "----------------------------------------"
  echo "服务名：${SERVICE_NAME}"
  echo "配置文件：${ENV_FILE}"
  echo "监听地址：${bind_host}"
  echo "监听端口：${port}"

  if [[ "$bind_host" != "0.0.0.0" && "$bind_host" != "::" ]]; then
    echo "访问地址：http://${bind_host}:${port}/"
    echo "首次初始化：http://${bind_host}:${port}/setup"
    echo "登录页面：http://${bind_host}:${port}/login"
    echo "----------------------------------------"
    return
  fi

  echo "内网地址：http://${local_ip}:${port}/"
  if [[ -n "$public_ip" && "$public_ip" != "$local_ip" ]]; then
    echo "公网地址：http://${public_ip}:${port}/"
  fi
  echo "首次初始化：http://${local_ip}:${port}/setup"
  echo "登录页面：http://${local_ip}:${port}/login"
  echo "----------------------------------------"
}

main() {
  require_root
  ensure_systemd
  install_python_dependencies

  if [[ ! -f "$APP_DIR/requirements.txt" ]]; then
    die "未找到 requirements.txt：${APP_DIR}"
  fi

  ensure_env_file
  install_python_venv
  write_systemd_service
  service_enable_start

  log "安装完成。"
  show_access_urls
}

main "$@"
