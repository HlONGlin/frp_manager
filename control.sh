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
BACKUP_DIR="$APP_DIR/backups"
SERVICE_NAME="frp-manager"
SERVICE_FILE_SYSTEMD="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_FILE_OPENRC="/etc/init.d/${SERVICE_NAME}"
SERVICE_FILE_SYSV="/etc/init.d/${SERVICE_NAME}"
PYTHON_BIN="${PYTHON_BIN:-}"
REPO_URL="${REPO_URL:-https://github.com/HlONGlin/frp_manager.git}"
BRANCH="${BRANCH:-main}"
BOOTSTRAP_DIR="${BOOTSTRAP_DIR:-/opt/frp-manager}"
BOOTSTRAP_FORCE_UPDATE="${BOOTSTRAP_FORCE_UPDATE:-0}"
KEEP_LOCAL_DB_ON_UPDATE="${KEEP_LOCAL_DB_ON_UPDATE:-0}"

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
    die "请使用 root 权限运行：sudo bash control.sh"
  fi
}

ensure_git() {
  if has_cmd git; then
    return
  fi

  local pm
  pm="$(detect_pkg_manager)"
  warn "未检测到 git，尝试通过包管理器安装：$pm"

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
    *) die "未检测到 git，且当前包管理器不受支持，请先手动安装 git。" ;;
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
  local backup_config_for_auth=""
  local backup_config_file=""
  local synced=0

  if [[ "$BOOTSTRAP_FORCE_UPDATE" == "1" && -f "$repo_dir/config.env" ]]; then
    backup_env="$(mktemp 2>/dev/null || true)"
    if [[ -n "$backup_env" ]]; then
      cp -f "$repo_dir/config.env" "$backup_env"
    fi
  fi

  if [[ "$BOOTSTRAP_FORCE_UPDATE" == "1" && "$KEEP_LOCAL_DB_ON_UPDATE" == "1" && -f "$repo_dir/frp_manager/config.json" ]]; then
    backup_config_file="$(mktemp 2>/dev/null || true)"
    if [[ -n "$backup_config_file" ]]; then
      cp -f "$repo_dir/frp_manager/config.json" "$backup_config_file"
    fi
  fi

  if [[ "$BOOTSTRAP_FORCE_UPDATE" == "1" && -f "$repo_dir/frp_manager/config.json" ]]; then
    backup_config_for_auth="$(mktemp 2>/dev/null || true)"
    if [[ -n "$backup_config_for_auth" ]]; then
      cp -f "$repo_dir/frp_manager/config.json" "$backup_config_for_auth"
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
  elif [[ -n "$backup_config_for_auth" && -f "$backup_config_for_auth" && -f "$repo_dir/frp_manager/config.json" ]]; then
    local python_bin
    python_bin=""
    if [[ -x "$repo_dir/.venv/bin/python" ]]; then
      python_bin="$repo_dir/.venv/bin/python"
    elif has_cmd python3; then
      python_bin="python3"
    elif has_cmd python; then
      python_bin="python"
    fi
    if [[ -n "$python_bin" ]]; then
      "$python_bin" - "$backup_config_for_auth" "$repo_dir/frp_manager/config.json" <<'PY'
import json
import sys

old_path, new_path = sys.argv[1], sys.argv[2]

try:
    with open(old_path, 'r', encoding='utf-8') as f:
        old_data = json.load(f)
except Exception:
    old_data = {}

try:
    with open(new_path, 'r', encoding='utf-8') as f:
        new_data = json.load(f)
except Exception:
    new_data = {}

old_auth = old_data.get('auth') if isinstance(old_data, dict) else None
if isinstance(old_auth, dict):
    initialized = bool(old_auth.get('initialized'))
    admin_username = str(old_auth.get('admin_username', '')).strip()
    password_hash = str(old_auth.get('password_hash', '')).strip()
    if initialized and admin_username and password_hash and isinstance(new_data, dict):
        new_data['auth'] = {
            'initialized': True,
            'admin_username': admin_username,
            'password_hash': password_hash,
        }
        with open(new_path, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, ensure_ascii=False, indent=4)
PY
    else
      warn "未检测到 Python，无法自动保留管理员账号配置。"
    fi
  fi

  if [[ -n "$backup_config_for_auth" && -f "$backup_config_for_auth" ]]; then
    rm -f "$backup_config_for_auth"
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

  log "引导模式：使用仓库目录 $BOOTSTRAP_DIR"
  log "正在同步仓库到 $BOOTSTRAP_DIR（分支：$BRANCH）"

  mkdir -p "$(dirname "$BOOTSTRAP_DIR")"
  if [[ -d "$BOOTSTRAP_DIR/.git" ]]; then
    local repo_state=1
    if repo_has_local_changes "$BOOTSTRAP_DIR"; then
      repo_state=0
    else
      repo_state="$?"
    fi

    if [[ "$repo_state" -eq 2 ]]; then
      die "无法检查仓库状态：$BOOTSTRAP_DIR"
    elif [[ "$repo_state" -eq 0 && "$BOOTSTRAP_FORCE_UPDATE" != "1" ]]; then
      BOOTSTRAP_FORCE_UPDATE="1"
      if [[ "$KEEP_LOCAL_DB_ON_UPDATE" == "1" ]]; then
        warn "检测到本地改动，已自动开启强制同步（保留 config.env 与 frp_manager/config.json）。"
      else
        warn "检测到本地改动，已自动开启强制同步（保留 config.env，并以 GitHub 最新 config.json 覆盖本地数据库；管理员账号会自动保留）。"
      fi
    fi

    if ! sync_repo_to_origin "$BOOTSTRAP_DIR"; then
      die "仓库同步失败。"
    fi
  else
    if [[ -e "$BOOTSTRAP_DIR" ]] && [[ -n "$(ls -A "$BOOTSTRAP_DIR" 2>/dev/null || true)" ]]; then
      die "引导目标目录非空：$BOOTSTRAP_DIR"
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
    *) die "未找到受支持的服务管理器。" ;;
  esac
}

service_stop() {
  case "$SERVICE_MGR" in
    systemd) systemctl stop "$SERVICE_NAME" ;;
    openrc) rc-service "$SERVICE_NAME" stop ;;
    sysv) service "$SERVICE_NAME" stop ;;
    *) die "未找到受支持的服务管理器。" ;;
  esac
}

service_status() {
  case "$SERVICE_MGR" in
    systemd) systemctl status "$SERVICE_NAME" --no-pager ;;
    openrc) rc-service "$SERVICE_NAME" status ;;
    sysv) service "$SERVICE_NAME" status ;;
    *) die "未找到受支持的服务管理器。" ;;
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
    echo "运行中"
    return
  fi

  if [[ "$?" -ne 1 ]]; then
    echo "未知"
    return
  fi

  if is_bootstrap_mode; then
    echo "未部署"
  else
    echo "已停止"
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
  die "未检测到 Python 运行环境。"
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
  echo "服务名：$SERVICE_NAME"
  echo "端口：$port"
  echo "内网地址：http://${local_ip}:${port}/"
  if [[ -n "$public_ip" && "$public_ip" != "$local_ip" ]]; then
    echo "公网地址：http://${public_ip}:${port}/"
  fi
  echo "首次初始化：http://${local_ip}:${port}/setup"
  echo "登录页面：http://${local_ip}:${port}/login"
  echo "----------------------------------------"
}

get_manager_base_url_for_agent() {
  local public_url port local_ip
  public_url="$(get_env_key FRP_MANAGER_PUBLIC_URL)"
  if [[ -n "$public_url" ]]; then
    echo "${public_url%%,*}" | xargs
    return
  fi

  port="$(get_port)"
  local_ip="$(detect_local_ip)"
  echo "http://${local_ip}:${port}"
}

shell_single_quote() {
  local text="${1:-}"
  text="$(printf '%s' "$text" | sed "s/'/'\"'\"'/g")"
  printf "'%s'" "$text"
}

show_logs() {
  case "$SERVICE_MGR" in
    systemd)
      journalctl -u "$SERVICE_NAME" -n 120 --no-pager
      ;;
    openrc|sysv)
      warn "当前服务管理器暂不支持通过控制脚本查看日志。"
      ;;
    *)
      warn "未找到受支持的服务管理器。"
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
print("管理员账号已重置，请重新访问 /setup 完成初始化。")
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
  echo " FRP 管理面板控制器"
  echo " 当前状态：$status_text"
  echo "=================================="
  if [[ "$bootstrap_mode" -eq 1 ]]; then
    echo "1) 部署环境（拉取仓库并安装）"
  else
    echo "1) 安装或更新"
  fi
  echo "2) 彻底卸载（删除服务、数据与目录）"
  echo "3) 重启服务"
  echo "4) 停止服务"
  echo "5) 查看服务状态与访问地址"
  echo "6) 修改面板端口"
  echo "7) 仅显示访问地址"
  echo "8) 查看最近日志"
  echo "9) 重置管理员账号（重新初始化）"
  echo "10) Agent 编排控制"
  echo "11) 备份配置"
  echo "12) 恢复配置"
  echo "13) 查看最新备份详情"
  echo "0) 退出"
  echo "----------------------------------"
}

backup_config_files() {
  require_root
  mkdir -p "$BACKUP_DIR"

  local ts archive_file config_file tmp_dir
  ts="$(date '+%Y%m%d_%H%M%S')"
  archive_file="$BACKUP_DIR/frp_manager_backup_${ts}.tar.gz"
  config_file="$APP_DIR/frp_manager/config.json"

  if [[ ! -f "$ENV_FILE" && ! -f "$config_file" ]]; then
    warn "未找到可备份的配置文件。"
    return
  fi

  tmp_dir="$(mktemp -d)"
  if [[ -f "$ENV_FILE" ]]; then
    cp -f "$ENV_FILE" "$tmp_dir/config.env"
  fi
  if [[ -f "$config_file" ]]; then
    mkdir -p "$tmp_dir/frp_manager"
    cp -f "$config_file" "$tmp_dir/frp_manager/config.json"
  fi

  if ! tar -czf "$archive_file" -C "$tmp_dir" .; then
    rm -rf "$tmp_dir"
    warn "备份失败。"
    return
  fi
  rm -rf "$tmp_dir"

  echo "备份完成：$archive_file"
}

list_backups() {
  if [[ ! -d "$BACKUP_DIR" ]]; then
    echo "暂无备份文件。"
    return
  fi
  ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "暂无备份文件。"
}

restore_config_files() {
  require_root
  mkdir -p "$BACKUP_DIR"

  local archive_file input
  echo "可用备份："
  list_backups

  if ! prompt_choice input "请输入要恢复的备份文件名（仅文件名），或输入 0 取消："; then
    warn "未读取到输入。"
    return
  fi

  input="$(printf '%s' "$input" | xargs)"
  if [[ "$input" == "0" || -z "$input" ]]; then
    echo "已取消。"
    return
  fi

  if [[ "$input" == *"/"* || "$input" == *".."* ]]; then
    warn "文件名无效。"
    return
  fi

  archive_file="$BACKUP_DIR/$input"
  if [[ ! -f "$archive_file" ]]; then
    warn "备份文件不存在：$archive_file"
    return
  fi

  local confirm=""
  if ! prompt_choice confirm "恢复会覆盖当前配置，确认继续？[y/N]："; then
    warn "未读取到输入。"
    return
  fi
  confirm="$(printf '%s' "$confirm" | tr '[:upper:]' '[:lower:]')"
  if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo "已取消。"
    return
  fi

  if ! tar -xzf "$archive_file" -C "$APP_DIR"; then
    warn "恢复失败。"
    return
  fi

  echo "恢复完成：$archive_file"
  if service_is_running; then
    service_restart
    echo "服务已自动重启。"
  fi
  show_access_urls
}

show_latest_backup_details() {
  if [[ ! -d "$BACKUP_DIR" ]]; then
    echo "暂无备份文件。"
    return
  fi

  local latest_backup
  latest_backup="$(ls -1t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -n1 || true)"
  if [[ -z "$latest_backup" || ! -f "$latest_backup" ]]; then
    echo "暂无备份文件。"
    return
  fi

  local backup_name backup_size backup_time
  backup_name="$(basename "$latest_backup")"
  backup_size="$(du -h "$latest_backup" | awk '{print $1}')"
  backup_time="$(date -r "$latest_backup" '+%Y-%m-%d %H:%M:%S')"

  echo "----------------------------------------"
  echo "最新备份：$backup_name"
  echo "时间：$backup_time"
  echo "大小：$backup_size"
  echo "包含文件："
  tar -tzf "$latest_backup" | sed 's#^#- #' || echo "- （读取失败）"
  echo "----------------------------------------"
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
    warn "当前为引导模式，请先执行 1) 部署环境。"
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

  if [[ -d "$APP_DIR/.git" ]]; then
    log "检测到本地仓库，正在同步 GitHub 最新代码与数据库..."
    if ! sync_repo_to_origin "$APP_DIR"; then
      warn "仓库同步失败，继续使用当前本地文件执行安装。"
    fi
  fi

  bash "$APP_DIR/install.sh"
  show_access_urls
}

do_uninstall() {
  require_root
  local confirm=""
  if ! prompt_choice confirm "确认彻底卸载并删除全部数据（含目录）？[y/N]："; then
    warn "未读取到输入。"
    return
  fi
  confirm="$(printf '%s' "$confirm" | tr '[:upper:]' '[:lower:]')"
  if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo "已取消。"
    return
  fi
  bash "$APP_DIR/uninstall.sh"
  echo "彻底卸载完成。"
  exit 0
}

do_restart() {
  require_root
  service_restart
  echo "服务已重启。"
  show_access_urls
}

do_stop() {
  require_root
  service_stop
  echo "服务已停止。"
}

do_status() {
  service_status || true
  show_access_urls
}

do_change_port() {
  require_root

  local current_port new_port
  current_port="$(get_port)"

  if ! prompt_choice new_port "请输入新的面板端口（1-65535，输入 0 取消）："; then
    warn "未读取到输入。"
    return
  fi
  new_port="$(printf '%s' "$new_port" | tr -d '[:space:]')"

  if [[ "$new_port" == "0" ]]; then
    echo "已取消。"
    return
  fi
  if ! is_valid_port "$new_port"; then
    warn "端口无效，请输入 1-65535 之间的数字。"
    return
  fi
  if [[ "$new_port" == "$current_port" ]]; then
    echo "端口未变更：$new_port"
    return
  fi
  if ! is_port_available "$new_port"; then
    warn "端口已被占用：$new_port"
    return
  fi

  set_env_key "FRP_MANAGER_PORT" "$new_port"
  service_restart
  echo "端口已修改为：$new_port"
  show_access_urls
}

agent_list_nodes() {
  local py
  py="$(pick_python_bin)"
  "$py" - <<PY
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_nodes

nodes = get_agent_nodes()
if not nodes:
    print("暂无 Agent 节点")
    raise SystemExit(0)

for item in nodes:
    labels = ",".join(item.get("labels", [])) if isinstance(item.get("labels", []), list) else ""
    print(f"- id={item.get('id','')} name={item.get('name','')} status={item.get('status','unknown')} last_seen={item.get('last_seen_at','')} labels={labels}")
PY
}

agent_create_node() {
  require_root
  local name labels py
  if ! prompt_choice name "输入节点名称："; then
    warn "未读取到输入。"
    return
  fi
  name="$(printf '%s' "$name" | xargs)"
  if [[ -z "$name" ]]; then
    warn "节点名称不能为空。"
    return
  fi

  if ! prompt_choice labels "输入标签（逗号分隔，可空）："; then
    warn "未读取到输入。"
    return
  fi

  py="$(pick_python_bin)"
  "$py" - "$name" "$labels" <<PY
import secrets
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import create_agent_node

name = sys.argv[1].strip()
raw_labels = sys.argv[2].strip()
labels = [item.strip() for item in raw_labels.split(',') if item.strip()]
token = secrets.token_urlsafe(48)[:48]
created = create_agent_node({
    "name": name,
    "labels": labels,
    "status": "offline",
}, token)

print(f"节点创建成功: {created.get('id','')}")
print(f"节点名称: {created.get('name','')}")
print(f"Agent Token: {token}")
PY
}

agent_print_bootstrap_command() {
  require_root
  local node_id py manager_url script_url token quoted_script quoted_manager quoted_node quoted_token
  if ! prompt_choice node_id "输入节点 ID："; then
    warn "未读取到输入。"
    return
  fi
  node_id="$(printf '%s' "$node_id" | xargs)"
  if [[ -z "$node_id" ]]; then
    warn "节点 ID 不能为空。"
    return
  fi

  manager_url="$(get_manager_base_url_for_agent)"
  script_url="${manager_url%/}/static/agent/frp_agent.py"
  py="$(pick_python_bin)"
  token="$($py - "$node_id" <<PY
import secrets
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_node, rotate_agent_node_token

node_id = sys.argv[1].strip()
node = get_agent_node(node_id)
if not node:
    print("")
    raise SystemExit(2)

token = secrets.token_urlsafe(48)[:48]
ok = rotate_agent_node_token(node_id, token)
if not ok:
    print("")
    raise SystemExit(3)
print(token)
PY
  )" || true

  if [[ -z "$token" ]]; then
    warn "节点不存在或轮换 token 失败。"
    return
  fi

  quoted_script="$(shell_single_quote "$script_url")"
  quoted_manager="$(shell_single_quote "$manager_url")"
  quoted_node="$(shell_single_quote "$node_id")"
  quoted_token="$(shell_single_quote "$token")"

  echo "----------------------------------------"
  echo "节点 ID: $node_id"
  echo "管理地址: $manager_url"
  echo "Agent Token: $token"
  echo ""
  echo "在目标服务器执行："
  echo "mkdir -p /opt/frp-agent && curl -fsSL ${quoted_script} -o /opt/frp-agent/frp_agent.py && NODE_ID=${quoted_node} NODE_TOKEN=${quoted_token} MANAGER_URL=${quoted_manager} POLL_INTERVAL=5 python3 /opt/frp-agent/frp_agent.py"
  echo "----------------------------------------"
}

agent_list_runtimes() {
  local py
  py="$(pick_python_bin)"
  "$py" - <<PY
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_runtimes

runtimes = get_agent_runtimes()
if not runtimes:
    print("暂无运行实例")
    raise SystemExit(0)

for item in runtimes:
    print(f"- id={item.get('id','')} name={item.get('name','')} node={item.get('node_id','')} kind={item.get('kind','')} status={item.get('status','unknown')}")
PY
}

agent_create_runtime() {
  require_root
  local node_id runtime_id runtime_name runtime_kind start_cmd stop_cmd check_cmd py
  if ! prompt_choice node_id "输入所属节点 ID："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice runtime_id "输入实例 ID（可空自动生成）："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice runtime_name "输入实例名称："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice runtime_kind "输入实例类型（frpc/frps，默认 frpc）："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice start_cmd "输入启动命令（可空）："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice stop_cmd "输入停止命令（可空）："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice check_cmd "输入检查命令（可空）："; then warn "未读取到输入。"; return; fi

  node_id="$(printf '%s' "$node_id" | xargs)"
  runtime_id="$(printf '%s' "$runtime_id" | xargs)"
  runtime_name="$(printf '%s' "$runtime_name" | xargs)"
  runtime_kind="$(printf '%s' "$runtime_kind" | xargs)"
  runtime_kind="${runtime_kind:-frpc}"

  if [[ -z "$node_id" || -z "$runtime_name" ]]; then
    warn "节点 ID 和实例名称不能为空。"
    return
  fi

  py="$(pick_python_bin)"
  "$py" - "$node_id" "$runtime_id" "$runtime_name" "$runtime_kind" "$start_cmd" "$stop_cmd" "$check_cmd" <<PY
import secrets
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_node, upsert_agent_runtime

node_id, runtime_id, runtime_name, runtime_kind, start_cmd, stop_cmd, check_cmd = [x.strip() for x in sys.argv[1:8]]
if not get_agent_node(node_id):
    print("节点不存在")
    raise SystemExit(2)

if not runtime_id:
    runtime_id = secrets.token_hex(12)

runtime = upsert_agent_runtime({
    "id": runtime_id,
    "node_id": node_id,
    "kind": runtime_kind or "frpc",
    "name": runtime_name,
    "status": "unknown",
    "enabled": True,
    "metadata": {
        "start_command": start_cmd,
        "stop_command": stop_cmd,
        "check_command": check_cmd,
    },
})
print(f"实例已保存: {runtime.get('id','')}")
PY
}

agent_queue_runtime_job() {
  require_root
  local runtime_id desired py
  runtime_id="$1"
  desired="$2"
  py="$(pick_python_bin)"
  "$py" - "$runtime_id" "$desired" <<PY
import secrets
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_runtime, create_agent_job

runtime_id = sys.argv[1].strip()
desired = sys.argv[2].strip()
runtime = get_agent_runtime(runtime_id)
if not runtime:
    print("运行实例不存在")
    raise SystemExit(2)

node_id = str(runtime.get("node_id", "")).strip()
if not node_id:
    print("运行实例缺少 node_id")
    raise SystemExit(3)

job_type = "instance.ensure_running" if desired == "running" else "instance.ensure_stopped"
payload = {
    "runtime_id": runtime_id,
    "desired_state": desired,
    "kind": runtime.get("kind", ""),
    "name": runtime.get("name", ""),
    "metadata": runtime.get("metadata", {}),
}

job = create_agent_job({
    "node_id": node_id,
    "type": job_type,
    "payload": payload,
    "max_attempts": 1,
    "idempotency_key": f"{runtime_id}:{desired}:{secrets.token_hex(4)}",
})
print(f"任务已创建: {job.get('id','')} ({job.get('type','')})")
PY
}

agent_start_runtime() {
  local runtime_id
  if ! prompt_choice runtime_id "输入要启动的 runtime_id："; then warn "未读取到输入。"; return; fi
  runtime_id="$(printf '%s' "$runtime_id" | xargs)"
  if [[ -z "$runtime_id" ]]; then warn "runtime_id 不能为空。"; return; fi
  agent_queue_runtime_job "$runtime_id" "running"
}

agent_stop_runtime() {
  local runtime_id
  if ! prompt_choice runtime_id "输入要停止的 runtime_id："; then warn "未读取到输入。"; return; fi
  runtime_id="$(printf '%s' "$runtime_id" | xargs)"
  if [[ -z "$runtime_id" ]]; then warn "runtime_id 不能为空。"; return; fi
  agent_queue_runtime_job "$runtime_id" "stopped"
}

agent_batch_runtime_action() {
  require_root
  local raw desired runtime_id
  desired="$1"
  if ! prompt_choice raw "输入 runtime_id 列表（逗号分隔）："; then warn "未读取到输入。"; return; fi
  raw="$(printf '%s' "$raw" | tr '\n' ',' )"

  IFS=',' read -r -a ids <<< "$raw"
  for runtime_id in "${ids[@]}"; do
    runtime_id="$(printf '%s' "$runtime_id" | xargs)"
    if [[ -z "$runtime_id" ]]; then
      continue
    fi
    agent_queue_runtime_job "$runtime_id" "$desired" || true
  done
}

agent_list_jobs() {
  local node_id limit py
  if ! prompt_choice node_id "按节点筛选（可空）："; then warn "未读取到输入。"; return; fi
  if ! prompt_choice limit "显示最近多少条任务（默认 20）："; then warn "未读取到输入。"; return; fi

  node_id="$(printf '%s' "$node_id" | xargs)"
  limit="$(printf '%s' "$limit" | xargs)"
  if [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]]; then
    limit="20"
  fi

  py="$(pick_python_bin)"
  "$py" - "$node_id" "$limit" <<PY
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_jobs

node_id = sys.argv[1].strip()
limit = int(sys.argv[2])

jobs = get_agent_jobs(node_id=node_id or None)
jobs = sorted(jobs, key=lambda item: str(item.get("created_at", "")), reverse=True)[:limit]
if not jobs:
    print("暂无任务")
    raise SystemExit(0)

for item in jobs:
    print(
        f"- id={item.get('id','')} status={item.get('status','')} "
        f"type={item.get('type','')} node={item.get('node_id','')} "
        f"attempts={item.get('attempts',0)}/{item.get('max_attempts',1)} "
        f"created={item.get('created_at','')} finished={item.get('finished_at','')}"
    )
PY
}

agent_show_job_detail() {
  local job_id py
  if ! prompt_choice job_id "输入 job_id："; then warn "未读取到输入。"; return; fi
  job_id="$(printf '%s' "$job_id" | xargs)"
  if [[ -z "$job_id" ]]; then
    warn "job_id 不能为空。"
    return
  fi

  py="$(pick_python_bin)"
  "$py" - "$job_id" <<PY
import json
import sys
sys.path.insert(0, r"${APP_DIR}")
from utils.config_manager import get_agent_job

job_id = sys.argv[1].strip()
job = get_agent_job(job_id)
if not job:
    print("任务不存在")
    raise SystemExit(2)

print(json.dumps(job, ensure_ascii=False, indent=2))
PY
}

do_agent_control() {
  if ! require_deployed_env; then
    return
  fi

  while true; do
    echo "=================================="
    echo " Agent 编排控制"
    echo "=================================="
    echo "1) 列出节点"
    echo "2) 创建节点"
    echo "3) 生成节点引导命令（轮换 Token）"
    echo "4) 列出运行实例"
    echo "5) 创建运行实例"
    echo "6) 启动单个实例（下发任务）"
    echo "7) 停止单个实例（下发任务）"
    echo "8) 批量启动实例（下发任务）"
    echo "9) 批量停止实例（下发任务）"
    echo "10) 查看最近任务"
    echo "11) 查看任务详情"
    echo "0) 返回上一级"
    echo "----------------------------------"

    local choice=""
    if ! prompt_choice choice "请选择操作："; then
      warn "未读取到输入。"
      return
    fi

    case "$choice" in
      1) agent_list_nodes ;;
      2) agent_create_node ;;
      3) agent_print_bootstrap_command ;;
      4) agent_list_runtimes ;;
      5) agent_create_runtime ;;
      6) agent_start_runtime ;;
      7) agent_stop_runtime ;;
      8) agent_batch_runtime_action "running" ;;
      9) agent_batch_runtime_action "stopped" ;;
      10) agent_list_jobs ;;
      11) agent_show_job_detail ;;
      0) return ;;
      *) echo "无效选项，请重新输入。" ;;
    esac
    echo
  done
}

main() {
  if is_bootstrap_mode && is_repo_ready "$BOOTSTRAP_DIR"; then
    log "检测到已部署仓库，切换到本地控制器：$BOOTSTRAP_DIR/control.sh"
    exec bash "$BOOTSTRAP_DIR/control.sh" "$@"
  fi

  while true; do
    show_menu
    local choice=""
    if ! prompt_choice choice "请选择操作："; then
      warn "未读取到输入，请在交互式终端中运行。"
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
      10)
        do_agent_control
        ;;
      11)
        if require_deployed_env; then
          backup_config_files
        fi
        ;;
      12)
        if require_deployed_env; then
          restore_config_files
        fi
        ;;
      13)
        if require_deployed_env; then
          show_latest_backup_details
        fi
        ;;
      0) exit 0 ;;
      *) echo "无效选项，请重新输入。" ;;
    esac
    echo
  done
}

main "$@"
