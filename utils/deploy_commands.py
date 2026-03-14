import os
import re


FRP_VERSION = os.environ.get('FRP_VERSION', '0.51.3')
LINUX_ARCH = os.environ.get('FRP_LINUX_ARCH', 'linux_amd64')
WINDOWS_ARCH = os.environ.get('FRP_WINDOWS_ARCH', 'windows_amd64')
BASE_DOWNLOAD_URL = f'https://github.com/fatedier/frp/releases/download/v{FRP_VERSION}'
LINUX_PACKAGE_NAME = f'frp_{FRP_VERSION}_{LINUX_ARCH}.tar.gz'
WINDOWS_PACKAGE_NAME = f'frp_{FRP_VERSION}_{WINDOWS_ARCH}.zip'
LINUX_FOLDER_NAME = f'frp_{FRP_VERSION}_{LINUX_ARCH}'
WINDOWS_FOLDER_NAME = f'frp_{FRP_VERSION}_{WINDOWS_ARCH}'

DEFAULT_SECURITY_PROFILE = 'balanced'
SECURITY_PROFILE_ALIASES = {
    'default': 'balanced',
    'recommended': 'balanced',
    'tls': 'balanced',
    'balanced': 'balanced',
    'hybrid': 'hybrid',
    'double': 'hybrid',
    'strict': 'mtls',
    'mtls': 'mtls',
}
SECURITY_PROFILE_LABELS = {
    'balanced': '推荐档：TLS + token（默认）',
    'hybrid': '增强档：TLS + token + 代理层加密/压缩',
    'mtls': '严格档：mTLS + token（需证书）',
}


def _value(raw_value):
    if raw_value is None:
        return ''
    return str(raw_value).strip()


def _safe_proxy_name(raw_name):
    normalized = re.sub(r'[^A-Za-z0-9._-]', '_', _value(raw_name) or 'proxy')
    normalized = normalized[:64]
    return normalized or 'proxy'


def _escape_for_batch_echo(text):
    escaped = _value(text)
    escaped = escaped.replace('^', '^^')
    escaped = escaped.replace('&', '^&')
    escaped = escaped.replace('|', '^|')
    escaped = escaped.replace('<', '^<')
    escaped = escaped.replace('>', '^>')
    escaped = escaped.replace('%', '%%')
    return escaped


def _shell_single_quote(text):
    return "'" + _value(text).replace("'", "'\"'\"'") + "'"


def normalize_security_profile(profile):
    normalized = _value(profile).lower()
    if not normalized:
        return DEFAULT_SECURITY_PROFILE
    return SECURITY_PROFILE_ALIASES.get(normalized, DEFAULT_SECURITY_PROFILE)


def get_security_profile_summary(profile):
    normalized = normalize_security_profile(profile)
    return {
        'id': normalized,
        'label': SECURITY_PROFILE_LABELS.get(normalized, SECURITY_PROFILE_LABELS[DEFAULT_SECURITY_PROFILE]),
    }


def _build_security_common_lines(profile):
    normalized = normalize_security_profile(profile)
    if normalized == 'mtls':
        return [
            '# [安全档位] 严格档：启用 TLS，并要求服务端证书校验（mTLS）。',
            '# 注意：请把下方证书路径替换为真实文件路径，否则连接会失败。',
            'tls_enable = true',
            'tls_trusted_ca_file = /etc/frp/certs/ca.crt',
            'tls_cert_file = /etc/frp/certs/client.crt',
            'tls_key_file = /etc/frp/certs/client.key',
        ]
    if normalized == 'hybrid':
        return [
            '# [安全档位] 增强档：TLS + 代理层加密 + 压缩。',
            '# 说明：在已开启 TLS 场景下再启 use_encryption 会增加 CPU 开销，适合高敏感流量。',
            'tls_enable = true',
        ]
    return [
        '# [安全档位] 推荐档：TLS + token。',
        '# 说明：默认好用、性能与安全较均衡，适合大多数生产场景。',
        'tls_enable = true',
    ]


def _build_security_proxy_lines(profile):
    normalized = normalize_security_profile(profile)
    if normalized == 'hybrid':
        return [
            'use_encryption = true',
            'use_compression = true',
        ]
    return []


def _build_proxy_section(port, security_profile='balanced'):
    lines = [
        f'[{_safe_proxy_name(port.get("name"))}]',
        f'type = {_value(port.get("protocol"))}',
        f'local_ip = {_value(port.get("local_ip"))}',
        f'local_port = {_value(port.get("local_port"))}',
    ]
    protocol = _value(port.get('protocol')).lower()
    if protocol in {'http', 'https'}:
        lines.append(f'custom_domains = {_value(port.get("domain"))}')
    else:
        lines.append(f'remote_port = {_value(port.get("remote_port"))}')
    lines.extend(_build_security_proxy_lines(security_profile))
    return lines


def build_frpc_config(server, ports, security_profile='balanced'):
    profile_summary = get_security_profile_summary(security_profile)
    lines = [
        '# ----------------------------------------',
        '# FRPC 自动生成配置',
        f'# 加密方案: {profile_summary["label"]}',
        '# ----------------------------------------',
        '[common]',
        f'server_addr = {_value(server.get("server_addr"))}',
        f'server_port = {_value(server.get("server_port"))}',
        f'token = {_value(server.get("token"))}',
    ]
    lines.extend(_build_security_common_lines(profile_summary['id']))
    lines.extend([
        '',
    ])

    used_names = set()
    for port in ports:
        if not port.get('enabled', True):
            continue

        section_name = _safe_proxy_name(port.get('name'))
        if section_name in used_names:
            index = 2
            while f'{section_name}_{index}' in used_names:
                index += 1
            port = dict(port)
            port['name'] = f'{section_name}_{index}'
            section_name = port['name']
        used_names.add(section_name)

        lines.extend(_build_proxy_section(port, security_profile=profile_summary['id']))
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def build_frps_deploy_command(server, manager_base_urls=None):
    normalized_urls = []
    seen_urls = set()

    if isinstance(manager_base_urls, str):
        manager_base_urls = [manager_base_urls]

    for raw_url in manager_base_urls or []:
        url = _value(raw_url).rstrip('/')
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        normalized_urls.append(url)

    callback_block = ''
    callback_echo_line = 'echo "未配置回报地址：部署后请在面板中补充可访问的回调地址。"'
    if normalized_urls:
        urls_literal = '\n'.join(normalized_urls)
        callback_echo_line = f'echo "回报地址候选: {", ".join(normalized_urls)}"'
        callback_block = f"""
FRPS_SERVER_ID={_shell_single_quote(server.get('id'))}

MANAGER_URL_LIST=$(cat <<'URLS'
{urls_literal}
URLS
)

report_to_manager() {{
    local manager_url endpoint payload
    payload='{{"token":"'"$FRPS_TOKEN"'","server_addr":"'"$REPORTED_IP"'","server_port":'"$ACTUAL_SERVER_PORT"',"vhost_http_port":'"$ACTUAL_HTTP_PORT"',"vhost_https_port":'"$ACTUAL_HTTPS_PORT"',"dashboard_port":'"$ACTUAL_DASHBOARD_PORT"'}}'

    while IFS= read -r manager_url; do
        [ -z "$manager_url" ] && continue
        endpoint="${{manager_url}}/api/frps/server/${{FRPS_SERVER_ID}}/report"

        if command -v curl >/dev/null 2>&1; then
            if curl -fsS --max-time 5 -X POST "$endpoint" \\
                -H "Content-Type: application/json" \\
                -d "$payload" >/dev/null 2>&1; then
                echo "已向管理面板回报 FRPS 地址: $manager_url"
                return 0
            fi
            continue
        fi

        if command -v wget >/dev/null 2>&1; then
            if wget -qO- --timeout=5 \\
                --header="Content-Type: application/json" \\
                --post-data="$payload" "$endpoint" >/dev/null 2>&1; then
                echo "已向管理面板回报 FRPS 地址: $manager_url"
                return 0
            fi
        fi
    done <<< "$MANAGER_URL_LIST"
    return 1
}}

start_reporter() {{
    local pid_file="/tmp/frps_report_${{FRPS_SERVER_ID}}.pid"
    local log_file="/tmp/frps_report_${{FRPS_SERVER_ID}}.log"
    local report_interval="${{REPORT_INTERVAL:-30}}"

    if [[ -f "$pid_file" ]]; then
        local old_pid=""
        old_pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            kill "$old_pid" >/dev/null 2>&1 || true
        fi
    fi

    (
        while true; do
            sleep "$report_interval"
            if command -v pgrep >/dev/null 2>&1 && ! pgrep -x frps >/dev/null 2>&1; then
                exit 0
            fi
            report_to_manager || true
        done
    ) >"$log_file" 2>&1 &
    echo "$!" >"$pid_file"
}}

if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    if ! report_to_manager; then
        echo "警告: 首次回报失败，已启动后台重试。请确认回报地址可从 FRPS 服务器访问。"
    fi
    start_reporter
else
    echo "警告: 未检测到 curl/wget，无法自动回报状态。"
fi
"""

    return f"""# FRPS 一键部署命令
set -euo pipefail

mkdir -p /opt/frp && cd /opt/frp
wget -O frps.tar.gz {BASE_DOWNLOAD_URL}/{LINUX_PACKAGE_NAME}
tar -xzf frps.tar.gz
cd {LINUX_FOLDER_NAME}
FRPS_TOKEN={_shell_single_quote(server.get('token'))}
LOCK_HTTPS_PORT={'1' if bool(server.get('lock_https_port', False)) else '0'}
CONFIG_SERVER_PORT={_value(server.get('server_port'))}
CONFIG_HTTP_PORT={_value(server.get('vhost_http_port'))}
CONFIG_HTTPS_PORT={_value(server.get('vhost_https_port'))}
CONFIG_DASHBOARD_PORT={_value(server.get('dashboard_port'))}

REPORTED_IP=""
if command -v ip >/dev/null 2>&1; then
    REPORTED_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{{for(i=1;i<=NF;i++) if ($i=="src"){{print $(i+1); exit}}}}')"
fi
if [ -z "$REPORTED_IP" ]; then
    REPORTED_IP="$(hostname -I 2>/dev/null | awk '{{print $1}}')"
fi
if command -v curl >/dev/null 2>&1; then
    PUBLIC_IP="$(curl -s --max-time 3 https://api.ipify.org || true)"
    if [ -n "$PUBLIC_IP" ]; then
        REPORTED_IP="$PUBLIC_IP"
    fi
fi
if [ -z "$REPORTED_IP" ]; then
    REPORTED_IP="127.0.0.1"
fi

port_in_use() {{
    local target_port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -lnt 2>/dev/null | awk '{{print $4}}' | grep -Eq "[:.]${{target_port}}$"
        return $?
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk '{{print $4}}' | grep -Eq "[:.]${{target_port}}$"
        return $?
    fi
    return 1
}}

random_port() {{
    local min_port="$1"
    local max_port="$2"
    local range=$((max_port - min_port + 1))
    local seed
    if command -v od >/dev/null 2>&1; then
        seed="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ' || true)"
    fi
    if [ -z "$seed" ]; then
        seed="$RANDOM"
    fi
    echo $(( (seed % range) + min_port ))
}}

pick_available_port() {{
    local preferred="$1"
    local min_port="$2"
    local max_port="$3"

    if [ -n "$preferred" ] && ! port_in_use "$preferred"; then
        echo "$preferred"
        return 0
    fi

    local attempt candidate
    for attempt in $(seq 1 80); do
        candidate="$(random_port "$min_port" "$max_port")"
        if ! port_in_use "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}}

ACTUAL_SERVER_PORT="$(pick_available_port "" 20000 39999 || true)"
ACTUAL_HTTP_PORT="$(pick_available_port "" 10080 19999 || true)"
ACTUAL_DASHBOARD_PORT="$(pick_available_port "" 30000 49999 || true)"

if [ "$LOCK_HTTPS_PORT" = "1" ]; then
    ACTUAL_HTTPS_PORT="$CONFIG_HTTPS_PORT"
    if port_in_use "$ACTUAL_HTTPS_PORT"; then
        echo "HTTPS 端口已锁定为 $ACTUAL_HTTPS_PORT，但该端口已被占用。"
        exit 1
    fi
else
    ACTUAL_HTTPS_PORT="$(pick_available_port "" 10443 20999 || true)"
fi

if [ -z "$ACTUAL_SERVER_PORT" ] || [ -z "$ACTUAL_HTTP_PORT" ] || [ -z "$ACTUAL_HTTPS_PORT" ] || [ -z "$ACTUAL_DASHBOARD_PORT" ]; then
    echo "无法分配可用端口，请检查系统端口占用。"
    exit 1
fi

if command -v pgrep >/dev/null 2>&1 && pgrep -x frps >/dev/null 2>&1; then
    echo "检测到已有 FRPS 进程，正在停止旧进程..."
    if command -v pkill >/dev/null 2>&1; then
        pkill -x frps || true
        sleep 1
    else
        echo "未检测到 pkill，无法自动停止旧 FRPS，请手动停止后重试。"
        exit 1
    fi
fi

cat > frps.ini << 'EOF'
[common]
bind_port = $ACTUAL_SERVER_PORT
vhost_http_port = $ACTUAL_HTTP_PORT
vhost_https_port = $ACTUAL_HTTPS_PORT
dashboard_port = $ACTUAL_DASHBOARD_PORT
dashboard_user = {_value(server.get('dashboard_user'))}
dashboard_pwd = {_value(server.get('dashboard_pwd'))}
token = $FRPS_TOKEN
allow_ports = 2000-30000
EOF

nohup ./frps -c frps.ini >/tmp/frps.log 2>&1 &
sleep 2

if command -v pgrep >/dev/null 2>&1 && ! pgrep -x frps >/dev/null 2>&1; then
    echo "FRPS 启动失败，请检查 /tmp/frps.log"
    tail -n 30 /tmp/frps.log || true
    exit 1
fi

if grep -qiE "create server listener error|bind: address already in use" /tmp/frps.log 2>/dev/null; then
    echo "FRPS 启动失败：端口冲突或监听失败"
    tail -n 50 /tmp/frps.log || true
    if command -v pkill >/dev/null 2>&1; then
        pkill -x frps || true
    fi
    exit 1
fi

echo "FRPS 部署完成！"
echo "FRPS 服务器地址: $REPORTED_IP"
echo "服务端口: $ACTUAL_SERVER_PORT"
echo "HTTP 端口: $ACTUAL_HTTP_PORT"
echo "HTTPS 端口: $ACTUAL_HTTPS_PORT"
echo "仪表盘地址: http://$REPORTED_IP:$ACTUAL_DASHBOARD_PORT"
echo "用户名: {_value(server.get('dashboard_user'))}"
echo "密码: {_value(server.get('dashboard_pwd'))}"
{callback_echo_line}
{callback_block}
"""


def build_frpc_deploy_command(server, port, system='linux', security_profile='balanced'):
    profile_summary = get_security_profile_summary(security_profile)
    config = build_frpc_config(server, [port], security_profile=profile_summary['id'])
    protocol = _value(port.get('protocol')).lower()

    if system == 'windows':
        windows_echo_lines = []
        for line in config.splitlines():
            if line:
                windows_echo_lines.append(f"echo {_escape_for_batch_echo(line)}")
        windows_echo_config = '\n'.join(windows_echo_lines)

        if protocol in {'http', 'https'}:
            target_line = f'echo 访问地址: http://{_value(port.get("domain"))}:{_value(server.get("vhost_http_port"))}'
        else:
            target_line = (
                f'echo 映射地址: {_value(server.get("server_addr"))}:{_value(port.get("remote_port"))} '
                f'^> {_value(port.get("local_ip"))}:{_value(port.get("local_port"))}'
            )
        return f"""@echo off
echo FRPC Windows 一键部署脚本
echo 安全档位: {profile_summary['label']}
echo.

if not exist "frp" mkdir frp
cd frp
powershell -Command "Invoke-WebRequest -Uri '{BASE_DOWNLOAD_URL}/{WINDOWS_PACKAGE_NAME}' -OutFile 'frpc.zip'"
powershell -Command "Expand-Archive -Path 'frpc.zip' -DestinationPath '.' -Force"
cd {WINDOWS_FOLDER_NAME}

(
@echo off
{windows_echo_config}
) > frpc.ini

start /b frpc.exe -c frpc.ini
echo.
echo FRPC 部署完成！
{target_line}
pause
"""

    if protocol in {'http', 'https'}:
        target_lines = [
            'echo "FRPC 部署完成！"',
            f'echo "访问地址: http://{_value(port.get("domain"))}:{_value(server.get("vhost_http_port"))}"',
        ]
    else:
        target_lines = [
            'echo "FRPC 部署完成！"',
            (
                f'echo "映射地址: {_value(server.get("server_addr"))}:{_value(port.get("remote_port"))} '
                f'-> {_value(port.get("local_ip"))}:{_value(port.get("local_port"))}"'
            ),
        ]

    return f"""mkdir -p /opt/frp && cd /opt/frp
wget -O frpc.tar.gz {BASE_DOWNLOAD_URL}/{LINUX_PACKAGE_NAME}
tar -xzf frpc.tar.gz
cd {LINUX_FOLDER_NAME}

echo "使用安全档位: {profile_summary['label']}"

cat > frpc.ini << 'EOF'
{config}
EOF

nohup ./frpc -c frpc.ini >/dev/null 2>&1 &
{target_lines[0]}
{target_lines[1]}
"""
