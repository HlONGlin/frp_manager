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


def _value(raw_value):
    if raw_value is None:
        return ''
    return str(raw_value).strip()


def _safe_proxy_name(raw_name):
    normalized = re.sub(r'[^A-Za-z0-9._-]', '_', _value(raw_name) or 'proxy')
    normalized = normalized[:64]
    return normalized or 'proxy'


def _build_proxy_section(port):
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
    return lines


def build_frpc_config(server, ports):
    lines = [
        '[common]',
        f'server_addr = {_value(server.get("server_addr"))}',
        f'server_port = {_value(server.get("server_port"))}',
        f'token = {_value(server.get("token"))}',
        '',
    ]

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

        lines.extend(_build_proxy_section(port))
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def build_frps_deploy_command(server, manager_base_url=None):
    callback_block = ''
    if manager_base_url:
        callback_block = f"""
MANAGER_URL='{_value(manager_base_url).rstrip('/')}'
FRPS_SERVER_ID='{_value(server.get('id'))}'

if command -v curl >/dev/null 2>&1; then
    curl -s -X POST "$MANAGER_URL/api/frps/server/$FRPS_SERVER_ID/report" \\
        -H "Content-Type: application/json" \\
        -d '{{"token":"'"$FRPS_TOKEN"'","server_addr":"'"$REPORTED_IP"'","server_port":{_value(server.get('server_port'))}}}' \\
        >/dev/null 2>&1 || true
    echo "已向管理面板回报 FRPS 地址: $REPORTED_IP"
else
    echo "未检测到 curl，无法自动回报地址到管理面板。"
fi
"""

    return f"""# FRPS 一键部署命令
mkdir -p /opt/frp && cd /opt/frp
wget -O frps.tar.gz {BASE_DOWNLOAD_URL}/{LINUX_PACKAGE_NAME}
tar -xzf frps.tar.gz
cd {LINUX_FOLDER_NAME}
FRPS_TOKEN='{_value(server.get('token'))}'

REPORTED_IP="$(hostname -I 2>/dev/null | awk '{{print $1}}')"
if command -v curl >/dev/null 2>&1; then
    PUBLIC_IP="$(curl -s --max-time 3 https://api.ipify.org || true)"
    if [ -n "$PUBLIC_IP" ]; then
        REPORTED_IP="$PUBLIC_IP"
    fi
fi
if [ -z "$REPORTED_IP" ]; then
    REPORTED_IP="127.0.0.1"
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

cat > frps.ini << EOF
[common]
bind_port = {_value(server.get('server_port'))}
vhost_http_port = {_value(server.get('vhost_http_port'))}
vhost_https_port = {_value(server.get('vhost_https_port'))}
dashboard_port = {_value(server.get('dashboard_port'))}
dashboard_user = {_value(server.get('dashboard_user'))}
dashboard_pwd = {_value(server.get('dashboard_pwd'))}
token = $FRPS_TOKEN
allow_ports = 2000-30000
EOF

nohup ./frps -c frps.ini >/tmp/frps.log 2>&1 &
sleep 1

if command -v pgrep >/dev/null 2>&1 && ! pgrep -x frps >/dev/null 2>&1; then
    echo "FRPS 启动失败，请检查 /tmp/frps.log"
    tail -n 30 /tmp/frps.log || true
    exit 1
fi

echo "FRPS 部署完成！"
echo "FRPS 服务器地址: $REPORTED_IP"
echo "仪表盘地址: http://$REPORTED_IP:{_value(server.get('dashboard_port'))}"
echo "用户名: {_value(server.get('dashboard_user'))}"
echo "密码: {_value(server.get('dashboard_pwd'))}"
{callback_block}
"""


def build_frpc_deploy_command(server, port, system='linux'):
    config_lines = [
        '[common]',
        f'server_addr = {_value(server.get("server_addr"))}',
        f'server_port = {_value(server.get("server_port"))}',
        f'token = {_value(server.get("token"))}',
        '',
    ]
    config_lines.extend(_build_proxy_section(port))
    config = '\n'.join(config_lines)
    protocol = _value(port.get('protocol')).lower()

    if system == 'windows':
        windows_echo_config = config.replace('\n', '\necho ')
        if protocol in {'http', 'https'}:
            target_line = f'echo 访问地址: http://{_value(port.get("domain"))}:{_value(server.get("vhost_http_port"))}'
        else:
            target_line = (
                f'echo 映射地址: {_value(server.get("server_addr"))}:{_value(port.get("remote_port"))} '
                f'^> {_value(port.get("local_ip"))}:{_value(port.get("local_port"))}'
            )
        return f"""@echo off
echo FRPC Windows 一键部署脚本
echo.

if not exist "frp" mkdir frp
cd frp
powershell -Command "Invoke-WebRequest -Uri '{BASE_DOWNLOAD_URL}/{WINDOWS_PACKAGE_NAME}' -OutFile 'frpc.zip'"
powershell -Command "Expand-Archive -Path 'frpc.zip' -DestinationPath '.' -Force"
cd {WINDOWS_FOLDER_NAME}

(
echo {windows_echo_config}
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

cat > frpc.ini << 'EOF'
{config}
EOF

nohup ./frpc -c frpc.ini >/dev/null 2>&1 &
{target_lines[0]}
{target_lines[1]}
"""
