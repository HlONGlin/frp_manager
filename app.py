from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import os
import re
import secrets
import socket
import sys
import threading
import time
from urllib.parse import quote, quote_plus, urlparse
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config_manager import (
    complete_agent_job,
    create_agent_job,
    create_agent_node,
    add_frps_server,
    add_port_mapping,
    delete_agent_node,
    delete_frpc_config,
    delete_frps_server,
    delete_port_mapping,
    get_agent_job,
    get_agent_jobs,
    get_agent_node,
    get_agent_nodes,
    get_agent_runtime,
    get_agent_runtimes,
    get_frpc_configs,
    get_auth_config,
    get_frps_server,
    get_frps_servers,
    is_auth_initialized,
    lease_agent_job_for_node,
    mark_agent_job_running,
    rotate_agent_node_token,
    save_frpc_config,
    set_admin_credentials,
    touch_agent_node,
    update_agent_job,
    update_agent_node,
    update_frps_server,
    update_port_mapping,
    upsert_agent_runtime,
    verify_agent_node_token,
)
from utils.deploy_commands import (
    build_frpc_config,
    build_frpc_deploy_command,
    build_frps_deploy_command,
    get_security_profile_summary,
)
from utils.validators import (
    ValidationError,
    validate_port_create,
    validate_port_update,
    validate_server_create,
    validate_server_update,
    validate_security_profile,
    validate_system,
)

STATUS_TIMEOUT = float(os.environ.get('FRP_STATUS_TIMEOUT', '1.0'))
STATUS_CACHE_TTL = float(os.environ.get('FRP_STATUS_CACHE_TTL', '20'))
STATUS_WORKERS = int(os.environ.get('FRP_STATUS_WORKERS', '16'))
REPORT_ONLINE_TTL = float(os.environ.get('FRP_REPORT_ONLINE_TTL', '90'))
SESSION_USER_KEY = 'admin_user'
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
TOKEN_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
TOKEN_LENGTH = 32
DEPLOY_KEY_LENGTH = 48
SENSITIVE_SERVER_FIELDS = {'deploy_key'}
SENSITIVE_NODE_FIELDS = {'token_hash'}
AGENT_API_PREFIX = '/api/agent/v1/'
ALLOWED_AGENT_JOB_TYPES = {
    'instance.ensure_running',
    'instance.ensure_stopped',
}
MAX_RUNTIME_COMMAND_LENGTH = 1024
SERVICE_IDENTIFIER_PATTERN = re.compile(r'^[A-Za-z0-9_.@:-]{1,128}$')

LOGIN_RATE_LIMIT = int(os.environ.get('FRP_LOGIN_RATE_LIMIT', '10'))
LOGIN_RATE_WINDOW = int(os.environ.get('FRP_LOGIN_RATE_WINDOW_SEC', '300'))
SETUP_RATE_LIMIT = int(os.environ.get('FRP_SETUP_RATE_LIMIT', '10'))
SETUP_RATE_WINDOW = int(os.environ.get('FRP_SETUP_RATE_WINDOW_SEC', '300'))
DEPLOY_SCRIPT_RATE_LIMIT = int(os.environ.get('FRP_DEPLOY_RATE_LIMIT', '30'))
DEPLOY_SCRIPT_RATE_WINDOW = int(os.environ.get('FRP_DEPLOY_RATE_WINDOW_SEC', '60'))
AGENT_PULL_RATE_LIMIT = int(os.environ.get('FRP_AGENT_PULL_RATE_LIMIT', '120'))
AGENT_PULL_RATE_WINDOW = int(os.environ.get('FRP_AGENT_PULL_RATE_WINDOW_SEC', '60'))

app = Flask(__name__)
configured_secret_key = str(os.environ.get('FRP_MANAGER_SECRET_KEY', '')).strip()
app.secret_key = configured_secret_key or os.urandom(32).hex()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FRP_SESSION_SECURE', '0') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=int(os.environ.get('FRP_SESSION_LIFETIME_HOURS', '12')))
status_cache = {}
status_cache_lock = threading.Lock()
rate_limit_cache = {}
rate_limit_lock = threading.Lock()

if not configured_secret_key and os.environ.get('FLASK_DEBUG', '0') != '1':
    print('[security] FRP_MANAGER_SECRET_KEY not set; sessions will be invalidated after restart.', file=sys.stderr)


def success_response(payload=None, status_code=200):
    body = {'success': True}
    if payload:
        body.update(payload)
    return jsonify(body), status_code


def error_response(message, status_code=400):
    return jsonify({'success': False, 'message': message}), status_code


def parse_json_body():
    body = request.get_json(silent=True)
    if body is None:
        raise ValidationError('请求体必须为 JSON 格式')
    if not isinstance(body, dict):
        raise ValidationError('请求体必须是 JSON 对象')
    return body


def get_client_ip():
    trust_proxy = os.environ.get('FRP_TRUST_PROXY', '0') == '1'
    if trust_proxy:
        forwarded_for = str(request.headers.get('X-Forwarded-For', '')).split(',')[0].strip()
        if forwarded_for:
            return forwarded_for
    return str(request.remote_addr or '').strip() or 'unknown'


def hit_rate_limit(scope, key, limit, window_seconds):
    if limit <= 0 or window_seconds <= 0:
        return False

    now = time.monotonic()
    cache_key = f'{scope}:{key}'
    with rate_limit_lock:
        bucket = rate_limit_cache.get(cache_key, [])
        threshold = now - window_seconds
        bucket = [ts for ts in bucket if ts >= threshold]
        if len(bucket) >= limit:
            rate_limit_cache[cache_key] = bucket
            return True
        bucket.append(now)
        rate_limit_cache[cache_key] = bucket
    return False


def get_logged_in_user():
    return str(session.get(SESSION_USER_KEY, '')).strip()


def is_logged_in():
    return bool(get_logged_in_user())


def validate_auth_payload(username, password, confirm_password=None):
    normalized_username = str(username or '').strip()
    normalized_password = str(password or '')
    normalized_confirm = str(confirm_password or '')

    if not USERNAME_PATTERN.fullmatch(normalized_username):
        raise ValidationError('用户名需为 3-32 位，支持字母/数字/._-')
    if len(normalized_password) < MIN_PASSWORD_LENGTH or len(normalized_password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(f'密码长度需在 {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} 位之间')
    if confirm_password is not None and normalized_password != normalized_confirm:
        raise ValidationError('两次输入的密码不一致')

    return normalized_username, normalized_password


def generate_server_token(length=TOKEN_LENGTH):
    return ''.join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))


def generate_deploy_key(length=DEPLOY_KEY_LENGTH):
    return secrets.token_urlsafe(length)[:length]


def shell_single_quote(text):
    return "'" + str(text or '').replace("'", "'\"'\"'") + "'"


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def normalize_base_url(raw_url):
    text = str(raw_url or '').strip().rstrip('/')
    if not text:
        return ''
    parsed = urlparse(text)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return ''
    return f'{parsed.scheme}://{parsed.netloc}'


def get_request_base_url():
    trust_proxy = os.environ.get('FRP_TRUST_PROXY', '0') == '1'
    if trust_proxy:
        forwarded_host = str(request.headers.get('X-Forwarded-Host', '')).split(',')[0].strip()
        if forwarded_host:
            forwarded_proto = str(request.headers.get('X-Forwarded-Proto', '')).split(',')[0].strip()
            scheme = forwarded_proto or request.scheme or 'http'
            return normalize_base_url(f'{scheme}://{forwarded_host}')
    return normalize_base_url(request.url_root)


def validate_runtime_command(text, field_label):
    command = str(text or '').strip()
    if not command:
        raise ValidationError(f'{field_label}不能为空')
    if len(command) > MAX_RUNTIME_COMMAND_LENGTH:
        raise ValidationError(f'{field_label}长度不能超过 {MAX_RUNTIME_COMMAND_LENGTH} 字符')
    if '\n' in command or '\r' in command or '\x00' in command:
        raise ValidationError(f'{field_label}不能包含换行或空字符')
    return command


def validate_service_identifier(text, field_label='服务名'):
    value = str(text or '').strip()
    if not value:
        raise ValidationError(f'{field_label}不能为空')
    if not SERVICE_IDENTIFIER_PATTERN.fullmatch(value):
        raise ValidationError(f'{field_label}格式不正确')
    return value


def build_template_commands(template_name, service_name):
    normalized_template = str(template_name or '').strip().lower()
    normalized_service = validate_service_identifier(service_name)
    if normalized_template == 'systemd':
        return {
            'start_command': f'systemctl start {normalized_service}',
            'stop_command': f'systemctl stop {normalized_service}',
            'check_command': f'systemctl is-active --quiet {normalized_service}',
            'command_template': 'systemd',
            'service_name': normalized_service,
        }
    if normalized_template == 'service':
        return {
            'start_command': f'service {normalized_service} start',
            'stop_command': f'service {normalized_service} stop',
            'check_command': f'service {normalized_service} status',
            'command_template': 'service',
            'service_name': normalized_service,
        }
    raise ValidationError('command_template 仅支持 systemd 或 service')


def normalize_runtime_metadata(metadata):
    if not isinstance(metadata, dict):
        raise ValidationError('metadata 必须是对象')

    normalized = dict(metadata)
    template_name = str(normalized.get('command_template', '')).strip().lower()
    service_name = str(normalized.get('service_name', '')).strip()

    if template_name:
        template_commands = build_template_commands(template_name, service_name)
        for key, value in template_commands.items():
            normalized[key] = value

    return normalized


def validate_runtime_metadata(metadata, require_all_commands=True):
    normalized = normalize_runtime_metadata(metadata)
    if require_all_commands:
        normalized['start_command'] = validate_runtime_command(normalized.get('start_command', ''), '启动命令')
        normalized['stop_command'] = validate_runtime_command(normalized.get('stop_command', ''), '停止命令')
        if str(normalized.get('check_command', '')).strip():
            normalized['check_command'] = validate_runtime_command(normalized.get('check_command', ''), '检查命令')
    else:
        if 'start_command' in normalized and str(normalized.get('start_command', '')).strip():
            normalized['start_command'] = validate_runtime_command(normalized.get('start_command', ''), '启动命令')
        if 'stop_command' in normalized and str(normalized.get('stop_command', '')).strip():
            normalized['stop_command'] = validate_runtime_command(normalized.get('stop_command', ''), '停止命令')
        if 'check_command' in normalized and str(normalized.get('check_command', '')).strip():
            normalized['check_command'] = validate_runtime_command(normalized.get('check_command', ''), '检查命令')
    return normalized


def require_runtime_command_for_state(runtime, desired_state):
    metadata = validate_runtime_metadata(
        runtime.get('metadata') if isinstance(runtime.get('metadata'), dict) else {},
        require_all_commands=True,
    )
    command_key = 'start_command' if desired_state == 'running' else 'stop_command'
    command_name = '启动命令' if desired_state == 'running' else '停止命令'
    if not str(metadata.get(command_key, '')).strip():
        raise ValidationError(f'该应用未配置{command_name}，无法下发任务')


def get_job_audit_context(via='api'):
    user = get_logged_in_user() if is_logged_in() else 'system'
    user_agent = str(request.headers.get('User-Agent', '')).strip()
    if len(user_agent) > 256:
        user_agent = user_agent[:256]
    return {
        'created_by': user,
        'created_from_ip': get_client_ip(),
        'created_via': via,
        'created_from_path': str(request.path or ''),
        'created_user_agent': user_agent,
    }


def is_same_origin_request():
    origin = str(request.headers.get('Origin', '')).strip()
    referer = str(request.headers.get('Referer', '')).strip()
    expected = get_request_base_url()

    if origin:
        return normalize_base_url(origin) == expected
    if referer:
        parsed = urlparse(referer)
        referer_base = normalize_base_url(f'{parsed.scheme}://{parsed.netloc}')
        return referer_base == expected
    return True


def is_csrf_exempt_path(path):
    if path.startswith(AGENT_API_PREFIX):
        return True
    if path.startswith('/api/frps/server/') and path.endswith('/report'):
        return True
    if path.startswith('/api/frps/server/') and path.endswith('/deploy.sh'):
        return True
    return False


def get_manager_base_urls(server=None):
    candidates = []

    if isinstance(server, dict):
        candidates.append(server.get('manager_url'))

    public_url_env = str(os.environ.get('FRP_MANAGER_PUBLIC_URL', '')).strip()
    if public_url_env:
        candidates.extend([item for item in re.split(r'[\s,]+', public_url_env) if item])

    candidates.append(get_request_base_url())

    normalized = []
    seen = set()
    for candidate in candidates:
        base_url = normalize_base_url(candidate)
        if not base_url or base_url in seen:
            continue
        seen.add(base_url)
        normalized.append(base_url)
    return normalized


def sanitize_server(server):
    if not isinstance(server, dict):
        return server
    sanitized = dict(server)
    for field in SENSITIVE_SERVER_FIELDS:
        sanitized.pop(field, None)
    return sanitized


def sanitize_servers(servers):
    return [sanitize_server(server) for server in servers]


def sanitize_agent_node(node):
    if not isinstance(node, dict):
        return node
    sanitized = dict(node)
    for field in SENSITIVE_NODE_FIELDS:
        sanitized.pop(field, None)
    return sanitized


def sanitize_agent_nodes(nodes):
    return [sanitize_agent_node(node) for node in nodes]


def get_bearer_token():
    auth_header = str(request.headers.get('Authorization', '')).strip()
    if not auth_header:
        return ''
    prefix = 'bearer '
    if auth_header.lower().startswith(prefix):
        return auth_header[len(prefix):].strip()
    return ''


def parse_agent_auth_payload():
    payload = parse_json_body()
    node_id = str(payload.get('node_id', '')).strip()
    token = get_bearer_token()
    if not node_id:
        raise ValidationError('node_id 不能为空')
    if not token:
        raise ValidationError('缺少 Bearer token')
    return node_id, token, payload


def ensure_agent_identity():
    node_id, token, payload = parse_agent_auth_payload()
    if not verify_agent_node_token(node_id, token):
        return None, None, error_response('agent 认证失败', 401)
    node = get_agent_node(node_id)
    if not node:
        return None, None, error_response('节点不存在', 404)
    return node, payload, None


def ensure_server_deploy_key(server):
    if not isinstance(server, dict):
        return ''
    deploy_key = str(server.get('deploy_key', '')).strip()
    if deploy_key:
        return deploy_key

    deploy_key = generate_deploy_key()
    server_id = str(server.get('id', '')).strip()
    if server_id:
        update_frps_server(server_id, {'deploy_key': deploy_key})
    server['deploy_key'] = deploy_key
    return deploy_key


def build_frps_deploy_script_url(base_url, server_id, deploy_key):
    normalized_base = normalize_base_url(base_url)
    normalized_server_id = str(server_id or '').strip()
    normalized_deploy_key = str(deploy_key or '').strip()
    if not normalized_base or not normalized_server_id or not normalized_deploy_key:
        return ''
    return (
        f'{normalized_base}/api/frps/server/{quote(normalized_server_id, safe="")}/deploy.sh'
        f'?deploy_key={quote_plus(normalized_deploy_key)}'
    )


def get_frps_deploy_script_urls(server, manager_base_urls=None):
    if not isinstance(server, dict):
        return []

    deploy_key = ensure_server_deploy_key(server)
    server_id = str(server.get('id', '')).strip()
    if not deploy_key or not server_id:
        return []

    candidate_base_urls = manager_base_urls if manager_base_urls is not None else get_manager_base_urls(server)
    script_urls = []
    seen_urls = set()
    for base_url in candidate_base_urls:
        script_url = build_frps_deploy_script_url(base_url, server_id, deploy_key)
        if not script_url or script_url in seen_urls:
            continue
        seen_urls.add(script_url)
        script_urls.append(script_url)
    return script_urls


def build_frps_one_click_command(script_urls):
    normalized_urls = [str(url).strip() for url in (script_urls or []) if str(url).strip()]
    if not normalized_urls:
        return ''
    if len(normalized_urls) == 1:
        return f'curl -fsSL {shell_single_quote(normalized_urls[0])} | (command -v sudo >/dev/null 2>&1 && sudo bash || bash)'

    joined_urls = ' '.join(shell_single_quote(url) for url in normalized_urls)
    return (
        f'for deploy_url in {joined_urls}; do '
        'if curl -fsSL "$deploy_url" | (command -v sudo >/dev/null 2>&1 && sudo bash || bash); then exit 0; fi; '
        'echo "deploy url unreachable: $deploy_url" >&2; '
        'done; '
        'echo "all deploy urls failed, check FRP_MANAGER_PUBLIC_URL or manager_url." >&2; '
        'exit 1'
    )

def build_frps_deploy_payload(server):
    manager_urls = get_manager_base_urls(server)
    deploy_script = build_frps_deploy_command(server, manager_base_urls=manager_urls)
    deploy_urls = get_frps_deploy_script_urls(server, manager_base_urls=manager_urls)
    one_click_command = build_frps_one_click_command(deploy_urls) or deploy_script
    return {
        'manager_urls': manager_urls,
        'deploy_script': deploy_script,
        'deploy_urls': deploy_urls,
        'deploy_url': deploy_urls[0] if deploy_urls else '',
        'one_click_command': one_click_command,
    }


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def parse_report_timestamp(raw_timestamp):
    text = str(raw_timestamp or '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = f'{text[:-1]}+00:00'
    try:
        timestamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def has_recent_report(last_report_at):
    if REPORT_ONLINE_TTL <= 0:
        return False
    timestamp = parse_report_timestamp(last_report_at)
    if not timestamp:
        return False
    age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
    return age_seconds <= REPORT_ONLINE_TTL


def normalize_server_addr(server_addr):
    return str(server_addr or '').strip()


def has_server_address(server_addr):
    return bool(normalize_server_addr(server_addr))


def check_frps_status(server_addr, server_port, last_report_at=None):
    if has_recent_report(last_report_at):
        return 'online'
    host = normalize_server_addr(server_addr)
    if not host:
        return 'pending'
    try:
        port = int(server_port)
    except (TypeError, ValueError):
        return 'offline'

    try:
        with socket.create_connection((host, port), timeout=STATUS_TIMEOUT):
            return 'online'
    except OSError:
        return 'offline'


def get_cached_status(server_id):
    if not server_id:
        return None

    with status_cache_lock:
        cache = status_cache.get(server_id)
    if not cache:
        return None

    status, timestamp = cache
    if time.monotonic() - timestamp > STATUS_CACHE_TTL:
        return None
    return status


def set_cached_status(server_id, status):
    if not server_id:
        return
    with status_cache_lock:
        status_cache[server_id] = (status, time.monotonic())


def clear_cached_status(server_id):
    if not server_id:
        return
    with status_cache_lock:
        status_cache.pop(server_id, None)


def attach_server_statuses(servers, refresh=False):
    if not servers:
        return

    if not refresh:
        for server in servers:
            server_id = str(server.get('id', ''))
            cached_status = get_cached_status(server_id)
            if cached_status:
                server['status'] = cached_status
            elif has_recent_report(server.get('last_report_at')):
                server['status'] = 'online'
            elif not has_server_address(server.get('server_addr')):
                server['status'] = 'pending'
            else:
                server['status'] = 'unknown'
        return

    worker_count = min(max(1, STATUS_WORKERS), len(servers))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {}
        for server in servers:
            future = pool.submit(
                check_frps_status,
                server.get('server_addr'),
                server.get('server_port'),
                server.get('last_report_at'),
            )
            futures[future] = server

        for future in as_completed(futures):
            server = futures[future]
            try:
                status = future.result()
            except Exception:
                status = 'offline'
            server['status'] = status
            set_cached_status(str(server.get('id', '')), status)


def find_port(server, port_id):
    for port in server.get('ports', []):
        if port.get('id') == port_id:
            return port
    return None


@app.errorhandler(ValidationError)
def handle_validation_error(error):
    return error_response(str(error), 422)


@app.errorhandler(404)
def handle_not_found(_error):
    if request.path.startswith('/api/'):
        return error_response('请求的资源不存在', 404)
    return _error


@app.errorhandler(500)
def handle_internal_error(_error):
    if request.path.startswith('/api/'):
        return error_response('服务器内部错误', 500)
    return _error


@app.before_request
def enforce_auth_flow():
    endpoint = request.endpoint or ''
    path = request.path or ''
    is_report_callback = path.startswith('/api/frps/server/') and path.endswith('/report')
    is_deploy_script = path.startswith('/api/frps/server/') and path.endswith('/deploy.sh')
    is_agent_v1_api = path.startswith(AGENT_API_PREFIX)

    if endpoint == 'static':
        return None

    setup_done = is_auth_initialized()
    api_request = path.startswith('/api/')

    auth_allowed_paths = {
        '/login',
        '/setup',
        '/logout',
    }
    auth_allowed_api_paths = {
        '/api/auth/status',
    }

    if not setup_done:
        if api_request and path not in auth_allowed_api_paths and not is_report_callback and not is_deploy_script:
            return error_response('管理员账号未初始化，请先完成首次设置', 403)
        if not api_request and path != '/setup':
            return redirect(url_for('setup_page'))
        return None

    if path == '/setup':
        return redirect(url_for('index'))

    if path in auth_allowed_paths or path in auth_allowed_api_paths or is_report_callback or is_deploy_script or is_agent_v1_api:
        return None

    if is_logged_in():
        return None

    if api_request:
        return error_response('未登录或登录已过期', 401)
    return redirect(url_for('login_page'))


@app.before_request
def enforce_security_controls():
    path = request.path or ''
    method = (request.method or 'GET').upper()

    if request.endpoint == 'static':
        return None

    ip = get_client_ip()
    is_api = path.startswith('/api/')

    if method in {'POST', 'PUT', 'DELETE', 'PATCH'} and is_logged_in() and not is_csrf_exempt_path(path):
        if not is_same_origin_request():
            if is_api:
                return error_response('请求来源无效', 403)
            return Response('Forbidden', status=403)

    if path == '/login' and method == 'POST':
        if hit_rate_limit('login', ip, LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW):
            return Response('登录尝试过于频繁，请稍后再试', status=429, mimetype='text/plain; charset=utf-8')

    if path == '/setup' and method == 'POST':
        if hit_rate_limit('setup', ip, SETUP_RATE_LIMIT, SETUP_RATE_WINDOW):
            return Response('初始化提交过于频繁，请稍后再试', status=429, mimetype='text/plain; charset=utf-8')

    if path.startswith('/api/frps/server/') and path.endswith('/deploy.sh'):
        if hit_rate_limit('deploy_script', ip, DEPLOY_SCRIPT_RATE_LIMIT, DEPLOY_SCRIPT_RATE_WINDOW):
            return Response('echo "请求过于频繁" >&2\nexit 1\n', status=429, mimetype='text/plain; charset=utf-8')

    if path == '/api/agent/v1/pull' and method == 'POST':
        payload = request.get_json(silent=True)
        node_id = str(payload.get('node_id', '')).strip() if isinstance(payload, dict) else ''
        key = f'{ip}:{node_id or "unknown"}'
        if hit_rate_limit('agent_pull', key, AGENT_PULL_RATE_LIMIT, AGENT_PULL_RATE_WINDOW):
            return error_response('拉取任务过于频繁，请稍后再试', 429)

    return None


@app.after_request
def apply_security_headers(response):
    path = request.path or ''

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    if path.startswith('/api/') or path in {'/', '/login', '/setup'}:
        response.headers['Cache-Control'] = 'no-store'

    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


@app.route('/setup', methods=['GET', 'POST'])
def setup_page():
    if is_auth_initialized():
        if is_logged_in():
            return redirect(url_for('index'))
        return redirect(url_for('login_page'))

    if request.method == 'GET':
        return render_template('setup.html', error=None, username='')

    username = request.form.get('username', '')
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    expected_setup_token = str(os.environ.get('FRP_SETUP_TOKEN', '')).strip()
    if expected_setup_token:
        supplied_setup_token = str(request.form.get('setup_token', '')).strip() or str(request.headers.get('X-Setup-Token', '')).strip()
        if not supplied_setup_token or not secrets.compare_digest(supplied_setup_token, expected_setup_token):
            return render_template('setup.html', error='初始化令牌无效', username=str(username or '').strip()), 403

    try:
        normalized_username, normalized_password = validate_auth_payload(username, password, confirm_password)
    except ValidationError as error:
        return render_template('setup.html', error=str(error), username=str(username or '').strip()), 422

    password_hash = generate_password_hash(normalized_password)
    set_admin_credentials(normalized_username, password_hash)
    session.clear()
    session.permanent = True
    session[SESSION_USER_KEY] = normalized_username
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if not is_auth_initialized():
        return redirect(url_for('setup_page'))

    if request.method == 'GET':
        if is_logged_in():
            return redirect(url_for('index'))
        return render_template('login.html', error=None, username='')

    username = str(request.form.get('username', '')).strip()
    password = str(request.form.get('password', ''))
    auth = get_auth_config()

    if not username or not password:
        return render_template('login.html', error='请输入账号和密码', username=username), 422
    if username != str(auth.get('admin_username', '')).strip():
        return render_template('login.html', error='账号或密码错误', username=username), 401
    if not check_password_hash(str(auth.get('password_hash', '')), password):
        return render_template('login.html', error='账号或密码错误', username=username), 401

    session.clear()
    session.permanent = True
    session[SESSION_USER_KEY] = username
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    if request.path.startswith('/api/'):
        return success_response()
    if is_auth_initialized():
        return redirect(url_for('login_page'))
    return redirect(url_for('setup_page'))


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    setup_done = is_auth_initialized()
    return success_response({
        'setup_completed': setup_done,
        'logged_in': is_logged_in(),
        'admin_user': get_logged_in_user() if is_logged_in() else '',
    })


@app.route('/')
def index():
    return render_template('index.html', admin_user=get_logged_in_user())


@app.route('/api/meta/local-ip', methods=['GET'])
def get_meta_local_ip():
    return success_response({'local_ip': get_local_ip()})


@app.route('/api/frps/servers', methods=['GET'])
def frps_servers_list():
    refresh = request.args.get('refresh', '0').lower() in {'1', 'true', 'yes'}
    servers = get_frps_servers()
    attach_server_statuses(servers, refresh=refresh)
    return jsonify(sanitize_servers(servers))


@app.route('/api/frps/server', methods=['POST'])
def add_frps():
    raw_payload = parse_json_body()
    if not str(raw_payload.get('token', '')).strip():
        raw_payload['token'] = generate_server_token()
    payload = validate_server_create(raw_payload, get_local_ip())
    payload['deploy_key'] = generate_deploy_key()
    payload['last_report_at'] = ''
    server = add_frps_server(payload)
    clear_cached_status(str(server.get('id', '')))
    deploy_payload = build_frps_deploy_payload(server)
    return success_response(
        {
            'server': sanitize_server(server),
            'deploy_command': deploy_payload['one_click_command'],
            'deploy_script': deploy_payload['deploy_script'],
            'deploy_url': deploy_payload['deploy_url'],
            'deploy_urls': deploy_payload['deploy_urls'],
            'local_ip': get_local_ip(),
            'manager_urls': deploy_payload['manager_urls'],
        },
        status_code=201,
    )


@app.route('/api/frps/server/<server_id>', methods=['GET'])
def get_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    server['status'] = check_frps_status(server.get('server_addr'), server.get('server_port'), server.get('last_report_at'))
    set_cached_status(str(server.get('id', '')), server['status'])
    return jsonify(sanitize_server(server))


@app.route('/api/frps/server/<server_id>/deploy', methods=['GET'])
def get_frps_deploy(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    deploy_payload = build_frps_deploy_payload(server)
    return success_response({
        'command': deploy_payload['one_click_command'],
        'script': deploy_payload['deploy_script'],
        'deploy_url': deploy_payload['deploy_url'],
        'deploy_urls': deploy_payload['deploy_urls'],
        'server': sanitize_server(server),
        'manager_urls': deploy_payload['manager_urls'],
    })


@app.route('/api/frps/server/<server_id>/deploy.sh', methods=['GET'])
def get_frps_deploy_script(server_id):
    server = get_frps_server(server_id)
    if not server:
        return Response('echo "FRPS 服务器不存在" >&2\nexit 1\n', status=404, mimetype='text/plain; charset=utf-8')

    deploy_key = str(request.headers.get('X-Deploy-Key', '')).strip() or str(request.args.get('deploy_key', '')).strip()
    expected_key = ensure_server_deploy_key(server)
    if not deploy_key or not expected_key or not secrets.compare_digest(deploy_key, expected_key):
        return Response('echo "deploy_key 无效" >&2\nexit 1\n', status=403, mimetype='text/plain; charset=utf-8')

    deploy_payload = build_frps_deploy_payload(server)
    script = str(deploy_payload.get('deploy_script', '')).strip()
    body = '#!/usr/bin/env bash\nset -euo pipefail\n\n' + script + '\n'
    response = Response(body, mimetype='text/plain; charset=utf-8')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/api/frps/server/<server_id>', methods=['PUT'])
def update_frps(server_id):
    updates = validate_server_update(parse_json_body())
    updated = update_frps_server(server_id, updates)
    if not updated:
        return error_response('服务器不存在', 404)
    clear_cached_status(server_id)
    return success_response()


@app.route('/api/frps/server/<server_id>', methods=['DELETE'])
def delete_frps(server_id):
    deleted = delete_frps_server(server_id)
    if not deleted:
        return error_response('服务器不存在', 404)
    clear_cached_status(server_id)
    return success_response()


@app.route('/api/frps/server/<server_id>/check', methods=['POST'])
def check_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    status = check_frps_status(server.get('server_addr'), server.get('server_port'), server.get('last_report_at'))
    set_cached_status(str(server.get('id', '')), status)
    return success_response({'status': status})


def validate_server_addr_ready(server):
    if has_server_address(server.get('server_addr')):
        return None
    return error_response('服务器地址尚未识别，请先在目标子服务器执行 FRPS 一键部署命令', 409)


@app.route('/api/frps/server/<server_id>/report', methods=['POST'])
def report_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)

    payload = parse_json_body()
    report_token = str(payload.get('token', '')).strip()
    if not report_token or report_token != str(server.get('token', '')).strip():
        return error_response('回报令牌无效', 403)

    updates_payload = {}
    if 'server_addr' in payload:
        updates_payload['server_addr'] = payload.get('server_addr')
    if 'server_port' in payload:
        updates_payload['server_port'] = payload.get('server_port')

    if updates_payload:
        updates = validate_server_update(updates_payload)
        updates['last_report_at'] = utc_now_iso()
        update_frps_server(server_id, updates)
        server.update(updates)
    else:
        updates = {'last_report_at': utc_now_iso()}
        update_frps_server(server_id, updates)
        server.update(updates)

    set_cached_status(server_id, 'online')
    return success_response({
        'server_id': server_id,
        'server_addr': server.get('server_addr'),
        'server_port': server.get('server_port'),
        'last_report_at': server.get('last_report_at'),
        'status': 'online',
    })


@app.route('/api/frps/server/<server_id>/ports', methods=['GET'])
def get_ports(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    return jsonify(server.get('ports', []))


@app.route('/api/frps/server/<server_id>/port', methods=['POST'])
def add_port(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    port_config = validate_port_create(parse_json_body())
    created = add_port_mapping(server_id, port_config)
    if not created:
        return error_response('服务器不存在', 404)
    return success_response({'port': created}, status_code=201)


@app.route('/api/frps/server/<server_id>/port/<port_id>', methods=['PUT'])
def update_port(server_id, port_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)

    current_port = find_port(server, port_id)
    if not current_port:
        return error_response('端口映射不存在', 404)

    validated_port = validate_port_update(parse_json_body(), current_port)
    updated = update_port_mapping(server_id, port_id, validated_port)
    if not updated:
        return error_response('端口映射不存在', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/port/<port_id>', methods=['DELETE'])
def delete_port(server_id, port_id):
    deleted = delete_port_mapping(server_id, port_id)
    if not deleted:
        return error_response('端口映射不存在', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/port/<port_id>/toggle', methods=['POST'])
def toggle_port(server_id, port_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)

    current_port = find_port(server, port_id)
    if not current_port:
        return error_response('端口映射不存在', 404)

    updated = update_port_mapping(server_id, port_id, {'enabled': not current_port.get('enabled', True)})
    if not updated:
        return error_response('端口映射不存在', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/generate_frpc', methods=['GET'])
def generate_frpc_for_server(server_id):
    security_profile = validate_security_profile(request.args.get('security_profile', 'balanced'))
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    addr_error = validate_server_addr_ready(server)
    if addr_error:
        return addr_error

    profile_summary = get_security_profile_summary(security_profile)
    config = build_frpc_config(server, server.get('ports', []), security_profile=profile_summary['id'])
    return success_response({'config': config, 'server': server, 'security_profile': profile_summary})


@app.route('/api/frps/server/<server_id>/port/<port_id>/deploy', methods=['GET'])
def generate_frpc_deploy(server_id, port_id):
    system = validate_system(request.args.get('system', 'linux'))
    security_profile = validate_security_profile(request.args.get('security_profile', 'balanced'))
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    addr_error = validate_server_addr_ready(server)
    if addr_error:
        return addr_error

    port = find_port(server, port_id)
    if not port:
        return error_response('端口映射不存在', 404)

    profile_summary = get_security_profile_summary(security_profile)
    command = build_frpc_deploy_command(server, port, system=system, security_profile=profile_summary['id'])
    return success_response({'command': command, 'security_profile': profile_summary})


@app.route('/api/frpc/configs', methods=['GET'])
def frpc_configs_list():
    return jsonify(get_frpc_configs())


@app.route('/api/frpc/config', methods=['POST'])
def frpc_config_create():
    config = parse_json_body()
    saved = save_frpc_config(config)
    return success_response({'config': saved}, status_code=201)


@app.route('/api/frpc/config/<config_id>', methods=['DELETE'])
def delete_frpc(config_id):
    deleted = delete_frpc_config(config_id)
    if not deleted:
        return error_response('客户端配置不存在', 404)
    return success_response()


@app.route('/api/agent/nodes', methods=['GET'])
def list_agent_nodes():
    return jsonify(sanitize_agent_nodes(get_agent_nodes()))


@app.route('/api/agent/node', methods=['POST'])
def create_agent_node_route():
    payload = parse_json_body()
    name = str(payload.get('name', '')).strip()
    if not name:
        raise ValidationError('节点名称不能为空')

    labels = payload.get('labels')
    if labels is None:
        labels = []
    if not isinstance(labels, list):
        raise ValidationError('labels 必须是数组')

    agent_token = generate_deploy_key()
    created = create_agent_node(
        {
            'name': name,
            'labels': [str(item).strip() for item in labels if str(item).strip()],
            'hostname': str(payload.get('hostname', '')).strip(),
            'platform': str(payload.get('platform', '')).strip(),
            'agent_version': str(payload.get('agent_version', '')).strip(),
            'status': 'offline',
        },
        token=agent_token,
    )
    return success_response({'node': sanitize_agent_node(created), 'agent_token': agent_token}, status_code=201)


@app.route('/api/agent/node/<node_id>', methods=['GET'])
def get_agent_node_route(node_id):
    node = get_agent_node(node_id)
    if not node:
        return error_response('节点不存在', 404)
    return success_response({'node': sanitize_agent_node(node)})


@app.route('/api/agent/node/<node_id>', methods=['PUT'])
def update_agent_node_route(node_id):
    payload = parse_json_body()
    updates = {}

    if 'name' in payload:
        name = str(payload.get('name', '')).strip()
        if not name:
            raise ValidationError('节点名称不能为空')
        updates['name'] = name

    if 'labels' in payload:
        labels = payload.get('labels')
        if not isinstance(labels, list):
            raise ValidationError('labels 必须是数组')
        updates['labels'] = [str(item).strip() for item in labels if str(item).strip()]

    if 'hostname' in payload:
        updates['hostname'] = str(payload.get('hostname', '')).strip()
    if 'platform' in payload:
        updates['platform'] = str(payload.get('platform', '')).strip()
    if 'agent_version' in payload:
        updates['agent_version'] = str(payload.get('agent_version', '')).strip()
    if 'status' in payload:
        updates['status'] = str(payload.get('status', '')).strip() or 'unknown'

    if not updates:
        raise ValidationError('至少需要一个可更新字段')

    updated = update_agent_node(node_id, updates)
    if not updated:
        return error_response('节点不存在', 404)
    return success_response()


@app.route('/api/agent/node/<node_id>', methods=['DELETE'])
def delete_agent_node_route(node_id):
    deleted = delete_agent_node(node_id)
    if not deleted:
        return error_response('节点不存在', 404)
    return success_response()


@app.route('/api/agent/node/<node_id>/rotate-token', methods=['POST'])
def rotate_agent_node_token_route(node_id):
    node = get_agent_node(node_id)
    if not node:
        return error_response('节点不存在', 404)

    new_token = generate_deploy_key()
    rotated = rotate_agent_node_token(node_id, new_token)
    if not rotated:
        return error_response('节点不存在', 404)

    return success_response({'node_id': node_id, 'agent_token': new_token})


def build_agent_script_urls(node_id):
    script_urls = []
    seen = set()
    for base_url in get_manager_base_urls():
        script_url = f"{base_url}/static/agent/frp_agent.py"
        if script_url in seen:
            continue
        seen.add(script_url)
        script_urls.append(script_url)
    return script_urls


def build_agent_bootstrap_command(node_id, token, manager_url, script_url):
    return (
        "mkdir -p /opt/frp-agent && "
        "curl -fsSL "
        f"{shell_single_quote(script_url)} "
        "-o /opt/frp-agent/frp_agent.py && "
        f"NODE_ID={shell_single_quote(node_id)} "
        f"NODE_TOKEN={shell_single_quote(token)} "
        f"MANAGER_URL={shell_single_quote(manager_url)} "
        "POLL_INTERVAL=5 "
        "python3 /opt/frp-agent/frp_agent.py"
    )


@app.route('/api/agent/node/<node_id>/bootstrap', methods=['POST'])
def build_agent_bootstrap(node_id):
    node = get_agent_node(node_id)
    if not node:
        return error_response('节点不存在', 404)

    new_token = generate_deploy_key()
    rotated = rotate_agent_node_token(node_id, new_token)
    if not rotated:
        return error_response('节点不存在', 404)

    script_urls = build_agent_script_urls(node_id)
    if not script_urls:
        return error_response('无法生成 agent 脚本地址', 422)

    manager_urls = get_manager_base_urls()
    manager_url = manager_urls[0] if manager_urls else ''
    command = build_agent_bootstrap_command(node_id, new_token, manager_url, script_urls[0])
    return success_response(
        {
            'node_id': node_id,
            'agent_token': new_token,
            'manager_url': manager_url,
            'script_url': script_urls[0],
            'script_urls': script_urls,
            'command': command,
        }
    )


def build_agent_job_payload(job_type, node_id, payload, max_attempts=1, idempotency_key='', audit_context=None):
    normalized_type = str(job_type or '').strip()
    normalized_node_id = str(node_id or '').strip()
    if not normalized_type:
        raise ValidationError('任务类型不能为空')
    if normalized_type not in ALLOWED_AGENT_JOB_TYPES:
        raise ValidationError('不支持的任务类型')
    if not normalized_node_id:
        raise ValidationError('node_id 不能为空')
    if not get_agent_node(normalized_node_id):
        raise ValidationError('目标节点不存在')

    normalized_payload = payload if isinstance(payload, dict) else {}
    normalized_key = str(idempotency_key or '').strip() or secrets.token_hex(16)
    audit = audit_context if isinstance(audit_context, dict) else {}
    return {
        'node_id': normalized_node_id,
        'type': normalized_type,
        'payload': normalized_payload,
        'max_attempts': max(1, int(max_attempts)),
        'idempotency_key': normalized_key,
        'created_by': str(audit.get('created_by', '')).strip(),
        'created_from_ip': str(audit.get('created_from_ip', '')).strip(),
        'created_via': str(audit.get('created_via', '')).strip() or 'api',
        'created_from_path': str(audit.get('created_from_path', '')).strip(),
        'created_user_agent': str(audit.get('created_user_agent', '')).strip(),
    }


@app.route('/api/agent/jobs', methods=['GET'])
def list_agent_jobs():
    node_id = str(request.args.get('node_id', '')).strip() or None
    status_param = str(request.args.get('status', '')).strip()
    statuses = [item.strip() for item in status_param.split(',') if item.strip()] if status_param else None
    return jsonify(get_agent_jobs(node_id=node_id, statuses=statuses))


@app.route('/api/agent/job', methods=['POST'])
def create_agent_job_route():
    body = parse_json_body()
    audit_context = get_job_audit_context(via='admin_api')
    payload = build_agent_job_payload(
        job_type=body.get('type'),
        node_id=body.get('node_id'),
        payload=body.get('payload'),
        max_attempts=body.get('max_attempts', 1),
        idempotency_key=body.get('idempotency_key', ''),
        audit_context=audit_context,
    )
    try:
        created = create_agent_job(payload)
    except ValueError as error:
        raise ValidationError(str(error))
    return success_response({'job': created}, status_code=201)


@app.route('/api/agent/jobs/batch', methods=['POST'])
def create_agent_batch_jobs_route():
    body = parse_json_body()
    audit_context = get_job_audit_context(via='admin_batch_api')
    node_ids = body.get('node_ids')
    if not isinstance(node_ids, list) or not node_ids:
        raise ValidationError('node_ids 必须是非空数组')

    job_type = body.get('type')
    payload = body.get('payload')
    max_attempts = body.get('max_attempts', 1)
    batch_key = str(body.get('batch_idempotency_key', '')).strip() or secrets.token_hex(16)
    created_jobs = []

    for node_id in node_ids:
        normalized_node_id = str(node_id or '').strip()
        job_payload = build_agent_job_payload(
            job_type=job_type,
            node_id=normalized_node_id,
            payload=payload,
            max_attempts=max_attempts,
            idempotency_key=f'{batch_key}:{normalized_node_id}',
            audit_context=audit_context,
        )
        try:
            created_jobs.append(create_agent_job(job_payload))
        except ValueError as error:
            raise ValidationError(str(error))

    return success_response({'jobs': created_jobs}, status_code=201)


@app.route('/api/agent/job/<job_id>/retry', methods=['POST'])
def retry_agent_job_route(job_id):
    existing = get_agent_job(job_id)
    if not existing:
        return error_response('任务不存在', 404)

    status = str(existing.get('status', '')).strip()
    if status != 'failed':
        return error_response('仅失败任务允许重试', 409)

    try:
        retry_payload = build_agent_job_payload(
            job_type=existing.get('type'),
            node_id=existing.get('node_id'),
            payload=existing.get('payload') if isinstance(existing.get('payload'), dict) else {},
            max_attempts=existing.get('max_attempts', 1),
            idempotency_key=f"retry:{job_id}:{secrets.token_hex(8)}",
            audit_context=get_job_audit_context(via='retry_api'),
        )
        created = create_agent_job(retry_payload)
    except (ValidationError, ValueError) as error:
        raise ValidationError(str(error))

    return success_response({'job': created}, status_code=201)


@app.route('/api/agent/runtimes', methods=['GET'])
def list_agent_runtimes():
    node_id = str(request.args.get('node_id', '')).strip() or None
    return jsonify(get_agent_runtimes(node_id=node_id))


@app.route('/api/agent/runtime', methods=['POST'])
def create_agent_runtime_route():
    body = parse_json_body()
    node_id = str(body.get('node_id', '')).strip()
    if not node_id:
        raise ValidationError('node_id 不能为空')
    if not get_agent_node(node_id):
        raise ValidationError('目标节点不存在')

    metadata = validate_runtime_metadata(body.get('metadata'), require_all_commands=True)

    runtime_id = str(body.get('id', '')).strip() or secrets.token_hex(12)
    try:
        saved = upsert_agent_runtime(
            {
                'id': runtime_id,
                'node_id': node_id,
                'kind': str(body.get('kind', '')).strip() or 'frpc',
                'name': str(body.get('name', '')).strip() or runtime_id,
                'status': str(body.get('status', '')).strip() or 'unknown',
                'enabled': bool(body.get('enabled', True)),
                'last_heartbeat_at': str(body.get('last_heartbeat_at', '')).strip(),
                'metadata': metadata,
            }
        )
    except ValueError as error:
        raise ValidationError(str(error))
    return success_response({'runtime': saved}, status_code=201)


@app.route('/api/agent/runtime/<runtime_id>', methods=['PUT'])
def update_agent_runtime_route(runtime_id):
    current = get_agent_runtime(runtime_id)
    if not current:
        return error_response('运行实例不存在', 404)

    body = parse_json_body()
    merged = dict(current)
    if 'kind' in body:
        merged['kind'] = str(body.get('kind', '')).strip() or merged.get('kind', 'frpc')
    if 'name' in body:
        merged['name'] = str(body.get('name', '')).strip() or merged.get('name', runtime_id)
    if 'status' in body:
        merged['status'] = str(body.get('status', '')).strip() or merged.get('status', 'unknown')
    if 'enabled' in body:
        merged['enabled'] = bool(body.get('enabled', True))
    if 'metadata' in body and isinstance(body.get('metadata'), dict):
        metadata = dict(merged.get('metadata', {}))
        metadata.update(validate_runtime_metadata(body.get('metadata'), require_all_commands=False))
        merged['metadata'] = metadata

    merged['metadata'] = validate_runtime_metadata(merged.get('metadata', {}), require_all_commands=True)

    try:
        saved = upsert_agent_runtime(merged)
    except ValueError as error:
        raise ValidationError(str(error))
    return success_response({'runtime': saved})


def queue_runtime_state_job(runtime_id, desired_state):
    runtime = get_agent_runtime(runtime_id)
    if not runtime:
        return None, error_response('运行实例不存在', 404)

    node_id = str(runtime.get('node_id', '')).strip()
    if not node_id:
        return None, error_response('运行实例缺少 node_id', 422)

    try:
        require_runtime_command_for_state(runtime, desired_state)
        metadata = validate_runtime_metadata(
            runtime.get('metadata') if isinstance(runtime.get('metadata'), dict) else {},
            require_all_commands=True,
        )
    except ValidationError as error:
        return None, error_response(str(error), 422)

    job_type = 'instance.ensure_running' if desired_state == 'running' else 'instance.ensure_stopped'
    payload = {
        'runtime_id': runtime_id,
        'desired_state': desired_state,
        'kind': runtime.get('kind', ''),
        'name': runtime.get('name', ''),
        'metadata': metadata,
    }

    try:
        created = create_agent_job(
            build_agent_job_payload(
                job_type=job_type,
                node_id=node_id,
                payload=payload,
                max_attempts=1,
                idempotency_key=f'{runtime_id}:{desired_state}',
                audit_context=get_job_audit_context(via='runtime_control'),
            )
        )
    except (ValidationError, ValueError) as error:
        return None, error_response(str(error), 422)
    return created, None


@app.route('/api/agent/runtime/<runtime_id>/ensure-running', methods=['POST'])
def ensure_runtime_running(runtime_id):
    created, error = queue_runtime_state_job(runtime_id, 'running')
    if error:
        return error
    return success_response({'job': created}, status_code=201)


@app.route('/api/agent/runtime/<runtime_id>/ensure-stopped', methods=['POST'])
def ensure_runtime_stopped(runtime_id):
    created, error = queue_runtime_state_job(runtime_id, 'stopped')
    if error:
        return error
    return success_response({'job': created}, status_code=201)


@app.route('/api/agent/v1/register', methods=['POST'])
def agent_register():
    node, payload, auth_error = ensure_agent_identity()
    if auth_error:
        return auth_error
    if not isinstance(node, dict) or not isinstance(payload, dict):
        return error_response('agent 身份无效', 401)

    updated = touch_agent_node(
        node.get('id', ''),
        {
            'status': 'online',
            'hostname': str(payload.get('hostname', '')).strip() or str(node.get('hostname', '')).strip(),
            'platform': str(payload.get('platform', '')).strip() or str(node.get('platform', '')).strip(),
            'agent_version': str(payload.get('agent_version', '')).strip() or str(node.get('agent_version', '')).strip(),
        },
    )
    return success_response({'node': sanitize_agent_node(updated)})


@app.route('/api/agent/v1/pull', methods=['POST'])
def agent_pull_jobs():
    node, payload, auth_error = ensure_agent_identity()
    if auth_error:
        return auth_error
    if not isinstance(node, dict) or not isinstance(payload, dict):
        return error_response('agent 身份无效', 401)

    lease_seconds = payload.get('lease_seconds', 45)
    try:
        lease_seconds = int(lease_seconds)
    except (TypeError, ValueError):
        lease_seconds = 45

    touch_agent_node(
        node.get('id', ''),
        {
            'status': 'online',
            'hostname': str(payload.get('hostname', '')).strip() or str(node.get('hostname', '')).strip(),
            'platform': str(payload.get('platform', '')).strip() or str(node.get('platform', '')).strip(),
            'agent_version': str(payload.get('agent_version', '')).strip() or str(node.get('agent_version', '')).strip(),
        },
    )

    leased_job = lease_agent_job_for_node(node.get('id', ''), lease_seconds=lease_seconds)
    if not leased_job:
        return success_response({'jobs': [], 'poll_after_sec': 10})
    return success_response({'jobs': [leased_job], 'poll_after_sec': 2})


@app.route('/api/agent/v1/jobs/<job_id>/start', methods=['POST'])
def agent_mark_job_running(job_id):
    node, payload, auth_error = ensure_agent_identity()
    if auth_error:
        return auth_error
    if not isinstance(node, dict) or not isinstance(payload, dict):
        return error_response('agent 身份无效', 401)

    lease_id = str(payload.get('lease_id', '')).strip()
    if not lease_id:
        raise ValidationError('lease_id 不能为空')

    existing = get_agent_job(job_id)
    if not existing:
        return error_response('任务不存在', 404)

    if str(existing.get('status', '')).strip() in {'succeeded', 'failed'}:
        return success_response({'job': existing})

    running = mark_agent_job_running(job_id, node.get('id', ''), lease_id)
    if not running:
        return error_response('任务领取无效或租约已过期', 409)
    return success_response({'job': running})


@app.route('/api/agent/v1/jobs/<job_id>/complete', methods=['POST'])
def agent_complete_job(job_id):
    node, payload, auth_error = ensure_agent_identity()
    if auth_error:
        return auth_error
    if not isinstance(node, dict) or not isinstance(payload, dict):
        return error_response('agent 身份无效', 401)

    lease_id = str(payload.get('lease_id', '')).strip()
    if not lease_id:
        raise ValidationError('lease_id 不能为空')

    success = bool(payload.get('success', False))
    result = payload.get('result')
    error_text = str(payload.get('error', '')).strip()

    existing = get_agent_job(job_id)
    if not existing:
        return error_response('任务不存在', 404)

    if str(existing.get('status', '')).strip() in {'succeeded', 'failed'}:
        return success_response({'job': existing})

    completed = complete_agent_job(job_id, node.get('id', ''), lease_id, success=success, result=result, error=error_text)
    if not completed:
        return error_response('任务完成上报无效', 409)
    return success_response({'job': completed})


@app.route('/api/agent/v1/runtime/report', methods=['POST'])
def agent_report_runtime():
    node, payload, auth_error = ensure_agent_identity()
    if auth_error:
        return auth_error
    if not isinstance(node, dict) or not isinstance(payload, dict):
        return error_response('agent 身份无效', 401)

    runtime = payload.get('runtime')
    if not isinstance(runtime, dict):
        raise ValidationError('runtime 必须是对象')

    runtime_id = str(runtime.get('id', '')).strip()
    if not runtime_id:
        raise ValidationError('runtime.id 不能为空')

    saved = upsert_agent_runtime(
        {
            'id': runtime_id,
            'node_id': node.get('id', ''),
            'kind': str(runtime.get('kind', '')).strip() or 'frpc',
            'name': str(runtime.get('name', '')).strip() or runtime_id,
            'status': str(runtime.get('status', '')).strip() or 'unknown',
            'enabled': bool(runtime.get('enabled', True)),
            'last_heartbeat_at': utc_now_iso(),
            'metadata': runtime.get('metadata') if isinstance(runtime.get('metadata'), dict) else {},
        }
    )
    touch_agent_node(node.get('id', ''), {'status': 'online'})
    return success_response({'runtime': saved})


if __name__ == '__main__':
    host = os.environ.get('FRP_MANAGER_HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    try:
        port = int(os.environ.get('FRP_MANAGER_PORT', '5000'))
    except ValueError:
        port = 5000
    app.run(debug=debug, host=host, port=port)

