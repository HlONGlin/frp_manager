from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os
import re
import secrets
import socket
import sys
import threading
import time
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config_manager import (
    add_frps_server,
    add_port_mapping,
    delete_frpc_config,
    delete_frps_server,
    delete_port_mapping,
    get_frpc_configs,
    get_auth_config,
    get_frps_server,
    get_frps_servers,
    is_auth_initialized,
    save_frpc_config,
    set_admin_credentials,
    update_frps_server,
    update_port_mapping,
)
from utils.deploy_commands import (
    build_frpc_config,
    build_frpc_deploy_command,
    build_frps_deploy_command,
)
from utils.validators import (
    ValidationError,
    validate_port_create,
    validate_port_update,
    validate_server_create,
    validate_server_update,
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

app = Flask(__name__)
app.secret_key = os.environ.get('FRP_MANAGER_SECRET_KEY') or os.urandom(32).hex()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FRP_SESSION_SECURE', '0') == '1'
status_cache = {}
status_cache_lock = threading.Lock()


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
    forwarded_host = str(request.headers.get('X-Forwarded-Host', '')).split(',')[0].strip()
    if forwarded_host:
        forwarded_proto = str(request.headers.get('X-Forwarded-Proto', '')).split(',')[0].strip()
        scheme = forwarded_proto or request.scheme or 'http'
        return normalize_base_url(f'{scheme}://{forwarded_host}')
    return normalize_base_url(request.url_root)


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
        if api_request and path not in auth_allowed_api_paths and not is_report_callback:
            return error_response('管理员账号未初始化，请先完成首次设置', 403)
        if not api_request and path != '/setup':
            return redirect(url_for('setup_page'))
        return None

    if path == '/setup':
        return redirect(url_for('index'))

    if path in auth_allowed_paths or path in auth_allowed_api_paths or is_report_callback:
        return None

    if is_logged_in():
        return None

    if api_request:
        return error_response('未登录或登录已过期', 401)
    return redirect(url_for('login_page'))


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

    try:
        normalized_username, normalized_password = validate_auth_payload(username, password, confirm_password)
    except ValidationError as error:
        return render_template('setup.html', error=str(error), username=str(username or '').strip()), 422

    password_hash = generate_password_hash(normalized_password)
    set_admin_credentials(normalized_username, password_hash)
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

    session[SESSION_USER_KEY] = username
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop(SESSION_USER_KEY, None)
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
    return jsonify(servers)


@app.route('/api/frps/server', methods=['POST'])
def add_frps():
    raw_payload = parse_json_body()
    if not str(raw_payload.get('token', '')).strip():
        raw_payload['token'] = generate_server_token()
    payload = validate_server_create(raw_payload, get_local_ip())
    payload['last_report_at'] = ''
    server = add_frps_server(payload)
    clear_cached_status(str(server.get('id', '')))
    manager_urls = get_manager_base_urls(server)
    deploy_command = build_frps_deploy_command(server, manager_base_urls=manager_urls)
    return success_response(
        {'server': server, 'deploy_command': deploy_command, 'local_ip': get_local_ip(), 'manager_urls': manager_urls},
        status_code=201,
    )


@app.route('/api/frps/server/<server_id>', methods=['GET'])
def get_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    server['status'] = check_frps_status(server.get('server_addr'), server.get('server_port'), server.get('last_report_at'))
    set_cached_status(str(server.get('id', '')), server['status'])
    return jsonify(server)


@app.route('/api/frps/server/<server_id>/deploy', methods=['GET'])
def get_frps_deploy(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    manager_urls = get_manager_base_urls(server)
    return success_response({
        'command': build_frps_deploy_command(server, manager_base_urls=manager_urls),
        'server': server,
        'manager_urls': manager_urls,
    })


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
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    addr_error = validate_server_addr_ready(server)
    if addr_error:
        return addr_error

    config = build_frpc_config(server, server.get('ports', []))
    return success_response({'config': config, 'server': server})


@app.route('/api/frps/server/<server_id>/port/<port_id>/deploy', methods=['GET'])
def generate_frpc_deploy(server_id, port_id):
    system = validate_system(request.args.get('system', 'linux'))
    server = get_frps_server(server_id)
    if not server:
        return error_response('服务器不存在', 404)
    addr_error = validate_server_addr_ready(server)
    if addr_error:
        return addr_error

    port = find_port(server, port_id)
    if not port:
        return error_response('端口映射不存在', 404)

    command = build_frpc_deploy_command(server, port, system=system)
    return success_response({'command': command})


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


if __name__ == '__main__':
    host = os.environ.get('FRP_MANAGER_HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    try:
        port = int(os.environ.get('FRP_MANAGER_PORT', '5000'))
    except ValueError:
        port = 5000
    app.run(debug=debug, host=host, port=port)
