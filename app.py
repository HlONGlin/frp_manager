from flask import Flask, jsonify, render_template, request
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config_manager import (
    add_frps_server,
    add_port_mapping,
    delete_frpc_config,
    delete_frps_server,
    delete_port_mapping,
    get_frpc_configs,
    get_frps_server,
    get_frps_servers,
    save_frpc_config,
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

app = Flask(__name__)
app.secret_key = os.environ.get('FRP_MANAGER_SECRET_KEY') or os.urandom(32).hex()
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
        raise ValidationError('Request body must be JSON')
    if not isinstance(body, dict):
        raise ValidationError('JSON body must be an object')
    return body


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_manager_base_url():
    return request.url_root.rstrip('/')


def check_frps_status(server_addr, server_port):
    host = server_addr or "127.0.0.1"
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
            server['status'] = get_cached_status(server_id) or 'unknown'
        return

    worker_count = min(max(1, STATUS_WORKERS), len(servers))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {}
        for server in servers:
            future = pool.submit(check_frps_status, server.get('server_addr'), server.get('server_port'))
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
        return error_response('Not found', 404)
    return _error


@app.errorhandler(500)
def handle_internal_error(_error):
    if request.path.startswith('/api/'):
        return error_response('Internal server error', 500)
    return _error


@app.route('/')
def index():
    return render_template('index.html')


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
    payload = validate_server_create(parse_json_body(), get_local_ip())
    server = add_frps_server(payload)
    clear_cached_status(str(server.get('id', '')))
    deploy_command = build_frps_deploy_command(server, manager_base_url=get_manager_base_url())
    return success_response(
        {'server': server, 'deploy_command': deploy_command, 'local_ip': server.get('server_addr')},
        status_code=201,
    )


@app.route('/api/frps/server/<server_id>', methods=['GET'])
def get_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)
    server['status'] = check_frps_status(server.get('server_addr'), server.get('server_port'))
    set_cached_status(str(server.get('id', '')), server['status'])
    return jsonify(server)


@app.route('/api/frps/server/<server_id>/deploy', methods=['GET'])
def get_frps_deploy(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)
    return success_response({'command': build_frps_deploy_command(server, manager_base_url=get_manager_base_url()), 'server': server})


@app.route('/api/frps/server/<server_id>', methods=['PUT'])
def update_frps(server_id):
    updates = validate_server_update(parse_json_body())
    updated = update_frps_server(server_id, updates)
    if not updated:
        return error_response('Server not found', 404)
    clear_cached_status(server_id)
    return success_response()


@app.route('/api/frps/server/<server_id>', methods=['DELETE'])
def delete_frps(server_id):
    deleted = delete_frps_server(server_id)
    if not deleted:
        return error_response('Server not found', 404)
    clear_cached_status(server_id)
    return success_response()


@app.route('/api/frps/server/<server_id>/check', methods=['POST'])
def check_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)
    status = check_frps_status(server.get('server_addr'), server.get('server_port'))
    set_cached_status(str(server.get('id', '')), status)
    return success_response({'status': status})


@app.route('/api/frps/server/<server_id>/report', methods=['POST'])
def report_frps(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)

    payload = parse_json_body()
    report_token = str(payload.get('token', '')).strip()
    if not report_token or report_token != str(server.get('token', '')).strip():
        return error_response('Invalid report token', 403)

    updates_payload = {}
    if 'server_addr' in payload:
        updates_payload['server_addr'] = payload.get('server_addr')
    if 'server_port' in payload:
        updates_payload['server_port'] = payload.get('server_port')

    if updates_payload:
        updates = validate_server_update(updates_payload)
        update_frps_server(server_id, updates)
        server.update(updates)

    set_cached_status(server_id, 'online')
    return success_response({
        'server_id': server_id,
        'server_addr': server.get('server_addr'),
        'server_port': server.get('server_port'),
        'status': 'online',
    })


@app.route('/api/frps/server/<server_id>/ports', methods=['GET'])
def get_ports(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)
    return jsonify(server.get('ports', []))


@app.route('/api/frps/server/<server_id>/port', methods=['POST'])
def add_port(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)
    port_config = validate_port_create(parse_json_body())
    created = add_port_mapping(server_id, port_config)
    if not created:
        return error_response('Server not found', 404)
    return success_response({'port': created}, status_code=201)


@app.route('/api/frps/server/<server_id>/port/<port_id>', methods=['PUT'])
def update_port(server_id, port_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)

    current_port = find_port(server, port_id)
    if not current_port:
        return error_response('Port not found', 404)

    validated_port = validate_port_update(parse_json_body(), current_port)
    updated = update_port_mapping(server_id, port_id, validated_port)
    if not updated:
        return error_response('Port not found', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/port/<port_id>', methods=['DELETE'])
def delete_port(server_id, port_id):
    deleted = delete_port_mapping(server_id, port_id)
    if not deleted:
        return error_response('Port not found', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/port/<port_id>/toggle', methods=['POST'])
def toggle_port(server_id, port_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)

    current_port = find_port(server, port_id)
    if not current_port:
        return error_response('Port not found', 404)

    updated = update_port_mapping(server_id, port_id, {'enabled': not current_port.get('enabled', True)})
    if not updated:
        return error_response('Port not found', 404)
    return success_response()


@app.route('/api/frps/server/<server_id>/generate_frpc', methods=['GET'])
def generate_frpc_for_server(server_id):
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)

    config = build_frpc_config(server, server.get('ports', []))
    return success_response({'config': config, 'server': server})


@app.route('/api/frps/server/<server_id>/port/<port_id>/deploy', methods=['GET'])
def generate_frpc_deploy(server_id, port_id):
    system = validate_system(request.args.get('system', 'linux'))
    server = get_frps_server(server_id)
    if not server:
        return error_response('Server not found', 404)

    port = find_port(server, port_id)
    if not port:
        return error_response('Port not found', 404)

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
        return error_response('Config not found', 404)
    return success_response()


if __name__ == '__main__':
    host = os.environ.get('FRP_MANAGER_HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    try:
        port = int(os.environ.get('FRP_MANAGER_PORT', '5000'))
    except ValueError:
        port = 5000
    app.run(debug=debug, host=host, port=port)
