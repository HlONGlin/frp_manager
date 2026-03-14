import copy
import datetime
import hashlib
import json
import os
import secrets
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / 'frp_manager' / 'config.json'
LOCK = threading.RLock()
MAX_AGENT_JOBS = 2000
MAX_JSON_BLOB_SIZE = 128 * 1024

DEFAULT_CONFIG: dict[str, Any] = {
    "frps_servers": [],
    "frpc_configs": [],
    "agent": {
        "nodes": [],
        "jobs": [],
        "runtimes": [],
    },
    "auth": {
        "initialized": False,
        "admin_username": "",
        "password_hash": "",
    },
}


def _new_id():
    return uuid.uuid4().hex


def _utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _parse_iso_timestamp(raw: Any) -> Optional[datetime.datetime]:
    text = str(raw or '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = f'{text[:-1]}+00:00'
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _ensure_agent_section(config: dict[str, Any]) -> dict[str, Any]:
    agent = config.get('agent')
    if not isinstance(agent, dict):
        agent = {}
    if not isinstance(agent.get('nodes'), list):
        agent['nodes'] = []
    if not isinstance(agent.get('jobs'), list):
        agent['jobs'] = []
    if not isinstance(agent.get('runtimes'), list):
        agent['runtimes'] = []
    config['agent'] = agent
    return agent


def _normalize_node(raw_node: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw_node, dict):
        return None

    node = copy.deepcopy(raw_node)
    node_id = str(node.get('id', '')).strip() or _new_id()
    created_at = str(node.get('created_at', '')).strip() or _utc_now_iso()
    updated_at = str(node.get('updated_at', '')).strip() or created_at

    node['id'] = node_id
    node['name'] = str(node.get('name', '')).strip() or f'node-{node_id[:8]}'
    node['token_hash'] = str(node.get('token_hash', '')).strip()
    node['status'] = str(node.get('status', '')).strip() or 'unknown'
    node['hostname'] = str(node.get('hostname', '')).strip()
    node['platform'] = str(node.get('platform', '')).strip()
    node['agent_version'] = str(node.get('agent_version', '')).strip()
    node['last_seen_at'] = str(node.get('last_seen_at', '')).strip()
    node['created_at'] = created_at
    node['updated_at'] = updated_at

    labels = node.get('labels')
    if not isinstance(labels, list):
        labels = []
    node['labels'] = [str(item).strip() for item in labels if str(item).strip()]

    return node


def _normalize_job(raw_job: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw_job, dict):
        return None

    job = copy.deepcopy(raw_job)
    job_id = str(job.get('id', '')).strip() or _new_id()
    created_at = str(job.get('created_at', '')).strip() or _utc_now_iso()
    updated_at = str(job.get('updated_at', '')).strip() or created_at

    job['id'] = job_id
    job['node_id'] = str(job.get('node_id', '')).strip()
    job['type'] = str(job.get('type', '')).strip() or 'noop'
    job['status'] = str(job.get('status', '')).strip() or 'queued'
    payload = job.get('payload')
    job['payload'] = copy.deepcopy(payload) if isinstance(payload, dict) else {}
    result = job.get('result')
    job['result'] = copy.deepcopy(result) if isinstance(result, dict) else {}
    job['error'] = str(job.get('error', '')).strip()
    job['idempotency_key'] = str(job.get('idempotency_key', '')).strip()
    job['lease_id'] = str(job.get('lease_id', '')).strip()
    job['lease_expires_at'] = str(job.get('lease_expires_at', '')).strip()
    job['created_at'] = created_at
    job['updated_at'] = updated_at
    job['started_at'] = str(job.get('started_at', '')).strip()
    job['finished_at'] = str(job.get('finished_at', '')).strip()

    try:
        attempts = int(job.get('attempts', 0))
    except (TypeError, ValueError):
        attempts = 0
    try:
        max_attempts = int(job.get('max_attempts', 1))
    except (TypeError, ValueError):
        max_attempts = 1

    job['attempts'] = max(0, attempts)
    job['max_attempts'] = max(1, max_attempts)
    return job


def _normalize_runtime(raw_runtime: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw_runtime, dict):
        return None

    runtime = copy.deepcopy(raw_runtime)
    runtime_id = str(runtime.get('id', '')).strip() or _new_id()
    created_at = str(runtime.get('created_at', '')).strip() or _utc_now_iso()
    updated_at = str(runtime.get('updated_at', '')).strip() or created_at

    runtime['id'] = runtime_id
    runtime['node_id'] = str(runtime.get('node_id', '')).strip()
    runtime['kind'] = str(runtime.get('kind', '')).strip() or 'frpc'
    runtime['name'] = str(runtime.get('name', '')).strip() or runtime_id[:8]
    runtime['status'] = str(runtime.get('status', '')).strip() or 'unknown'
    runtime['enabled'] = bool(runtime.get('enabled', True))
    runtime['last_heartbeat_at'] = str(runtime.get('last_heartbeat_at', '')).strip()

    metadata = runtime.get('metadata')
    runtime['metadata'] = copy.deepcopy(metadata) if isinstance(metadata, dict) else {}

    runtime['created_at'] = created_at
    runtime['updated_at'] = updated_at
    return runtime


def _hash_agent_token(token: Any) -> str:
    return hashlib.sha256(str(token or '').encode('utf-8')).hexdigest()


def _normalize_config(raw_config: Any) -> dict[str, Any]:
    if not isinstance(raw_config, dict):
        return copy.deepcopy(DEFAULT_CONFIG)

    config = copy.deepcopy(raw_config)
    if not isinstance(config.get('frps_servers'), list):
        config['frps_servers'] = []
    if not isinstance(config.get('frpc_configs'), list):
        config['frpc_configs'] = []

    agent = _ensure_agent_section(config)
    normalized_nodes = []
    normalized_jobs = []
    normalized_runtimes = []

    for node in agent.get('nodes', []):
        normalized = _normalize_node(node)
        if normalized is not None:
            normalized_nodes.append(normalized)

    for job in agent.get('jobs', []):
        normalized = _normalize_job(job)
        if normalized is not None:
            normalized_jobs.append(normalized)

    for runtime in agent.get('runtimes', []):
        normalized = _normalize_runtime(runtime)
        if normalized is not None:
            normalized_runtimes.append(normalized)

    agent['nodes'] = normalized_nodes
    agent['jobs'] = normalized_jobs
    agent['runtimes'] = normalized_runtimes

    auth = config.get('auth')
    if not isinstance(auth, dict):
        auth = {}
    admin_username = auth.get('admin_username') if isinstance(auth.get('admin_username'), str) else ''
    password_hash = auth.get('password_hash') if isinstance(auth.get('password_hash'), str) else ''
    initialized = bool(auth.get('initialized') and admin_username and password_hash)
    config['auth'] = {
        'initialized': initialized,
        'admin_username': admin_username,
        'password_hash': password_hash,
    }
    return config


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=4, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def load_config() -> dict[str, Any]:
    with LOCK:
        if not CONFIG_FILE.exists():
            default_copy = copy.deepcopy(DEFAULT_CONFIG)
            _atomic_write(CONFIG_FILE, default_copy)
            return default_copy

        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError):
            # Preserve broken data for manual recovery and reset to a healthy default.
            backup_path = CONFIG_FILE.with_suffix(f"{CONFIG_FILE.suffix}.bak")
            try:
                os.replace(CONFIG_FILE, backup_path)
            except OSError:
                pass
            default_copy = copy.deepcopy(DEFAULT_CONFIG)
            _atomic_write(CONFIG_FILE, default_copy)
            return default_copy

        normalized = _normalize_config(raw)
        if normalized != raw:
            _atomic_write(CONFIG_FILE, normalized)
        return normalized


def save_config(config: dict[str, Any]) -> None:
    with LOCK:
        _atomic_write(CONFIG_FILE, _normalize_config(config))


def get_frps_servers():
    config = load_config()
    return copy.deepcopy(config.get('frps_servers', []))


def add_frps_server(server):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])

        new_server = copy.deepcopy(server)
        new_server['id'] = new_server.get('id') or _new_id()
        new_server['status'] = new_server.get('status', 'offline')
        ports = new_server.get('ports', [])
        new_server['ports'] = ports if isinstance(ports, list) else []
        servers.append(new_server)

        config['frps_servers'] = servers
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(new_server)


def update_frps_server(server_id, server_data):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])
        updates = copy.deepcopy(server_data)
        updates.pop('id', None)
        updates.pop('ports', None)
        updates.pop('status', None)

        updated = False
        for index, server in enumerate(servers):
            if server.get('id') == server_id:
                servers[index].update(updates)
                updated = True
                break

        if updated:
            config['frps_servers'] = servers
            _atomic_write(CONFIG_FILE, config)
        return updated


def delete_frps_server(server_id):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])
        new_servers = [server for server in servers if server.get('id') != server_id]
        deleted = len(new_servers) != len(servers)
        if deleted:
            config['frps_servers'] = new_servers
            _atomic_write(CONFIG_FILE, config)
        return deleted


def get_frps_server(server_id):
    servers = get_frps_servers()
    for server in servers:
        if server.get('id') == server_id:
            return copy.deepcopy(server)
    return None


def add_port_mapping(frps_server_id, port_config):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])
        created = None

        for index, server in enumerate(servers):
            if server.get('id') != frps_server_id:
                continue
            ports = server.get('ports', [])
            if not isinstance(ports, list):
                ports = []

            new_port = copy.deepcopy(port_config)
            new_port['id'] = new_port.get('id') or _new_id()
            new_port['enabled'] = bool(new_port.get('enabled', True))
            ports.append(new_port)
            server['ports'] = ports
            servers[index] = server
            created = new_port
            break

        if created is not None:
            config['frps_servers'] = servers
            _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(created) if created is not None else None


def update_port_mapping(frps_server_id, port_id, port_data):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])
        updates = copy.deepcopy(port_data)
        updates.pop('id', None)

        updated = False
        for server_index, server in enumerate(servers):
            if server.get('id') != frps_server_id:
                continue

            ports = server.get('ports', [])
            if not isinstance(ports, list):
                ports = []

            for port_index, port in enumerate(ports):
                if port.get('id') != port_id:
                    continue
                ports[port_index].update(updates)
                ports[port_index]['id'] = port_id
                updated = True
                break

            server['ports'] = ports
            servers[server_index] = server
            break

        if updated:
            config['frps_servers'] = servers
            _atomic_write(CONFIG_FILE, config)
        return updated


def delete_port_mapping(frps_server_id, port_id):
    with LOCK:
        config = load_config()
        servers = config.get('frps_servers', [])
        deleted = False

        for server_index, server in enumerate(servers):
            if server.get('id') != frps_server_id:
                continue

            ports = server.get('ports', [])
            if not isinstance(ports, list):
                ports = []

            new_ports = [port for port in ports if port.get('id') != port_id]
            deleted = len(new_ports) != len(ports)
            server['ports'] = new_ports
            servers[server_index] = server
            break

        if deleted:
            config['frps_servers'] = servers
            _atomic_write(CONFIG_FILE, config)
        return deleted


def get_frpc_configs():
    config = load_config()
    return copy.deepcopy(config.get('frpc_configs', []))


def save_frpc_config(frpc_config):
    with LOCK:
        config = load_config()
        configs = config.get('frpc_configs', [])
        saved_config = copy.deepcopy(frpc_config)
        if len(json.dumps(saved_config, ensure_ascii=False)) > MAX_JSON_BLOB_SIZE:
            raise ValueError('frpc config too large')
        config_id = saved_config.get('id')

        if config_id:
            for index, existed in enumerate(configs):
                if existed.get('id') == config_id:
                    configs[index] = saved_config
                    break
            else:
                configs.append(saved_config)
        else:
            saved_config['id'] = _new_id()
            configs.append(saved_config)

        config['frpc_configs'] = configs
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(saved_config)


def delete_frpc_config(config_id):
    with LOCK:
        config = load_config()
        configs = config.get('frpc_configs', [])
        new_configs = [item for item in configs if item.get('id') != config_id]
        deleted = len(new_configs) != len(configs)
        if deleted:
            config['frpc_configs'] = new_configs
            _atomic_write(CONFIG_FILE, config)
        return deleted


def get_auth_config():
    config = load_config()
    auth = config.get('auth', {})
    return copy.deepcopy(auth)


def is_auth_initialized():
    auth = get_auth_config()
    return bool(
        auth.get('initialized')
        and str(auth.get('admin_username', '')).strip()
        and str(auth.get('password_hash', '')).strip()
    )


def set_admin_credentials(username, password_hash):
    with LOCK:
        config = load_config()
        config['auth'] = {
            'initialized': True,
            'admin_username': str(username).strip(),
            'password_hash': str(password_hash).strip(),
        }
        _atomic_write(CONFIG_FILE, config)


def clear_admin_credentials():
    with LOCK:
        config = load_config()
        config['auth'] = copy.deepcopy(DEFAULT_CONFIG['auth'])
        _atomic_write(CONFIG_FILE, config)


def get_agent_nodes():
    config = load_config()
    agent = config.get('agent', {})
    return copy.deepcopy(agent.get('nodes', []))


def get_agent_node(node_id):
    normalized_id = str(node_id or '').strip()
    if not normalized_id:
        return None
    for node in get_agent_nodes():
        if node.get('id') == normalized_id:
            return copy.deepcopy(node)
    return None


def create_agent_node(node, token):
    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        nodes = agent.get('nodes', [])

        created = _normalize_node(node)
        if created is None:
            raise ValueError('invalid node payload')
        assert created is not None
        created['token_hash'] = _hash_agent_token(token)
        created['created_at'] = _utc_now_iso()
        created['updated_at'] = created['created_at']
        nodes.append(created)

        agent['nodes'] = nodes
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(created)


def update_agent_node(node_id, updates):
    normalized_id = str(node_id or '').strip()
    if not normalized_id:
        return False

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        nodes = agent.get('nodes', [])

        updated = False
        update_payload = copy.deepcopy(updates) if isinstance(updates, dict) else {}
        update_payload.pop('id', None)
        update_payload.pop('token_hash', None)

        for index, node in enumerate(nodes):
            if node.get('id') != normalized_id:
                continue
            nodes[index].update(update_payload)
            nodes[index]['updated_at'] = _utc_now_iso()
            updated = True
            break

        if updated:
            agent['nodes'] = nodes
            config['agent'] = agent
            _atomic_write(CONFIG_FILE, config)
        return updated


def rotate_agent_node_token(node_id, token):
    normalized_id = str(node_id or '').strip()
    if not normalized_id:
        return False

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        nodes = agent.get('nodes', [])
        updated = False
        for index, node in enumerate(nodes):
            if node.get('id') != normalized_id:
                continue
            nodes[index]['token_hash'] = _hash_agent_token(token)
            nodes[index]['updated_at'] = _utc_now_iso()
            updated = True
            break
        if updated:
            agent['nodes'] = nodes
            config['agent'] = agent
            _atomic_write(CONFIG_FILE, config)
        return updated


def delete_agent_node(node_id):
    normalized_id = str(node_id or '').strip()
    if not normalized_id:
        return False

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        nodes = agent.get('nodes', [])
        jobs = agent.get('jobs', [])
        runtimes = agent.get('runtimes', [])

        new_nodes = [node for node in nodes if node.get('id') != normalized_id]
        deleted = len(new_nodes) != len(nodes)
        if not deleted:
            return False

        new_jobs = [job for job in jobs if job.get('node_id') != normalized_id]
        new_runtimes = [runtime for runtime in runtimes if runtime.get('node_id') != normalized_id]

        agent['nodes'] = new_nodes
        agent['jobs'] = new_jobs
        agent['runtimes'] = new_runtimes
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return True


def verify_agent_node_token(node_id, token):
    node = get_agent_node(node_id)
    if not node:
        return False
    expected = str(node.get('token_hash', '')).strip()
    if not expected:
        return False
    return secrets.compare_digest(expected, _hash_agent_token(token))


def touch_agent_node(node_id, updates=None):
    normalized_id = str(node_id or '').strip()
    if not normalized_id:
        return None

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        nodes = agent.get('nodes', [])
        payload = copy.deepcopy(updates) if isinstance(updates, dict) else {}
        payload.pop('id', None)
        payload.pop('token_hash', None)

        for index, node in enumerate(nodes):
            if node.get('id') != normalized_id:
                continue
            nodes[index].update(payload)
            nodes[index]['last_seen_at'] = _utc_now_iso()
            nodes[index]['updated_at'] = nodes[index]['last_seen_at']
            agent['nodes'] = nodes
            config['agent'] = agent
            _atomic_write(CONFIG_FILE, config)
            return copy.deepcopy(nodes[index])
        return None


def get_agent_jobs(node_id=None, statuses=None):
    config = load_config()
    agent = config.get('agent', {})
    jobs = copy.deepcopy(agent.get('jobs', []))

    if node_id is not None:
        normalized_node_id = str(node_id or '').strip()
        jobs = [job for job in jobs if str(job.get('node_id', '')).strip() == normalized_node_id]

    if statuses:
        normalized_statuses = {str(item).strip() for item in statuses if str(item).strip()}
        jobs = [job for job in jobs if str(job.get('status', '')).strip() in normalized_statuses]

    jobs.sort(key=lambda item: str(item.get('created_at', '')))
    return jobs


def get_agent_job(job_id):
    normalized_id = str(job_id or '').strip()
    if not normalized_id:
        return None
    for job in get_agent_jobs():
        if job.get('id') == normalized_id:
            return copy.deepcopy(job)
    return None


def _find_job_by_id(jobs, job_id):
    normalized_id = str(job_id or '').strip()
    for index, job in enumerate(jobs):
        if str(job.get('id', '')).strip() == normalized_id:
            return index
    return -1


def create_agent_job(job):
    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        jobs = agent.get('jobs', [])

        created = _normalize_job(job)
        if created is None:
            raise ValueError('invalid job payload')
        assert created is not None

        if len(json.dumps(created.get('payload', {}), ensure_ascii=False)) > MAX_JSON_BLOB_SIZE:
            raise ValueError('job payload too large')

        idempotency_key = str(created.get('idempotency_key', '')).strip()
        if idempotency_key:
            for existed in jobs:
                if str(existed.get('idempotency_key', '')).strip() != idempotency_key:
                    continue
                if str(existed.get('node_id', '')).strip() != str(created.get('node_id', '')).strip():
                    continue
                if str(existed.get('type', '')).strip() != str(created.get('type', '')).strip():
                    continue
                if str(existed.get('status', '')).strip() in {'queued', 'leased', 'running', 'succeeded'}:
                    return copy.deepcopy(existed)

        created['status'] = 'queued'
        created['created_at'] = _utc_now_iso()
        created['updated_at'] = created['created_at']
        created['attempts'] = 0
        jobs.append(created)

        if len(jobs) > MAX_AGENT_JOBS:
            jobs = sorted(jobs, key=lambda item: str(item.get('created_at', '')))
            jobs = jobs[-MAX_AGENT_JOBS:]

        agent['jobs'] = jobs
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(created)


def update_agent_job(job_id, updates):
    normalized_id = str(job_id or '').strip()
    if not normalized_id:
        return False

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        jobs = agent.get('jobs', [])
        index = _find_job_by_id(jobs, normalized_id)
        if index < 0:
            return False

        payload = copy.deepcopy(updates) if isinstance(updates, dict) else {}
        payload.pop('id', None)
        jobs[index].update(payload)
        jobs[index]['updated_at'] = _utc_now_iso()

        agent['jobs'] = jobs
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return True


def lease_agent_job_for_node(node_id, lease_seconds=45):
    normalized_node_id = str(node_id or '').strip()
    if not normalized_node_id:
        return None

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        jobs = agent.get('jobs', [])
        now = datetime.datetime.now(datetime.timezone.utc)
        selected_index = -1

        for index, job in enumerate(jobs):
            if str(job.get('node_id', '')).strip() != normalized_node_id:
                continue

            status = str(job.get('status', '')).strip()
            if status == 'queued':
                selected_index = index
                break

            if status == 'leased':
                expires_at = _parse_iso_timestamp(job.get('lease_expires_at', ''))
                if expires_at is None or expires_at <= now:
                    selected_index = index
                    break

        if selected_index < 0:
            return None

        lease_id = _new_id()
        lease_expires = now + datetime.timedelta(seconds=max(15, int(lease_seconds)))
        jobs[selected_index]['status'] = 'leased'
        jobs[selected_index]['lease_id'] = lease_id
        jobs[selected_index]['lease_expires_at'] = lease_expires.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        jobs[selected_index]['updated_at'] = _utc_now_iso()

        agent['jobs'] = jobs
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(jobs[selected_index])


def mark_agent_job_running(job_id, node_id, lease_id):
    normalized_job_id = str(job_id or '').strip()
    normalized_node_id = str(node_id or '').strip()
    normalized_lease_id = str(lease_id or '').strip()
    if not normalized_job_id or not normalized_node_id or not normalized_lease_id:
        return None

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        jobs = agent.get('jobs', [])
        index = _find_job_by_id(jobs, normalized_job_id)
        if index < 0:
            return None

        job = jobs[index]
        if str(job.get('node_id', '')).strip() != normalized_node_id:
            return None
        if str(job.get('lease_id', '')).strip() != normalized_lease_id:
            return None

        expires_at = _parse_iso_timestamp(job.get('lease_expires_at', ''))
        now = datetime.datetime.now(datetime.timezone.utc)
        if expires_at is not None and expires_at < now:
            return None

        job['status'] = 'running'
        job['attempts'] = int(job.get('attempts', 0)) + 1
        if not str(job.get('started_at', '')).strip():
            job['started_at'] = _utc_now_iso()
        job['updated_at'] = _utc_now_iso()

        jobs[index] = job
        agent['jobs'] = jobs
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(job)


def complete_agent_job(job_id, node_id, lease_id, success, result=None, error=''):
    normalized_job_id = str(job_id or '').strip()
    normalized_node_id = str(node_id or '').strip()
    normalized_lease_id = str(lease_id or '').strip()
    if not normalized_job_id or not normalized_node_id or not normalized_lease_id:
        return None

    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        jobs = agent.get('jobs', [])
        index = _find_job_by_id(jobs, normalized_job_id)
        if index < 0:
            return None

        job = jobs[index]
        if str(job.get('node_id', '')).strip() != normalized_node_id:
            return None
        if str(job.get('lease_id', '')).strip() != normalized_lease_id:
            return None

        payload_result = copy.deepcopy(result) if isinstance(result, dict) else {}
        payload_error = str(error or '').strip()

        if success:
            job['status'] = 'succeeded'
            job['result'] = payload_result
            job['error'] = ''
            job['finished_at'] = _utc_now_iso()
            job['lease_id'] = ''
            job['lease_expires_at'] = ''
        else:
            attempts = int(job.get('attempts', 0))
            max_attempts = int(job.get('max_attempts', 1))
            job['result'] = payload_result
            job['error'] = payload_error or 'unknown error'
            if attempts < max_attempts:
                job['status'] = 'queued'
            else:
                job['status'] = 'failed'
                job['finished_at'] = _utc_now_iso()
            job['lease_id'] = ''
            job['lease_expires_at'] = ''

        job['updated_at'] = _utc_now_iso()
        jobs[index] = job
        agent['jobs'] = jobs
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(job)


def get_agent_runtimes(node_id=None):
    config = load_config()
    agent = config.get('agent', {})
    runtimes = copy.deepcopy(agent.get('runtimes', []))
    if node_id is None:
        return runtimes
    normalized_id = str(node_id or '').strip()
    return [runtime for runtime in runtimes if str(runtime.get('node_id', '')).strip() == normalized_id]


def get_agent_runtime(runtime_id):
    normalized_id = str(runtime_id or '').strip()
    if not normalized_id:
        return None
    for runtime in get_agent_runtimes():
        if runtime.get('id') == normalized_id:
            return copy.deepcopy(runtime)
    return None


def upsert_agent_runtime(runtime):
    with LOCK:
        config = load_config()
        agent = _ensure_agent_section(config)
        runtimes = agent.get('runtimes', [])
        normalized = _normalize_runtime(runtime)
        if normalized is None:
            raise ValueError('invalid runtime payload')
        assert normalized is not None

        target_index = -1
        for index, item in enumerate(runtimes):
            if str(item.get('id', '')).strip() == str(normalized.get('id', '')).strip():
                target_index = index
                break

        normalized['updated_at'] = _utc_now_iso()
        if not str(normalized.get('created_at', '')).strip():
            normalized['created_at'] = normalized['updated_at']

        if target_index < 0:
            runtimes.append(normalized)
            saved = normalized
        else:
            merged = copy.deepcopy(runtimes[target_index])
            merged.update(normalized)
            merged['updated_at'] = _utc_now_iso()
            runtimes[target_index] = merged
            saved = merged

        agent['runtimes'] = runtimes
        config['agent'] = agent
        _atomic_write(CONFIG_FILE, config)
        return copy.deepcopy(saved)
