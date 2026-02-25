import copy
import json
import os
import tempfile
import threading
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / 'frp_manager' / 'config.json'
LOCK = threading.RLock()

DEFAULT_CONFIG = {
    "frps_servers": [],
    "frpc_configs": [],
    "auth": {
        "initialized": False,
        "admin_username": "",
        "password_hash": "",
    },
}


def _new_id():
    return uuid.uuid4().hex


def _normalize_config(raw_config):
    if not isinstance(raw_config, dict):
        return copy.deepcopy(DEFAULT_CONFIG)

    config = copy.deepcopy(raw_config)
    if not isinstance(config.get('frps_servers'), list):
        config['frps_servers'] = []
    if not isinstance(config.get('frpc_configs'), list):
        config['frpc_configs'] = []

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


def _atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=4, ensure_ascii=False)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def load_config():
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


def save_config(config):
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
