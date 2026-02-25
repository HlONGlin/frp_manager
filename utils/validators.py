import copy
import re


class ValidationError(ValueError):
    pass


PROTOCOLS = {'tcp', 'udp', 'http', 'https'}
SERVER_FIELDS = {
    'name',
    'server_addr',
    'server_port',
    'token',
    'dashboard_port',
    'dashboard_user',
    'dashboard_pwd',
    'vhost_http_port',
    'vhost_https_port',
}
PORT_FIELDS = {
    'name',
    'local_ip',
    'local_port',
    'remote_port',
    'protocol',
    'domain',
    'enabled',
}

NAME_PATTERN = re.compile(r'^[^\r\n]{1,64}$')
HOST_PATTERN = re.compile(r'^[A-Za-z0-9._:-]{1,255}$')
TOKEN_PATTERN = re.compile(r'^[^\s\r\n]{1,128}$')
USER_PATTERN = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')
PASSWORD_PATTERN = re.compile(r'^[^\r\n]{1,128}$')
DOMAIN_PATTERN = re.compile(r'^[A-Za-z0-9*._,-]{1,255}$')

FIELD_LABELS = {
    'name': '名称',
    'server_addr': '服务器地址',
    'server_port': '服务端口',
    'token': '令牌',
    'dashboard_port': '仪表盘端口',
    'dashboard_user': '仪表盘账号',
    'dashboard_pwd': '仪表盘密码',
    'vhost_http_port': 'HTTP 端口',
    'vhost_https_port': 'HTTPS 端口',
    'local_ip': '本地 IP',
    'local_port': '本地端口',
    'remote_port': '远程端口',
    'protocol': '协议',
    'domain': '域名',
    'enabled': '启用状态',
}


def _label(field):
    return FIELD_LABELS.get(field, field)


def _ensure_dict(payload):
    if not isinstance(payload, dict):
        raise ValidationError('请求体必须是 JSON 对象')
    return payload


def _ensure_known_fields(payload, allowed_fields):
    unknown = set(payload.keys()) - allowed_fields
    if unknown:
        unknown_display = ', '.join(sorted(unknown))
        raise ValidationError(f'存在未知字段: {unknown_display}')


def _as_text(value, field, required=False, default=None, pattern=None):
    field_name = _label(field)
    if value is None:
        if default is not None:
            return default
        if required:
            raise ValidationError(f'{field_name}不能为空')
        return None

    text = str(value).strip()
    if not text:
        if default is not None:
            return default
        if required:
            raise ValidationError(f'{field_name}不能为空')
        return None
    if '\n' in text or '\r' in text:
        raise ValidationError(f'{field_name}不能包含换行')
    if pattern and not pattern.fullmatch(text):
        raise ValidationError(f'{field_name}格式不正确')
    return text


def _as_port(value, field, required=False, default=None):
    field_name = _label(field)
    if value is None or value == '':
        if default is not None:
            return default
        if required:
            raise ValidationError(f'{field_name}不能为空')
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f'{field_name}必须是整数')
    if port < 1 or port > 65535:
        raise ValidationError(f'{field_name}必须在 1 到 65535 之间')
    return port


def _as_bool(value, field, default=True):
    field_name = _label(field)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {'1', 'true', 'yes', 'on'}:
            return True
        if text in {'0', 'false', 'no', 'off'}:
            return False
    raise ValidationError(f'{field_name}必须是布尔值')


def validate_server_create(payload, local_ip):
    payload = _ensure_dict(payload)
    _ensure_known_fields(payload, SERVER_FIELDS)

    return {
        'name': _as_text(payload.get('name'), 'name', default='FRPS服务器', pattern=NAME_PATTERN),
        'server_addr': _as_text(payload.get('server_addr'), 'server_addr', default=local_ip, pattern=HOST_PATTERN),
        'server_port': _as_port(payload.get('server_port'), 'server_port', required=True),
        'token': _as_text(payload.get('token'), 'token', required=True, pattern=TOKEN_PATTERN),
        'dashboard_port': _as_port(payload.get('dashboard_port'), 'dashboard_port', default=7500),
        'dashboard_user': _as_text(payload.get('dashboard_user'), 'dashboard_user', default='admin', pattern=USER_PATTERN),
        'dashboard_pwd': _as_text(payload.get('dashboard_pwd'), 'dashboard_pwd', default='admin', pattern=PASSWORD_PATTERN),
        'vhost_http_port': _as_port(payload.get('vhost_http_port'), 'vhost_http_port', default=80),
        'vhost_https_port': _as_port(payload.get('vhost_https_port'), 'vhost_https_port', default=443),
    }


def validate_server_update(payload):
    payload = _ensure_dict(payload)
    _ensure_known_fields(payload, SERVER_FIELDS)
    if not payload:
        raise ValidationError('至少需要提交一个修改字段')

    updates = {}
    if 'name' in payload:
        updates['name'] = _as_text(payload.get('name'), 'name', required=True, pattern=NAME_PATTERN)
    if 'server_addr' in payload:
        updates['server_addr'] = _as_text(payload.get('server_addr'), 'server_addr', required=True, pattern=HOST_PATTERN)
    if 'server_port' in payload:
        updates['server_port'] = _as_port(payload.get('server_port'), 'server_port', required=True)
    if 'token' in payload:
        updates['token'] = _as_text(payload.get('token'), 'token', required=True, pattern=TOKEN_PATTERN)
    if 'dashboard_port' in payload:
        updates['dashboard_port'] = _as_port(payload.get('dashboard_port'), 'dashboard_port', required=True)
    if 'dashboard_user' in payload:
        updates['dashboard_user'] = _as_text(payload.get('dashboard_user'), 'dashboard_user', required=True, pattern=USER_PATTERN)
    if 'dashboard_pwd' in payload:
        updates['dashboard_pwd'] = _as_text(payload.get('dashboard_pwd'), 'dashboard_pwd', required=True, pattern=PASSWORD_PATTERN)
    if 'vhost_http_port' in payload:
        updates['vhost_http_port'] = _as_port(payload.get('vhost_http_port'), 'vhost_http_port', required=True)
    if 'vhost_https_port' in payload:
        updates['vhost_https_port'] = _as_port(payload.get('vhost_https_port'), 'vhost_https_port', required=True)

    return updates


def validate_port_create(payload):
    payload = _ensure_dict(payload)
    _ensure_known_fields(payload, PORT_FIELDS)

    protocol = _as_text(payload.get('protocol'), 'protocol', default='tcp')
    protocol = protocol.lower()
    if protocol not in PROTOCOLS:
        raise ValidationError('协议仅支持 tcp、udp、http、https')

    local_port = _as_port(payload.get('local_port'), 'local_port', required=True)
    remote_port = _as_port(payload.get('remote_port'), 'remote_port', required=protocol in {'tcp', 'udp'})
    domain = _as_text(payload.get('domain'), 'domain', required=protocol in {'http', 'https'}, pattern=DOMAIN_PATTERN)

    return {
        'name': _as_text(payload.get('name'), 'name', default='端口映射', pattern=NAME_PATTERN),
        'local_ip': _as_text(payload.get('local_ip'), 'local_ip', default='127.0.0.1', pattern=HOST_PATTERN),
        'local_port': local_port,
        'remote_port': remote_port if protocol in {'tcp', 'udp'} else None,
        'protocol': protocol,
        'domain': domain if protocol in {'http', 'https'} else '',
        'enabled': _as_bool(payload.get('enabled'), 'enabled', default=True),
    }


def validate_port_update(payload, current_port):
    payload = _ensure_dict(payload)
    _ensure_known_fields(payload, PORT_FIELDS)
    if not payload:
        raise ValidationError('至少需要提交一个修改字段')

    merged = copy.deepcopy(current_port)
    merged.update(payload)
    return validate_port_create(merged)


def validate_system(system):
    if not system:
        return 'linux'
    normalized = str(system).strip().lower()
    if normalized not in {'linux', 'windows'}:
        raise ValidationError('系统类型仅支持 linux 或 windows')
    return normalized
