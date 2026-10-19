"""Runtime inputs and asset identity. Assets never filter inference or sources."""
import json
import ipaddress
from pathlib import Path, PurePosixPath
import re

DEFAULT_SOURCES = [
    {'kind': 'auth', 'container': 'ubuntu-endpoint', 'path': '/var/log/auth.log', 'output': 'ubuntu-auth.log'},
    {'kind': 'eve', 'container': 'ubuntu-endpoint', 'path': '/var/log/suricata/eve.json', 'output': 'suricata-eve.jsonl'},
    {'kind': 'wazuh', 'container': 'single-node-wazuh.manager-1', 'path': '/var/ossec/logs/alerts/alerts.json', 'output': 'wazuh-alerts.jsonl'},
]


def container_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value):
        raise ValueError('Invalid Docker container name or ID')
    return value


def output_name(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError('Source output must be a unique basename')
    if any(c in value for c in '/\\:<>"|?*') or value.endswith((' ', '.')):
        raise ValueError('Source output must be a unique basename')
    key = value.casefold()
    device = key.split('.')[0]
    if device in {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                  *(f'lpt{i}' for i in range(1, 10))}:
        raise ValueError('Reserved Windows device filename')
    if key.startswith(('ai-', 'correlation-', '.')) or key in (
            'session.json', 'checkpoint.json', 'live-activities.jsonl', 'web-events.jsonl'):
        raise ValueError('Reserved output filename')
    return key


def validated_assets(assets):
    if not isinstance(assets, list):
        raise ValueError('assets must be a list')
    hosts, addresses, result = set(), set(), []
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError('Asset must be an object')
        host, ips = asset.get('host'), asset.get('ips', [])
        if (not isinstance(host, str) or not host.strip() or any(c.isspace() for c in host)
                or any(ord(c) < 32 for c in host) or host.casefold() in hosts):
            raise ValueError('Asset requires a unique host name')
        if not isinstance(ips, list) or any(not isinstance(ip, str) for ip in ips):
            raise ValueError('Asset ips must be a list of IP strings')
        normalized = [str(ipaddress.ip_address(ip)) for ip in ips]
        if len(set(normalized)) != len(normalized) or addresses.intersection(normalized):
            raise ValueError('Ambiguous asset IP: one address cannot identify multiple hosts')
        hosts.add(host.casefold())
        addresses.update(normalized)
        result.append({**asset, 'host': host, 'ips': normalized})
    return result


def load_config(path=None):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig')) if path else {}
    if not isinstance(data, dict):
        raise ValueError('Runtime configuration must be an object')
    sources = data.get('sources', DEFAULT_SOURCES)
    if not sources or not isinstance(sources, list):
        raise ValueError('sources must be a non-empty list')
    outputs, inputs = set(), set()
    for s in sources:
        if not isinstance(s, dict):
            raise ValueError('Source must be an object')
        if s.get('kind') not in ('eve', 'auth', 'wazuh', 'web', 'raw'):
            raise ValueError('Source kind must be eve, auth, wazuh, web or raw')
        for key in ('container', 'path', 'output'):
            if not isinstance(s.get(key), str) or not s[key] or any(ord(c) < 32 for c in s[key]):
                raise ValueError('Invalid source ' + key)
        container_name(s['container'])
        output = output_name(s['output'])
        if output in outputs:
            raise ValueError('Source output must be a unique basename')
        if not s['path'].startswith('/') or '..' in s['path'].split('/'):
            raise ValueError('Container log path must be absolute')
        identity = (s['container'], str(PurePosixPath(s['path'])))
        if identity in inputs:
            raise ValueError('Duplicate container log source')
        inputs.add(identity)
        outputs.add(output)
    settings = data.get('correlation', {})
    if not isinstance(settings, dict):
        raise ValueError('correlation must be an object')
    for key in ('failure_threshold', 'failure_window_seconds', 'success_window_seconds',
                'recon_window_seconds', 'max_events'):
        if key in settings and (type(settings[key]) is not int or settings[key] < 1):
            raise ValueError('Invalid correlation configuration: ' + key)
    correlation = {**settings, 'all_agents': True,
                   'assets': validated_assets(data.get('assets', [])),
                   'source_kinds': {s['output']: s['kind'] for s in sources},
                   'source_origins': {s['output']: {'source_container': s['container'],
                       'source_path': s['path']} for s in sources}}
    manager = data.get('wazuh_manager', 'single-node-wazuh.manager-1')
    container_name(manager)
    return {'sources': sources, 'correlation': correlation, 'wazuh_manager': manager}
