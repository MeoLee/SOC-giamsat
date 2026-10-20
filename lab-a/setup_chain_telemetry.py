"""Install opt-in fixed lab probes, with no SSH/PAM/Wazuh rule changes.

The endpoint log is writable by the dedicated lab account. This is controlled
exercise instrumentation, not tamper-resistant general endpoint auditing.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from endpoint_probe import PROBE_PATH, LOG_PATH
from live_config import container_name, load_config

SERVER_PATH = '/usr/local/lib/soc-lab/lab_transfer_server.py'
INSTALL = r'''
import base64,hashlib,json,os,pwd,sys
from pathlib import Path
p=json.load(sys.stdin)
root=Path('/usr/local/lib/soc-lab')
if root.is_symlink() or (root.exists() and root.stat().st_uid!=0):
    raise ValueError('Unsafe probe installation directory')
root.mkdir(parents=True,exist_ok=True);os.chmod(root,0o755)
marker=root/'managed-chain-probe.json'
previous=json.loads(marker.read_text()) if marker.exists() else {}
for name,encoded in p['files'].items():
    path=root/name;data=base64.b64decode(encoded)
    if path.is_symlink():raise ValueError('Probe path is a symlink')
    if path.exists() and path.read_bytes()!=data:
        if previous.get(name)!=hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('Unmanaged or modified probe exists; preserve and inspect it')
for name,encoded in p['files'].items():
    path=root/name;data=base64.b64decode(encoded)
    tmp=root/(name+'.new');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()
    os.chown(path,0,0);os.chmod(path,0o644)
    previous[name]=hashlib.sha256(data).hexdigest()
marker.write_text(json.dumps(previous,sort_keys=True)+'\n');os.chmod(marker,0o644)
if p.get('username'):
    user=pwd.getpwnam(p['username'])
    if user.pw_uid==0:raise ValueError('Dedicated unprivileged lab account required')
    folder=Path('/var/log/soc-lab')
    if folder.is_symlink():raise ValueError('Unsafe endpoint log directory')
    folder.mkdir(exist_ok=True);os.chown(folder,0,0);os.chmod(folder,0o755)
    log=folder/'endpoint-probe.jsonl'
    if log.is_symlink():raise ValueError('Unsafe endpoint log file')
    fd=os.open(log,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o640);os.close(fd)
    os.chown(log,user.pw_uid,user.pw_gid);os.chmod(log,0o640)
print(json.dumps({'installed':previous,'controlled_lab_only':True}))
'''


def candidate_config(data, sensor):
    from live_config import DEFAULT_SOURCES
    result = json.loads(json.dumps(data))
    source = {'kind': 'endpoint', 'container': sensor, 'path': LOG_PATH,
              'output': 'endpoint-probe.jsonl'}
    if not any(a.get('host') == sensor for a in result.get('assets', [])):
        raise ValueError('The sensor container must have a matching asset host/IP entry')
    sources = result.setdefault('sources', list(DEFAULT_SOURCES))
    for existing in sources:
        if existing.get('output') == source['output'] or (existing.get('container'), existing.get('path')) == (sensor, LOG_PATH):
            if existing != source:
                raise ValueError('Conflicting endpoint log source; preserve the current config')
            return result
    sources.append(source)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sensor', default='ubuntu-endpoint')
    p.add_argument('--client', default='kali-attacker')
    p.add_argument('--username', default='soctest')
    p.add_argument('--config', type=Path, default=Path(__file__).with_name('live-config.json'))
    a = p.parse_args()
    for name in (a.sensor, a.client): container_name(name)
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', a.username): p.error('Invalid lab account')
    load_config(a.config)
    old = a.config.read_bytes(); data = candidate_config(json.loads(old.decode('utf-8-sig')), a.sensor)
    with tempfile.TemporaryDirectory() as folder:
        check = Path(folder)/'config.json'; check.write_text(json.dumps(data)); load_config(check)
    def command(argv, **kwargs):
        r = subprocess.run(argv, capture_output=True, timeout=20, **kwargs)
        if r.returncode:
            raise RuntimeError(r.stderr.decode(errors='replace')[-2000:])
        return r
    # Preflight before installation. No package installation or SSH-policy edits.
    command(['docker', 'exec', '--user', a.username, a.sensor, 'python3', '-c',
             'import os,shutil; assert os.getuid()!=0; assert shutil.which("curl"); print("ENDPOINT_READY")'])
    command(['docker', 'exec', a.client, 'python3', '-c', 'import http.server; print("CLIENT_READY")'])
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = a.config.with_name(a.config.name+'.before-chain-probe-'+stamp)
    backup.write_bytes(old)
    root = Path(__file__).parent
    for container, names, user in [(a.sensor, ['endpoint_probe.py'], a.username),
                                    (a.client, ['endpoint_probe.py', 'lab_transfer_server.py'], None)]:
        payload = {'username': user, 'files': {name: base64.b64encode((root/name).read_bytes()).decode() for name in names}}
        result = command(['docker', 'exec', '-i', '--user', '0', container, 'python3', '-c', INSTALL],
                         input=json.dumps(payload).encode())
        print(container, result.stdout.decode().strip())
    from soc_ai.common import write_json
    write_json(a.config, data)
    print('CONFIG_BACKUP:', backup)
    print('CHAIN_PROBE_INSTALLED: start a NEW Live capture; then run chain-extended.')
    print('Fixed benign lab actions only; no general audit coverage or confirmed compromise.')


if __name__ == '__main__': main()
