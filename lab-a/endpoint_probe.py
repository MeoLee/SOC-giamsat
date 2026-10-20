"""Opt-in, instrumented lab actions; not a general or tamper-resistant audit agent.

Installed root-owned on the endpoint, run as the dedicated SSH lab account.
Only two fixed benign actions are supported. SSH_CONNECTION binds their evidence
to the server's auth-log source port. Never use these events as training labels.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

PROBE_PATH = '/usr/local/lib/soc-lab/endpoint_probe.py'
LOG_PATH = '/var/log/soc-lab/endpoint-probe.jsonl'
SERVER_PORT = 18080
PAYLOAD = b'SOC LAB BENIGN TRANSFER PROBE v1\n'
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
SHELL_ARGV = ['/bin/sh', '-c', 'id; uname -s']
SCHEMA = 'soc-endpoint-probe/0.1'


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def private_ipv4(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not any(ip in ipaddress.ip_network(net) for net in
            ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('An RFC1918 IPv4 lab address is required')
    return str(ip)


def ssh_context(token):
    if not re.fullmatch(r'[a-f0-9]{32}', token):
        raise ValueError('Probe token must contain 32 lowercase hexadecimal digits')
    parts = os.environ.get('SSH_CONNECTION', '').split()
    if len(parts) != 4 or parts[3] != '22':
        raise ValueError('Run through the lab SSH server on port 22')
    source, source_port, target, _ = parts
    if not source_port.isascii() or not source_port.isdecimal() or not 1 <= int(source_port) <= 65535:
        raise ValueError('Invalid SSH connection source port')
    if os.getuid() == 0:
        raise ValueError('Use the dedicated unprivileged lab SSH account')
    import pwd
    return {'schema_version': SCHEMA, 'lab_probe': True,
            'telemetry_trust': 'instrumented_lab_not_tamper_resistant',
            'probe_id': token, 'source_ip': private_ipv4(source), 'source_port': int(source_port),
            'target_ip': private_ipv4(target), 'target_port': 22,
            'username': pwd.getpwuid(os.getuid()).pw_name, 'uid': os.getuid()}


def transfer_argv(source, token, destination):
    return ['curl', '--noproxy', '*', '--proto', '=http', '--connect-timeout', '3',
            '--max-time', '5', '--max-filesize', '4096', '--max-redirs', '0',
            '--fail', '--silent', '--show-error', '--output', destination,
            'http://'+source+':'+str(SERVER_PORT)+'/'+token+'.txt']


def record(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        if os.write(fd, data) != len(data):
            raise RuntimeError('Partial endpoint evidence write')
        os.fsync(fd)
    finally:
        os.close(fd)


def run_probe(token, log_path=LOG_PATH):
    context = ssh_context(token)
    start = now()
    # A real shell process executes fixed harmless commands; no arbitrary input.
    result = subprocess.run(SHELL_ARGV, capture_output=True, timeout=5, check=False)
    record(log_path, {**context, 'kind': 'process.execution', 'started_at': start,
        'event_time': now(), 'argv': SHELL_ARGV, 'returncode': result.returncode,
        'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()})
    if result.returncode:
        raise RuntimeError('The fixed shell action failed; inspect endpoint evidence')
    print(result.stdout.decode(errors='replace'), end='', flush=True)
    # Let Live publish the execution transition before the next real action.
    time.sleep(3)
    fd, filename = tempfile.mkstemp(prefix='soc-lab-probe-', suffix='.txt')
    os.close(fd)
    try:
        start = now()
        argv = transfer_argv(context['source_ip'], token, filename)
        result = subprocess.run(argv, capture_output=True, timeout=8, check=False)
        data = Path(filename).read_bytes()
        valid = result.returncode == 0 and data == PAYLOAD
        record(log_path, {**context, 'kind': 'file.transfer', 'started_at': start,
            'event_time': now(), 'argv': argv, 'returncode': result.returncode,
            'artifact_path': filename, 'artifact_bytes': len(data),
            'artifact_sha256': hashlib.sha256(data).hexdigest(), 'payload_verified': valid})
        if not valid:
            raise RuntimeError('Benign transfer incomplete or hash mismatch; no transfer stage accepted')
        print('BENIGN_FILE_TRANSFER_VERIFIED sha256='+PAYLOAD_SHA256, flush=True)
    finally:
        Path(filename).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    run_probe(args.token)


if __name__ == '__main__':
    main()
