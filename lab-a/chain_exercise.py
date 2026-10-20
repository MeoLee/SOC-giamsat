"""Bounded lifecycle for the one-file lab server used by chain-extended."""
import json
import time

from endpoint_probe import PAYLOAD_SHA256, PAYLOAD, PROBE_PATH, LOG_PATH
from setup_chain_telemetry import SERVER_PATH

READ_STATE = '''
import pathlib,sys
p=pathlib.Path('/tmp/soc-lab-transfer-'+sys.argv[1]+'.jsonl')
print(p.read_text()[:16000] if p.exists() else '')
'''
STOP_SERVER = '''
import json,os,pathlib,signal,sys
token=sys.argv[1];p=pathlib.Path('/tmp/soc-lab-transfer-'+token+'.jsonl')
if p.exists():
    rows=[json.loads(l) for l in p.read_text().splitlines()]
    ready=next((r for r in rows if r.get('kind')=='ready'),None)
    if ready:
        cmd=pathlib.Path('/proc/'+str(ready['pid'])+'/cmdline')
        if cmd.exists():
            text=cmd.read_bytes().split(b'\\x00')
            if token.encode() in text and any(x.endswith(b'/lab_transfer_server.py') for x in text):
                os.kill(ready['pid'],signal.SIGTERM)
'''


def preflight(sensor, username, command):
    command(['docker', 'exec', '--user', username, sensor, 'python3', '-c',
        'import os,pathlib; p=pathlib.Path("'+PROBE_PATH+'"); '
        'assert p.is_file() and p.stat().st_uid==0; '
        'assert os.access("'+LOG_PATH+'",os.W_OK); print("ENDPOINT_PROBE_READY")'])


def read_state(client, token, command):
    r = command(['docker', 'exec', client, 'python3', '-c', READ_STATE, token])
    return [json.loads(line) for line in r.stdout.decode().splitlines() if line.strip()]


def start_server(client, source, target, token, command):
    command(['docker', 'exec', '-d', client, 'python3', SERVER_PATH,
             '--token', token, '--bind', source, '--peer', target])
    for _ in range(10):
        rows = read_state(client, token, command)
        if any(r.get('kind') == 'ready' and r.get('bind') == source for r in rows):
            return
        time.sleep(.5)
    raise RuntimeError('One-file lab server did not start; check port 18080 and installed helper')


def verify_server(rows, target, token):
    matches = [r for r in rows if r.get('kind') == 'transfer_served'
               and r.get('probe_id') == token and r.get('peer_ip') == target
               and r.get('sha256') == PAYLOAD_SHA256 and r.get('bytes_sent') == len(PAYLOAD)
               and r.get('path') == '/'+token+'.txt']
    if len(matches) != 1:
        raise ValueError('Expected one verified benign marker response from lab server')
    return matches[0]
