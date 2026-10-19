"""Import controlled, successful SSH lab flows using the existing normalizer.

Labels come from the declared normal session AND matching auth.log evidence.
Predictions and Wazuh rule IDs are never used as labels or input features.
"""
import argparse
from collections import Counter, defaultdict
from datetime import timedelta
import ipaddress
import json
from pathlib import Path
import re

import numpy as np
from soc_ai.common import digest, read_json, sha256, write_json
from soc_ai.flow import FEATURE_HASH, features, normalize, parse_time, utc

SCHEMA = 'soc-lab-labeled-flow/0.1'
REPORT = 'soc-lab-import/0.1'
AUTH = re.compile(
    r'^(?P<time>\S+)\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+'
    r'Accepted (?P<method>password|publickey) for (?P<user>\S+) '
    r'from (?P<ip>\S+) port (?P<port>\d+) ssh2(?:\s|$)')


def auth_index(path):
    index = defaultdict(list)
    seen = set()
    stats = Counter()
    with Path(path).open(encoding='utf-8-sig') as source:
        for number, line in enumerate(source, 1):
            match = AUTH.search(line)
            if match is None:
                if 'Accepted password for ' in line or 'Accepted publickey for ' in line:
                    stats['unparsed_accepted_lines'] += 1
                continue
            try:
                fields = match.groupdict()
                item = {'timestamp': utc(parse_time(fields['time'])),
                        'source_ip': str(ipaddress.ip_address(fields['ip'])),
                        'source_port': int(fields['port']), 'user': fields['user'],
                        'method': fields['method'], 'auth_line': number}
                if not 0 <= item['source_port'] <= 65535:
                    raise ValueError('invalid source port')
            except (ValueError, TypeError):
                stats['invalid_accepted_lines'] += 1
                continue
            key = tuple(item[k] for k in ('timestamp', 'source_ip', 'source_port', 'user', 'method'))
            if key in seen:
                stats['duplicate_auth_lines'] += 1
                continue
            seen.add(key)
            index[(item['source_ip'], item['source_port'], item['user'])].append(item)
            stats['accepted_lines'] += 1
    return index, stats


def identity(flow):
    endpoints = sorted(((flow['src_ip'], flow['src_port']),
                        (flow['dest_ip'], flow['dest_port'])))
    return digest([flow['protocol'], endpoints, flow['start_time'], flow['end_time']])


def select(events, marker, auth, client, server, user, role):
    stats = Counter(input_records=len(events))
    groups = defaultdict(list)
    start_boundary = parse_time(marker['start_time'])
    for event in events:
        if event.get('event_type') != 'flow':
            raise ValueError('Capture file must contain only raw Suricata flow events')
        flow = normalize(event)
        if flow['protocol'] != 'TCP' or flow['app_protocol'] != 'ssh':
            stats['excluded_non_ssh_tcp'] += 1
            continue
        if (flow['src_ip'], flow['dest_ip'], flow['dest_port']) != (client, server, 22):
            stats['excluded_other_or_reverse_endpoints'] += 1
            continue
        if parse_time(flow['start_time']) < start_boundary:
            stats['excluded_before_session'] += 1
            continue
        if (flow['duration_seconds'] <= 0 or
                flow['pkts_toserver'] + flow['pkts_toclient'] <= 1 or
                flow['flow_reason'] == 'tcp_reuse'):
            stats['excluded_out_of_model_scope'] += 1
            continue
        groups[identity(flow)].append(flow)

    session_id = 'lab-session:' + digest({
        k: marker[k] for k in ('container_started_at', 'start_time', 'endpoints', 'context')})
    records = []
    for key, flows in groups.items():
        vectors = [features(flow) for flow in flows]
        if any(not np.array_equal(vectors[0], vector) for vector in vectors[1:]):
            stats['excluded_inconsistent_observations'] += len(flows)
            continue
        flow = flows[0]
        stats['duplicate_observations_removed'] += len(flows) - 1
        # The tolerance accommodates timestamp precision, never a timezone/hour guess.
        lower = parse_time(flow['start_time']) - timedelta(seconds=2)
        upper = parse_time(flow['end_time']) + timedelta(seconds=2)
        matches = [item for item in auth.get((client, flow['src_port'], user), [])
                   if lower <= parse_time(item['timestamp']) <= upper
                   and parse_time(item['timestamp']) >= start_boundary]
        if not matches:
            stats['excluded_no_auth_success'] += 1
            continue
        if len(matches) != 1:
            stats['excluded_ambiguous_auth_success'] += 1
            continue
        flow = {**flow, 'record_id': 'lab-flow:' + key}
        records.append({'schema_version': SCHEMA, 'record_id': flow['record_id'],
                        'session_id': session_id, 'role': role, 'label': 'BENIGN',
                        'label_method': 'declared_normal_session_and_accepted_ssh',
                        'flow': flow, 'evidence': matches[0]})
    stats['selected_records'] = len(records)
    return records, stats, session_id


def run(capture, output, role='train', client='172.20.0.4', server='172.20.0.3', user='labuser'):
    capture, output = Path(capture).resolve(), Path(output).resolve()
    client, server = str(ipaddress.ip_address(client)), str(ipaddress.ip_address(server))
    if role not in ('train', 'validation', 'test'):
        raise ValueError('Invalid split role')
    if client == server:
        raise ValueError('Client and server must differ')
    session = capture.parent
    marker = read_json(session / 'session.json')
    summary = read_json(capture / 'summary.json')
    if marker.get('version') != 'lab-flow-check/0.1' or summary.get('complete') is not True:
        raise ValueError('Requires a completed lab-flow-check capture')
    if summary.get('session') != marker:
        raise ValueError('Capture and session metadata do not match')
    if not str(marker.get('context', '')).startswith('normal-ssh'):
        raise ValueError('Only a declared normal SSH session can use this importer')
    if set(marker.get('endpoints', [])) != {client, server}:
        raise ValueError('Endpoint scope differs from captured session')
    paths = {'flows': capture / 'flows.jsonl', 'auth': session / 'auth.log',
             'session': session / 'session.json', 'capture_summary': capture / 'summary.json'}
    hashes = {name: sha256(path) for name, path in paths.items()}
    events = []
    with paths['flows'].open(encoding='utf-8-sig') as source:
        for number, line in enumerate(source, 1):
            if line.strip():
                events.append(json.loads(line))
    expected = summary.get('capture_counts', {}).get('selected_flows')
    if expected != len(events):
        raise ValueError('Capture count and flow file differ')
    if output.exists():
        raise ValueError('Output directory exists; choose a new one')
    auth, auth_stats = auth_index(paths['auth'])
    records, counts, session_id = select(events, marker, auth, client, server, user, role)
    if any(sha256(path) != hashes[name] for name, path in paths.items()):
        raise ValueError('Input changed during import')
    output.mkdir(parents=True)
    report = {'version': REPORT, 'complete': False, 'feature_hash': FEATURE_HASH,
              'label': 'BENIGN', 'role': role, 'session_id': session_id,
              'session_context': marker['context'], 'counts': dict(counts),
              'auth_counts': dict(auth_stats),
              'inputs': {name: {'path': str(path), 'sha256': hashes[name]}
                         for name, path in paths.items()},
              'policy': {'accepted_auth_required': True, 'client_to_server_ssh_only': True,
                         'auth_time_tolerance_seconds': 2,
                         'predictions_are_not_labels': True,
                         'duplicate_observations_removed': True},
              'warnings': ['Labels require that the declared normal session was controlled.',
                           'A successful login alone does not prove benign intent outside that session.',
                           'A separate local validation and test session are needed before comparing models.']}
    write_json(output / 'report.json', report)
    if not records:
        raise ValueError('No evidence-backed records selected; see incomplete report.json')
    target = output / 'labeled-flows.jsonl'
    with target.open('x', encoding='utf-8', newline='\n') as out:
        for item in records:
            out.write(json.dumps(item, ensure_ascii=False, allow_nan=False) + '\n')
    report.update(complete=True, data_sha256=sha256(target))
    write_json(output / 'report.json', report)
    print('LOCAL_IMPORT_COMPLETE:', output, flush=True)
    print(json.dumps({'role': role, 'label': 'BENIGN', 'counts': dict(counts),
                      'auth_counts': dict(auth_stats)}, indent=2), flush=True)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--role', choices=('train', 'validation', 'test'), required=True)
    p.add_argument('--client', default='172.20.0.4')
    p.add_argument('--server', default='172.20.0.3')
    p.add_argument('--user', default='labuser')
    a = p.parse_args()
    try:
        run(a.capture, a.output, a.role, a.client, a.server, a.user)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.exit(1, f'ERROR: {exc}\n')


if __name__ == '__main__':
    main()
