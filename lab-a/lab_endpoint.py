"""Normalize opt-in endpoint probe evidence and bind it to one SSH success.

These are instrumented lab observations, not a generic auditd detector. Account,
target, SSH source port, event-time window and probe ID must all agree. A file
transfer additionally requires verified bytes/hash and earlier shell execution.
"""
import json
from pathlib import PurePosixPath
import re

from endpoint_probe import SCHEMA, PAYLOAD, PAYLOAD_SHA256, SHELL_ARGV, transfer_argv, private_ipv4


def normalize(raw, config, source):
    from lab_correlation import instant, stamp, ip_host
    event = json.loads(raw)
    if not isinstance(event, dict) or event.get('schema_version') != SCHEMA or event.get('lab_probe') is not True:
        raise ValueError('Explicit endpoint lab-probe schema required')
    if event.get('kind') not in ('process.execution', 'file.transfer'):
        raise ValueError('Unsupported endpoint action')
    if type(event.get('returncode')) is not int or event['returncode'] != 0:
        # Preserve failed raw actions, but they cannot create completed stages.
        return None
    token = event.get('probe_id')
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{32}', token):
        raise ValueError('Invalid endpoint probe ID')
    src, dst = private_ipv4(event['source_ip']), private_ipv4(event['target_ip'])
    host = ip_host(dst, config)
    origin = config.get('source_origins', {}).get(source, {})
    if host.startswith('ip:') or origin.get('source_container') != host:
        raise ValueError('Endpoint probe target must match its configured source container/asset')
    user = event.get('username')
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('Invalid endpoint account')
    if type(event.get('uid')) is not int or event['uid'] <= 0:
        raise ValueError('Endpoint probe must use an unprivileged account')
    port = event['source_port']
    if type(port) is not int or not 1 <= port <= 65535 or event.get('target_port') != 22:
        raise ValueError('Invalid endpoint SSH connection')
    started, ended = instant(event['started_at']), instant(event['event_time'])
    if not 0 <= (ended-started).total_seconds() <= 15:
        raise ValueError('Invalid endpoint action time interval')
    result = {k: event[k] for k in ('kind', 'probe_id', 'username', 'uid', 'source_port')}
    result.update(event_time=stamp(ended), started_at=stamp(started), source_ip=src,
        target_ip=dst, target_host=host, lab_probe=True,
        telemetry_trust='instrumented_lab_not_tamper_resistant')
    if event['kind'] == 'process.execution':
        if event.get('argv') != SHELL_ARGV or not re.fullmatch(r'[a-f0-9]{64}', event.get('stdout_sha256', '')):
            raise ValueError('Unsupported shell action or missing output hash')
        result.update(command='/bin/sh -c "id; uname -s"', stdout_sha256=event['stdout_sha256'])
    else:
        path = event.get('artifact_path', '')
        if (not isinstance(path, str) or str(PurePosixPath(path).parent) != '/tmp'
                or not re.fullmatch(r'soc-lab-probe-[A-Za-z0-9_-]+\.txt', PurePosixPath(path).name)):
            raise ValueError('Invalid probe artifact path')
        if (event.get('payload_verified') is not True or event.get('artifact_sha256') != PAYLOAD_SHA256
                or type(event.get('artifact_bytes')) is not int or event['artifact_bytes'] != len(PAYLOAD)
                or event.get('argv') != transfer_argv(src, token, path)):
            raise ValueError('Transfer requires the actual bounded curl action and verified marker bytes/hash')
        result.update(artifact_path=path, artifact_bytes=len(PAYLOAD), artifact_sha256=PAYLOAD_SHA256,
                      transfer_url=event['argv'][-1], payload_verified=True)
    return result


def extend_cases(cases, events, config):
    from lab_correlation import instant
    by_id = {e['event_id']: e for e in events}
    window = config.get('endpoint_window_seconds', 300)
    for case in cases.values():
        if case['status'] != 'suspicious_login_sequence':
            continue
        success_stage = next(s for s in case['stages'] if s['name'] == 'auth_success_after_failures')
        auth = by_id[success_stage['evidence_ids'][0]]
        def eligible(e):
            return (e.get('lab_probe') is True and all(e.get(k) == auth.get(k) for k in
                    ('source_ip', 'target_ip', 'target_host', 'username', 'source_port'))
                    and 0 <= (instant(e['started_at'])-instant(auth['event_time'])).total_seconds() <= window)
        processes = sorted((e for e in events if e['kind'] == 'process.execution' and eligible(e)),
                           key=lambda e: (e['started_at'], e['event_id']))
        if not processes:
            continue
        process = processes[0]
        additions = [('observed_shell_execution', process)]
        transfers = sorted((e for e in events if e['kind'] == 'file.transfer' and eligible(e)
            and e['probe_id'] == process['probe_id']
            and instant(e['started_at']) >= instant(process['event_time'])
            and e.get('payload_verified') is True), key=lambda e: (e['started_at'], e['event_id']))
        if transfers:
            additions.append(('observed_file_transfer', transfers[0]))
        for name, event in additions:
            case['stages'].append({'name': name, 'start_time': event['started_at'],
                'end_time': event['event_time'], 'evidence_ids': [event['event_id']],
                'probe_id': event['probe_id'], 'lab_probe': True,
                **{k: event[k] for k in ('command', 'artifact_bytes', 'artifact_sha256', 'transfer_url') if k in event}})
        case['last_seen'] = case['stages'][-1]['end_time']
        case['endpoint_evidence_scope'] = 'controlled_lab_probe_only'
        case['explanation'] += ' Additional fixed lab shell/file actions were observed in the same SSH connection; this is not general endpoint auditing.'
