"""Label scoped controlled SSH captures by joining native flow and auth evidence.

No traffic is executed. The operator's reviewed declaration is an assertion,
not a guarantee of truthful labels, universal SSH-Patator semantics or quality.
"""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

from import_lab_normal import SCHEMA, identity
from data_markers import known_synthetic
from lab_correlation import auth_event
from lab_scenarios import dump, load_object, safe_relative, sha256
from prepare_session_data import in_scope
from soc_ai.flow import normalize, parse_time

OPERATOR_SCHEMA = 'soc-controlled-ssh/1.0'
MANIFEST_SCHEMA = 'soc-supervised-sessions/1.0'
MAX_LINE = 16 * 1024 * 1024
ATTACK_FAILURE_MINIMUM = 8
ATTACK_WINDOW_SECONDS = 60


def lines(path):
    with Path(path).open('rb') as stream:
        number, offset = 0, 0
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                return
            number += 1
            if len(raw) > MAX_LINE or not raw.endswith(b'\n'):
                raise ValueError('Oversized/partial source record: ' + str(path) + ':' + str(number))
            clean = raw.rstrip(b'\r\n')
            if clean.strip():
                yield number, offset, clean
            offset += len(raw)


def reference(evidence_id, number, offset, raw):
    return {'evidence_id': evidence_id, 'line': number, 'byte_offset': offset,
            'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'hash_covers': 'raw line bytes excluding CR/LF'}


def operator_manifest(path, capture):
    operator = load_object(path)
    if operator.get('schema_version') != OPERATOR_SCHEMA:
        raise ValueError('Expected operator schema ' + OPERATOR_SCHEMA)
    if type(operator.get('synthetic')) is not bool:
        raise ValueError('Operator synthetic must be an explicit boolean')
    capture_synthetic = known_synthetic(capture)
    if type(capture_synthetic) is not bool or capture_synthetic and not operator['synthetic']:
        raise ValueError('Cannot remove a synthetic capture marker')
    for name in ('controlled', 'independent', 'reviewed'):
        if operator.get(name) is not True:
            raise ValueError('Operator ' + name + ':true is required')
    for name in ('id', 'reviewer', 'target_host', 'username'):
        value = operator.get(name)
        if not isinstance(value, str) or not value.strip() or any(c in value for c in '\r\n\t\x00'):
            raise ValueError('Operator ' + name + ' must be a nonempty single-line string')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', operator['id']):
        raise ValueError('Use a simple unique operator session ID')
    if operator.get('role') not in ('train', 'validation', 'test'):
        raise ValueError('Operator role must be train/validation/test')
    if operator.get('capture_session_id') != capture.get('session_id'):
        raise ValueError('Operator belongs to a different physical capture')
    if operator.get('intent') not in ('normal_ssh', 'ssh_password_guessing'):
        raise ValueError('Only explicitly controlled normal_ssh/ssh_password_guessing are supported')
    for name in ('source_ip', 'target_ip'):
        value = operator.get(name)
        if not isinstance(value, str) or str(ipaddress.ip_address(value)) != value:
            raise ValueError('Operator requires canonical endpoint IPs')
    if operator['source_ip'] == operator['target_ip']:
        raise ValueError('SSH source and target must differ')
    start, end = parse_time(operator.get('start_time')), parse_time(operator.get('end_time'))
    parse_time(operator.get('captured_at'))
    if end <= start:
        raise ValueError('Operator time window end must follow start')
    capture_start, capture_end = parse_time(capture.get('started_at_utc')), parse_time(capture.get('ended_at_utc'))
    if not capture_start <= start < end <= capture_end:
        raise ValueError('Operator window must be inside the closed physical capture')
    artifact = operator.get('tool_output')
    if not isinstance(artifact, dict):
        raise ValueError('A hashed operator/tool transcript is required')
    tool = safe_relative(Path(path).parent, artifact.get('path'))
    if tool.stat().st_size == 0 or artifact.get('sha256') != sha256(tool):
        raise ValueError('Operator/tool transcript hash mismatch or empty artifact')
    return operator, tool, start, end


def auth_records(path):
    found, seen = [], set()
    for number, offset, raw in lines(path):
        event = auth_event(raw.decode('utf-8-sig').strip(), {})
        if event is None:
            continue
        # Duplicated views of exactly the same auth outcome are not extra trials.
        key = tuple(event[k] for k in ('kind', 'event_time', 'target_host',
            'source_ip', 'source_port', 'username', 'auth_method'))
        if key in seen:
            continue
        seen.add(key)
        found.append({**event, 'auth_ref': reference('auth', number, offset, raw)})
    return found


def controlled_attack_supported(events, operator, start, end):
    matching = [event for event in events if event['kind'] == 'auth.failure'
        and event['auth_method'] == 'password' and event['source_ip'] == operator['source_ip']
        and event['target_host'] == operator['target_host'] and event['username'] == operator['username']
        and start <= parse_time(event['event_time']) <= end]
    window = deque()
    for event in sorted(matching, key=lambda row: row['event_time']):
        when = parse_time(event['event_time'])
        window.append(when)
        while (when - window[0]).total_seconds() > ATTACK_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= ATTACK_FAILURE_MINIMUM:
            return True
    return False


def select(eve, auth, operator, start, end):
    stats, groups, selected = Counter(), defaultdict(list), []
    attack = operator['intent'] == 'ssh_password_guessing'
    if attack and not controlled_attack_supported(auth, operator, start, end):
        raise ValueError('Controlled guessing requires at least 8 distinct scoped password failures within 60 seconds')
    index = defaultdict(list)
    for event in auth:
        index[(event['source_ip'], event['source_port'])].append(event)
    for number, offset, raw in lines(eve):
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError('EVE record must be an object')
        if known_synthetic(event):
            stats['known_synthetic_records'] += 1
        if event.get('event_type') != 'flow':
            stats['excluded_non_flow'] += 1
            continue
        try:
            flow = normalize(event)
        except (ValueError, KeyError, TypeError):
            stats['excluded_invalid_flow'] += 1
            continue
        if flow['protocol'] != 'TCP' or flow['app_protocol'] != 'ssh':
            stats['excluded_non_ssh_tcp'] += 1
            continue
        if (flow['src_ip'], flow['dest_ip'], flow['dest_port']) != (
                operator['source_ip'], operator['target_ip'], 22):
            stats['excluded_other_or_reverse_endpoints'] += 1
            continue
        if not (start <= parse_time(flow['start_time']) and parse_time(flow['end_time']) <= end):
            stats['excluded_outside_operator_time'] += 1
            continue
        groups[identity(flow)].append((flow, reference('raw-eve', number, offset, raw)))
    volatile = {'record_id', 'flow_id', 'community_id', 'eve_timestamp', 'available_time', 'quality_flags'}
    for key, observations in groups.items():
        flow, raw_ref = observations[0]
        if any(not in_scope(other) for other, _ in observations):
            stats['excluded_out_of_model_scope'] += len(observations)
            continue
        stable = {name: value for name, value in flow.items() if name not in volatile}
        if any({name: value for name, value in other.items() if name not in volatile} != stable
               for other, _ in observations[1:]):
            stats['excluded_inconsistent_observations'] += len(observations)
            continue
        lower, upper = parse_time(flow['start_time']), parse_time(flow['end_time'])
        matches = [event for event in index[(flow['src_ip'], flow['src_port'])]
                   if lower <= parse_time(event['event_time']) <= upper]
        if not matches:
            stats['excluded_no_exact_auth_match'] += 1
            continue
        if any(event['target_host'] != operator['target_host'] or
               event['username'] != operator['username'] for event in matches):
            stats['excluded_ambiguous_user_or_host'] += 1
            continue
        kinds = {event['kind'] for event in matches}
        if len(kinds) != 1:
            stats['excluded_mixed_auth_outcomes'] += 1
            continue
        if attack:
            if kinds != {'auth.failure'} or any(event['auth_method'] != 'password' for event in matches):
                stats['excluded_not_password_failure'] += 1
                continue
        elif kinds != {'auth.success'} or len(matches) != 1:
            stats['excluded_not_unambiguous_success'] += 1
            continue
        flow = {**flow, 'record_id': 'lab-flow:' + key}
        selected.append({'schema_version': SCHEMA, 'record_id': flow['record_id'],
            'session_id': operator['id'], 'role': operator['role'],
            'synthetic': operator['synthetic'] or bool(stats['known_synthetic_records']),
            'label': 'SSH-Patator' if attack else 'BENIGN',
            'label_method': 'reviewed_controlled_ssh_intent_and_exact_native_auth_flow_join',
            'flow': flow, 'raw_ref': raw_ref, 'evidence_refs': ['operator', 'transcript', 'auth'],
            'evidence': {'auth_refs': [event['auth_ref'] for event in matches],
                'all_observation_refs': [ref for _, ref in observations],
                'operator_scope': {name: operator[name] for name in ('capture_session_id', 'intent',
                    'source_ip', 'target_ip', 'target_host', 'username', 'start_time', 'end_time')},
                'predictions_and_rules_are_not_label_sources': True}})
        stats['duplicate_observations_removed'] += len(observations) - 1
    # A timestamp/tuple can be reused or have overlapping sensor observations.
    # Never choose arbitrarily if the very same auth event matches two flows.
    uses = Counter((ref['line'], ref['raw_sha256']) for item in selected for ref in item['evidence']['auth_refs'])
    unique = []
    for item in selected:
        if any(uses[(ref['line'], ref['raw_sha256'])] != 1 for ref in item['evidence']['auth_refs']):
            stats['excluded_auth_matches_multiple_flows'] += 1
        else:
            unique.append(item)
    stats['selected_records'] = len(unique)
    return unique, stats


def run(capture, operator_file, output, eve_name='suricata-eve.jsonl', auth_name='ubuntu-auth.log'):
    capture, operator_file, output = Path(capture).resolve(), Path(operator_file).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('Output exists; choose a new labelled directory')
    session_path = capture / 'session.json'
    session_hash, operator_hash = sha256(session_path), sha256(operator_file)
    session = load_object(session_path)
    if session.get('format') != 'soc-capture/1.0' or session.get('closed') is not True or session.get('status') != 'completed':
        raise ValueError('Require a closed completed soc-capture/1.0 session')
    if not isinstance(session.get('session_id'), str) or not session['session_id'] or session.get('gaps') or session.get('partials'):
        raise ValueError('Capture must be identified and have no gap/partial records')
    metadata, hashes = session.get('sources'), session.get('sha256')
    if not isinstance(metadata, list) or not metadata or not isinstance(hashes, dict):
        raise ValueError('Closed source metadata and hashes are required')
    names = {row.get('output') for row in metadata if isinstance(row, dict)}
    if len(names) != len(metadata) or eve_name == auth_name or not {eve_name, auth_name}.issubset(names):
        raise ValueError('Unique native auth and EVE capture sources are required')
    if any(row.get('last_error') for row in metadata) or not names.issubset(hashes):
        raise ValueError('Capture has unresolved source errors or missing hashes')
    raw_files = {}
    for name, expected in hashes.items():
        path = safe_relative(capture, name)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected) or sha256(path) != expected:
            raise ValueError('Raw capture hash mismatch: ' + name)
        raw_files[name] = path
    operator, tool, start, end = operator_manifest(operator_file, session)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + output.name + '-building-', dir=output.parent))
    try:
        evidence = staging / 'evidence'; evidence.mkdir()
        files = [('raw-eve', 'raw_eve', raw_files[eve_name], 'suricata-eve.jsonl'),
                 ('auth', 'auth', raw_files[auth_name], 'ubuntu-auth.log'),
                 ('operator', 'operator', operator_file, 'operator.json'),
                 ('transcript', 'operator', tool, 'tool-output.txt')]
        evidence_files = []
        for eid, kind, source, filename in files:
            shutil.copyfile(source, evidence / filename)
            evidence_files.append({'id': eid, 'kind': kind, 'path': 'evidence/' + filename,
                                   'sha256': sha256(evidence / filename)})
        shutil.copyfile(session_path, evidence / 'capture-session.json')
        # Preserve the operator JSON verbatim; its transcript path remains an
        # original reference, while fragment evidence_files locates frozen copies.
        expected_copies = [hashes[eve_name], hashes[auth_name], operator_hash, operator['tool_output']['sha256']]
        if [entry['sha256'] for entry in evidence_files] != expected_copies:
            raise ValueError('An input changed while freezing evidence')
        auth = auth_records(evidence / 'ubuntu-auth.log')
        records, stats = select(evidence / 'suricata-eve.jsonl', auth, operator, start, end)
        known_fixture = operator['synthetic'] or bool(stats['known_synthetic_records'])
        if not records:
            raise ValueError('No unambiguous completed SSH flows matched independent controlled evidence')
        records_path = staging / 'labels.jsonl'
        with records_path.open('x', encoding='utf-8', newline='\n') as stream:
            for item in records:
                stream.write(json.dumps(item, ensure_ascii=False, allow_nan=False) + '\n')
        fragment = {'schema_version': MANIFEST_SCHEMA, 'synthetic': known_fixture,
            'sessions': [{'id': operator['id'], 'capture_session_id': operator['capture_session_id'],
                'role': operator['role'], 'synthetic': known_fixture,
                'records': 'labels.jsonl', 'sha256': sha256(records_path),
                'captured_at': operator['captured_at'], 'evidence_files': evidence_files,
                'label_review': {'reviewed': True, 'independent': True,
                    'reviewer': operator['reviewer'],
                    'method': 'Scoped operator attestation plus exact auth source-port/user/host/time and raw completed SSH flow join; operator truth is not independently proven by software.'}}]}
        dump(staging / 'fragment.json', fragment)
        dump(staging / 'report.json', {'schema_version': 'soc-controlled-ssh-label-report/1.0',
            'complete': True, 'synthetic': known_fixture, 'counts': dict(stats),
            'label': 'SSH-Patator' if operator['intent'] == 'ssh_password_guessing' else 'BENIGN',
            'capture_session_id': session['session_id'], 'capture_manifest_sha256': session_hash,
            'operator_sha256': operator_hash, 'fragment_sha256': sha256(staging / 'fragment.json'),
            'policy': {'traffic_executed': False, 'labels_from_predictions_or_rules': False,
                'minimum_attack_password_failures': ATTACK_FAILURE_MINIMUM,
                'attack_window_seconds': ATTACK_WINDOW_SECONDS,
                'exact_source_port_user_host_and_flow_time': True,
                'mixed_outcome_connections_excluded': True},
            'limitations': ['Operator declaration is an attestation; hashes do not prove its truth.',
                'Strict timestamp joins may exclude valid connections with low-precision or skewed logs.',
                'Controlled password guessing is a local supervised label, not proof of compromise or universal CICIDS equivalence.',
                'Use physically independent whole sessions for train/validation/test and fresh final benchmark.']})
        if sha256(session_path) != session_hash or sha256(operator_file) != operator_hash or sha256(tool) != operator['tool_output']['sha256']:
            raise ValueError('Capture/operator evidence changed during labeling')
        if any(sha256(path) != hashes[name] for name, path in raw_files.items()):
            raise ValueError('Raw source changed during labeling')
        if sha256(evidence / 'capture-session.json') != session_hash:
            raise ValueError('Capture metadata changed while copying')
        if output.exists():
            raise ValueError('Output appeared during labeling; choose a new directory')
        staging.rename(output)
        return fragment
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--operator', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--eve', default='suricata-eve.jsonl')
    parser.add_argument('--auth', default='ubuntu-auth.log')
    args = parser.parse_args(argv)
    try:
        fragment = run(args.capture, args.operator, args.output, args.eve, args.auth)
        print('CONTROLLED_SSH_FRAGMENT:', args.output / 'fragment.json')
        print('LABELS:', args.output / 'labels.jsonl', 'SYNTHETIC:', fragment['synthetic'])
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
