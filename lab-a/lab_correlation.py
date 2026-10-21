"""Evidence-based lab correlation, shared by offline replay and live collection.

Raw authentication failures, successes and Suricata recon alerts are evidence.
MLP predictions never create brute-force or compromise stages by themselves.
All cases are hypotheses about observed sequences, not ground-truth labels.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

SOURCES = ('ubuntu-auth.log', 'suricata-eve.jsonl', 'wazuh-alerts.jsonl')
AUTH = re.compile(r'^(\S+)\s+(\S+)\s+sshd(?:-session)?(?:\[(\d+)\])?:\s+'
    r'(Failed|Accepted) (password|publickey) for (?:invalid user )?(\S+) '
    r'from (\S+) port (\d+) ssh2(?::|\s|$)')
DEFAULTS = {'protected_host': 'ubuntu-endpoint', 'protected_ip': '172.20.0.3',
    'agent_id': '001', 'failure_threshold': 8, 'failure_window_seconds': 60,
    'success_window_seconds': 300, 'recon_window_seconds': 600,
    'max_events': 50000, 'recon_port_threshold':20, 'recon_port_window_seconds':10}


def instant(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Event timestamp must be a timezone-aware string')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timezone required; no assumed local timezone')
    return result.astimezone(timezone.utc)


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def append(path, rows):
    import os
    with Path(path).open('ab') as stream:
        for row in rows:
            stream.write((json.dumps(row, ensure_ascii=False, allow_nan=False)+'\n').encode())
        stream.flush()
        os.fsync(stream.fileno())


def auth_event(line, config):
    match = AUTH.search(line)
    if not match:
        if any(text in line for text in ('Failed password for ', 'Accepted password for ', 'Accepted publickey for ')):
            raise ValueError('Unsupported SSH auth log format; RFC3339 timestamp with timezone and sshd program required')
        return None
    date, host, sshd_pid, outcome, method, user, ip, port = match.groups()
    number = int(port)
    if not 0 <= number <= 65535:
        raise ValueError('Invalid authentication source port')
    return {'kind': 'auth.failure' if outcome == 'Failed' else 'auth.success',
        'event_time': stamp(instant(date)), 'target_host': host,
        'target_ip': host_ip(host, config),
        'source_ip': str(ipaddress.ip_address(ip)), 'source_port': number,
        'username': user, 'auth_method': method,
        **({'sshd_pid':int(sshd_pid)} if sshd_pid else {})}


def host_ip(host, config):
    for asset in config.get('assets', []):
        if host == asset['host']:
            return asset.get('ips', [None])[0] if asset.get('ips') else None
    return (config.get('protected_ip') if host == config.get('protected_host') else None) if 'assets' not in config else None


def ip_host(ip, config):
    for asset in config.get('assets', []):
        if ip in asset.get('ips', []):
            return asset['host']
    return (config.get('protected_host') if ip == config.get('protected_ip') else 'ip:' + ip) if 'assets' not in config else 'ip:' + ip


def recon_event(event, config, sensor_id=None):
    if not isinstance(event, dict):
        raise ValueError('Suricata event must be an object')
    if event.get('event_type') != 'alert':
        return None
    alert = event.get('alert', {})
    if not isinstance(alert, dict):
        raise ValueError('Suricata alert must be an object')
    sid = str(alert.get('signature_id'))
    if sid not in ('9900001','9900003','9900101','9900102'): return None
    if sid=='9900003':
        from lab_recon import observation
        return observation(event,sensor_id or config['protected_host'],ip_host(event['dest_ip'],config))
    from soc_ai.flow import identifier, port
    def event_port(value):
        # Wazuh's JSON decoder may represent an EVE port as a decimal string.
        if isinstance(value, str) and value.isascii() and value.isdecimal():
            value = int(value)
        return port(value)
    flow_id = identifier(event['flow_id'])
    if flow_id is None:
        raise ValueError('Suricata alert requires a flow_id')
    dest = str(ipaddress.ip_address(event['dest_ip']))
    # Destination identity, not the Wazuh agent's management-network address.
    host = ip_host(dest, config)
    normalized = {'kind': 'network.syn_rate_indicator', 'event_time': stamp(instant(event['timestamp'])),
        'target_host': host, 'target_ip': dest,
        'source_ip': str(ipaddress.ip_address(event['src_ip'])),
        'source_port': event_port(event.get('src_port')), 'destination_port': event_port(event.get('dest_port')),
        'flow_id': flow_id, 'signature_id': sid}
    if sid != '9900001':
        from lab_web import normalize_http_status
        http = event.get('http', {})
        if not isinstance(http, dict):
            raise ValueError('Suricata HTTP must be an object')
        normalized.update(kind='web.sqli_indicator', evidence_provider='suricata',
            request_target=http.get('url'), http_method=http.get('http_method'),
            http_status=normalize_http_status(http.get('status')),
            tx_id=identifier(event.get('tx_id')), success_proven=False,
            sql_indicators=['sql_union_select'])
    return normalized


def normalize_line(source, raw, config):
    kind = config.get('source_kinds', {}).get(source, source)
    if kind == 'raw': return None
    if kind == 'process':
        from lab_process_chain import normalize
        return normalize(raw,config,source)
    if kind == 'endpoint':
        from lab_endpoint import normalize
        return normalize(raw, config, source)
    if kind == 'web':
        from lab_web import apache_tsv, sql_evidence
        event = apache_tsv(raw)
        event['target_host'] = ip_host(event['target_ip'],config)
        return sql_evidence(event)
    if kind in ('auth', 'ubuntu-auth.log'):
        return auth_event(raw.decode('utf-8-sig').strip(), config)
    wrapper = json.loads(raw)
    if not isinstance(wrapper, dict):
        raise ValueError('Expected event object')
    if kind in ('eve', 'suricata-eve.jsonl'):
        origin=config.get('source_origins',{}).get(source,{})
        return recon_event(wrapper, config, origin.get('source_container'))
    data = wrapper.get('data')
    if isinstance(data, dict) and data.get('soc_ai_producer') == 'soc-ai-live':
        return None
    agent = wrapper.get('agent', {})
    if not isinstance(agent, dict):
        raise ValueError('Wazuh agent must be an object')
    if not config.get('all_agents', False):
        if agent.get('id') != config['agent_id'] or agent.get('name') != config['protected_host']:
            return None
    elif not agent.get('id') or not agent.get('name'):
        return None
    from lab_file_chain import native_event
    file_event = native_event(wrapper, config)
    if file_event:
        return file_event
    full = wrapper.get('full_log', '')
    if not isinstance(full, str):
        raise ValueError('Invalid Wazuh full_log')
    if full.lstrip().startswith('{'):
        nested = json.loads(full)
        if not isinstance(nested, dict):
            raise ValueError('Nested Wazuh JSON must be an object')
        if nested.get('soc_ai_producer') == 'soc-ai-live':
            return None
        return recon_event(nested, config, agent.get('name'))
    # Some Wazuh exports retain decoded EVE under data but omit full_log.
    # Use the native EVE timestamp/fields; wrapper timestamp and agent.ip are
    # transport metadata and must not replace target or event identity.
    if isinstance(data, dict) and data.get('event_type') == 'alert':
        return recon_event(data, config, agent.get('name'))
    # A Wazuh auth alert is another view of the original auth event, not
    # an additional failed attempt. Correlation does not trust 119103's TTL.
    from lab_web import apache_combined, sql_evidence
    http = apache_combined(full, agent.get('name'), host_ip(agent.get('name'),config))
    if http:
        return sql_evidence(http)
    event = auth_event(full.strip(), config)
    if event and config.get('all_agents', False) and event['target_host'] != agent['name']:
        raise ValueError('Auth hostname differs from Wazuh agent identity; configure matching host names')
    return event


def case_for(burst, scans, success=None, config=None):
    config = config or DEFAULTS
    failures = sorted(burst['failures'].values(), key=lambda e: (e['event_time'], e['event_id']))
    start = instant(failures[0]['event_time'])
    earlier = [e for e in scans if e['target_host'] == burst['target_host']
        and e['source_ip'] == burst['source_ip']
        and 0 < (start-instant(e['event_time'])).total_seconds() <= config['recon_window_seconds']]
    earlier.sort(key=lambda e: (e['event_time'], e['event_id']))
    stages = []
    if earlier:
        from lab_recon import stage
        stages.append(stage(earlier))
    stages.append({'name': 'repeated_auth_failures', 'start_time': failures[0]['event_time'],
        'end_time': failures[-1]['event_time'], 'evidence_ids': [e['event_id'] for e in failures],
        'failure_count': len(failures), 'threshold': config['failure_threshold'],
        'window_seconds': config['failure_window_seconds']})
    if success:
        stages.append({'name': 'auth_success_after_failures', 'start_time': success['event_time'],
            'end_time': success['event_time'], 'evidence_ids': [success['event_id']]})
    return {'schema_version': 'soc-correlation-case/0.1',
        'case_id': 'case:' + digest([burst['target_host'], burst['source_ip'],
                                    burst['username'], burst['trigger_id']]),
        'target_host': burst['target_host'], 'target_ip': failures[0]['target_ip'],
        'source_ip': burst['source_ip'], 'username': burst['username'],
        'status': 'suspicious_login_sequence' if success else 'possible_password_guessing',
        'first_seen': stages[0]['start_time'], 'last_seen': stages[-1]['end_time'],
        'stages': stages, 'confirmed_compromise': False, 'training_label': None,
        'explanation': 'Repeated password failures for the same source, target and account.' +
            (' A subsequent successful login was observed within the configured window.' if success else '') +
            (' A preceding reconnaissance alert was observed.' if earlier else '')}


def build_cases(events, config):
    events=list({e['event_id']:e for e in events}.values())
    from lab_recon import scan_evidence
    scans = scan_evidence(events,config)
    groups = defaultdict(list)
    for e in events:
        if e['kind'].startswith('auth.'):
            groups[(e['target_host'], e['source_ip'], e['username'],e['target_ip'])].append(e)
    cases = {}
    for key, timeline in groups.items():
        recent = deque()
        active = None
        for event in sorted(timeline, key=lambda e: (e['event_time'], e['event_id'])):
            t = instant(event['event_time'])
            if event['kind'] == 'auth.failure':
                if event.get('auth_method') != 'password':
                    continue
                recent.append(event)
                while recent and (t-instant(recent[0]['event_time'])).total_seconds() > config['failure_window_seconds']:
                    recent.popleft()
                if len(recent) >= config['failure_threshold']:
                    if active is None or (t-active['last_trigger']).total_seconds() > config['success_window_seconds'] or active.get('success'):
                        active = {'target_host': key[0], 'source_ip': key[1], 'username': key[2],
                            'trigger_id': event['event_id'], 'failures': {}}
                    active['last_trigger'] = t
                    active['failures'].update({e['event_id']: e for e in recent})
                    case = case_for(active, scans, config=config)
                    cases[case['case_id']] = case
            elif active is not None and not active.get('success'):
                delay = (t-active['last_trigger']).total_seconds()
                if 0 < delay <= config['success_window_seconds']:
                    active['success'] = event
                    case = case_for(active, scans, success=event, config=config)
                    cases[case['case_id']] = case
                    # A later burst must have its own failures, not reuse this one.
                    recent.clear()
    from lab_web import build_web_cases
    for case in build_web_cases(events, config, digest, scans=scans):
        cases[case['case_id']] = case
    consumed_scans = {eid for case in cases.values() for s in case['stages']
                      if s['name'] == 'possible_recon' for eid in s['evidence_ids']}
    scan_groups = defaultdict(list)
    for e in scans:
        if e['event_id'] not in consumed_scans:
            scan_groups[(e['target_host'], e['source_ip'],e['sensor_id'],e['target_ip'])].append(e)
    for key, timeline in scan_groups.items():
        cluster = []
        for e in sorted(timeline, key=lambda e: (e['event_time'], e['event_id'])):
            # Bound an episode from its first alert, not by an endless sliding gap.
            if cluster and (instant(e['event_time'])-instant(cluster[0]['event_time'])).total_seconds() > config['recon_window_seconds']:
                add_scan_case(cases, key, cluster)
                cluster = []
            cluster.append(e)
        if cluster:
            add_scan_case(cases, key, cluster)
    from lab_endpoint import extend_cases
    extend_cases(cases, events, config)
    from lab_file_chain import transfer_cases
    for case in transfer_cases(events):
        cases[case['case_id']] = case
    from lab_process_chain import extend_process_cases
    extend_process_cases(cases,events,config)
    from lab_risk import case_assessment
    for case in cases.values():
        case.update(case_assessment(case))
    return sorted(cases.values(), key=lambda c: (c['first_seen'], c['case_id']))


def add_scan_case(cases, key, cluster):
    from lab_recon import stage
    evidence_stage=stage(cluster)
    cid = 'case:' + digest([key, cluster[0]['event_id']])
    cases[cid] = {'schema_version': 'soc-correlation-case/0.1', 'case_id': cid,
        'target_host': key[0], 'target_ip': cluster[0]['target_ip'], 'source_ip': key[1],
        'username': None, 'status': 'possible_recon', 'first_seen': evidence_stage['start_time'],
        'last_seen': cluster[-1]['event_time'], 'confirmed_compromise': False, 'training_label': None,
        'stages': [evidence_stage],
        'explanation': 'Distinct TCP destination ports observed from the same source to the same target at one sensor within a bounded window. Authorized scanning can produce the same pattern.'}


class Correlator:
    def __init__(self, source_directory, output_directory, config=None):
        self.source_directory = Path(source_directory)
        self.directory = Path(output_directory)
        self.config = {**DEFAULTS, **(config or {})}
        for key in ('failure_threshold', 'failure_window_seconds', 'success_window_seconds',
                    'recon_window_seconds', 'max_events','recon_port_threshold','recon_port_window_seconds',
                    'endpoint_window_seconds'):
            if key == 'endpoint_window_seconds' and key not in self.config:
                continue
            if type(self.config[key]) is not int or self.config[key] < 1:
                raise ValueError('Invalid correlation configuration: ' + key)
        if not 2<=self.config['recon_port_threshold']<=65536 or self.config['recon_port_window_seconds']>3600:
            raise ValueError('Invalid reconnaissance port/window configuration')
        from lab_campaign import validate
        self.config = validate(self.config)
        self.config['protected_ip'] = str(ipaddress.ip_address(self.config['protected_ip']))
        from live_config import validated_assets, output_name
        if 'assets' in self.config:
            self.config['assets'] = validated_assets(self.config['assets'])
        self.sources = tuple(self.config.get('source_kinds', {})) or SOURCES
        names = [output_name(name) for name in self.sources]
        if len(set(names)) != len(names):
            raise ValueError('Correlation source filenames must be unique')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.offsets = {name: 0 for name in self.sources}
        self.pending = {name: b'' for name in self.sources}
        self.lines = Counter()
        self.counts = Counter()
        self.events = {}
        self.cases = []
        self.chains = []
        self.deferred = False
        self.buffered_events = []
        self.buffered_errors = []
        self.web_activity = []
        self.buffered_web = []
        self.web_log = self.directory/'web-events.jsonl'
        self.event_log = self.directory/'correlation-events.jsonl'
        self.errors = self.directory/'correlation-errors.jsonl'
        self.snapshot = self.directory/'correlation-cases.json'
        for path in (self.event_log, self.errors, self.snapshot):
            if path.exists():
                raise ValueError('Correlation output exists; choose a new directory/session')
        self.event_log.touch()
        self.errors.touch()
        self.web_log.touch(exist_ok=False)
        self.write('running')

    def emit_event(self, event):
        row = {**event, 'source_refs': list(event['source_refs'])}
        if self.deferred:
            self.buffered_events.append(row)
        else:
            append(self.event_log, [row])

    def flush(self):
        if self.buffered_web:
            append(self.web_log, self.buffered_web)
            self.buffered_web.clear()
        if self.buffered_events:
            append(self.event_log, self.buffered_events)
            self.buffered_events.clear()
        if self.buffered_errors:
            append(self.errors, self.buffered_errors)
            self.buffered_errors.clear()

    def process(self, source, raw, byte_offset=None):
        self.lines[source] += 1
        if not raw.strip():
            return False
        ref = {'source_file': source, 'record_number': self.lines[source],
               'raw_sha256': hashlib.sha256(raw).hexdigest()}
        ref.update(self.config.get('source_origins', {}).get(source, {}))
        if byte_offset is not None:
            ref['byte_offset'] = byte_offset
        try:
            if self.config.get('source_kinds', {}).get(source) == 'web':
                from lab_web import apache_tsv, sql_evidence
                web = apache_tsv(raw)
                web['target_host'] = ip_host(web['target_ip'],self.config)
                web['source_ref'] = ref
                self.counts['http_requests'] += 1
                self.web_activity.append(web)
                if self.deferred: self.buffered_web.append(web)
                else: append(self.web_log,[web])
                if self.config.get('attack_chain_enabled'):
                    web['http_origin'] = self.config.get('source_origins',{}).get(source,{}).get('source_container','')+'|'+source
                e = sql_evidence(web)
                if e: e.pop('source_ref',None)
                elif self.config.get('attack_chain_enabled'):
                    e = {k:web[k] for k in ('event_time','available_time','source_ip','source_port','target_ip',
                        'target_host','destination_port','http_status','duration_us','evidence_provider','http_origin','http_method','url_path')}
                    e.update(kind='web.request', http_record_id=web['record_id'])
            else:
                e = normalize_line(source, raw, self.config)
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            self.counts['invalid_source_records'] += 1
            row = {**ref, 'error': str(exc)}
            if self.deferred:
                self.buffered_errors.append(row)
            else:
                append(self.errors, [row])
            return False
        if e is None:
            self.counts['ignored_records'] += 1
            return False
        eid = 'event:' + digest(e)
        if eid in self.events:
            self.counts['duplicate_views'] += 1
            # Keep both sensor/auth and Wazuh provenance without double counting.
            old = self.events[eid]
            if ref not in old['source_refs']:
                old['source_refs'].append(ref)
                self.emit_event(old)
            return False
        if len(self.events) >= self.config['max_events']:
            raise RuntimeError('Correlation event limit reached; close this session and start a new one. Raw logs remain available.')
        e = {**e, 'schema_version': 'soc-event/0.1', 'event_id': eid, 'source_refs': [ref]}
        self.events[eid] = e
        self.counts[e['kind']] += 1
        self.emit_event(e)
        return True

    def consume(self):
        self.web_activity.clear()
        more, changed = False, False
        for name in self.sources:
            path = self.source_directory/name
            size = path.stat().st_size
            if size < self.offsets[name]:
                raise RuntimeError('Captured raw file truncated: ' + name)
            with path.open('rb') as stream:
                stream.seek(self.offsets[name])
                block = stream.read(4*1024*1024)
            byte_offset = self.offsets[name] - len(self.pending[name])
            self.offsets[name] += len(block)
            data = self.pending[name] + block
            end = data.rfind(b'\n')+1
            self.pending[name] = data[end:]
            if len(self.pending[name]) > 16*1024*1024:
                raise RuntimeError('Correlation input line exceeds 16 MiB')
            self.deferred = True
            try:
                for line in data[:end].splitlines(keepends=True):
                    changed = self.process(name, line.rstrip(b'\r\n'), byte_offset) or changed
                    byte_offset += len(line)
            finally:
                self.deferred = False
                self.flush()
            more = path.stat().st_size > self.offsets[name] or more
        if changed:
            # Rebuild from event time, so delayed/out-of-order source delivery
            # yields the same final cases as sorted offline replay.
            self.cases = build_cases(list(self.events.values()), self.config)
            from lab_campaign import build_chains
            self.chains = build_chains(list(self.events.values()), self.cases, self.config)
            self.write('running')
        return more

    def write(self, status, capture_status=None):
        from soc_ai.common import write_json
        write_json(self.snapshot, {'version': 'soc-correlation/0.1', 'status': status,
            'complete': status == 'completed', 'config': self.config,
            'source_directory': str(self.source_directory), 'capture_status': capture_status,
            'counts': dict(self.counts), 'unique_events': len(self.events),
            'case_count': len(self.cases), 'cases': self.cases,
            'chain_count':len(self.chains), 'chains':self.chains,
            'unfinished_source_lines': [n for n, tail in self.pending.items() if tail],
            'policy': {'mlp_prediction_alone_creates_chain': False,
                'same_host_source_and_account_for_auth': True,
                'event_time_utc': True, 'predictions_are_not_labels': True,
                'compromise_is_not_proven_by_login': True}})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--config', type=Path)
    a = p.parse_args()
    try:
        # Replay only an explicitly closed capture, verify any recorded hashes.
        session = json.loads((a.session/'session.json').read_text(encoding='utf-8-sig'))
        if not session.get('closed'):
            raise ValueError('Offline replay requires a closed session')
        config = json.loads(a.config.read_text(encoding='utf-8-sig')) if a.config else None
        if config and 'sources' in config:
            from live_config import load_config
            config = load_config(a.config)['correlation']
        replay_sources = tuple((config or {}).get('source_kinds',{})) or SOURCES
        for name in replay_sources:
            expected = session.get('sha256', {}).get(name)
            if expected:
                h = hashlib.sha256()
                with (a.session/name).open('rb') as stream:
                    for block in iter(lambda: stream.read(1024*1024), b''):
                        h.update(block)
                if h.hexdigest() != expected:
                    raise ValueError('Raw input hash mismatch: ' + name)
        engine = Correlator(a.session, a.output, config)
        while engine.consume():
            pass
        status = 'completed' if session.get('status') == 'completed' and not any(engine.pending.values()) and not engine.counts['invalid_source_records'] else 'degraded'
        engine.write(status, session.get('status'))
        print('CORRELATION_COMPLETE:', engine.snapshot)
        print(json.dumps({'unique_events': len(engine.events), 'cases': len(engine.cases),
            'statuses': dict(Counter(c['status'] for c in engine.cases)),
            'counts': dict(engine.counts)}, indent=2))
        return 0 if status == 'completed' else 2
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
