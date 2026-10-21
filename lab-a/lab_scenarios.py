"""Plan, deterministic offline replay, and independently evidenced benchmark import.

This tool never runs Docker, generates network traffic, trains a model, or labels
from an AI prediction/rule. Synthetic replay verifies contracts, not accuracy.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import sys
import tempfile
from types import SimpleNamespace

CATALOG = Path(__file__).with_name('scenarios') / 'catalog-v1.json'
SOURCES = {'ubuntu-auth.log': 'auth', 'suricata-eve.jsonl': 'eve',
           'wazuh-alerts.jsonl': 'wazuh', 'apache-requests.tsv': 'web'}
BASE = datetime(2026, 10, 19, 0, 0, 0, tzinfo=timezone.utc)
CLIENT, TARGET = '192.0.2.10', '192.0.2.20'  # Documentation-only fixtures.
MAX_LINE = 16 * 1024 * 1024


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False,
                                    allow_nan=False) + '\n', encoding='utf-8')


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load_object(path):
    value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object: ' + str(path))
    return value


def catalogue():
    return load_object(CATALOG)['scenarios']


def safe_relative(root, value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('A nonempty POSIX relative path is required')
    path = Path(value)
    if path.is_absolute() or PureWindowsPath(value).drive or any(p in ('.', '..') for p in path.parts):
        raise ValueError('Absolute/traversing artifact path is forbidden: ' + value)
    candidate = Path(root) / path
    if not candidate.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Artifact escapes its directory: ' + value)
    for parent in (candidate, *candidate.parents):
        if parent == Path(root).parent:
            break
        if parent.is_symlink():
            raise ValueError('Symlink artifacts are not accepted: ' + value)
    if not candidate.is_file():
        raise ValueError('Artifact is not a regular file: ' + value)
    return candidate


def stamp(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def auth(seconds, outcome='Failed', user='labtest', source=CLIENT, host='ubuntu-endpoint'):
    return (f'{stamp(seconds)} {host} sshd[321]: {outcome} password for '
            f'{user} from {source} port {42000 + int(seconds)} ssh2\n').encode()


def flow(number=0, port=22, seconds=1, source=CLIENT, target=TARGET):
    return {'event_type': 'flow', 'flow_id': str(10**18 + number),
        'timestamp': stamp(seconds + 2), 'src_ip': source, 'src_port': 42000 + number,
        'dest_ip': target, 'dest_port': port, 'proto': 'TCP',
        'app_proto': 'ssh' if port == 22 else 'http' if port == 80 else 'unknown',
        'flow': {'start': stamp(seconds), 'end': stamp(seconds + 1),
            'pkts_toserver': 4, 'pkts_toclient': 3,
            'bytes_toserver': 400, 'bytes_toclient': 300,
            'state': 'closed', 'reason': 'timeout'}}


def web(target='/?id=1', seconds=1, number=0):
    epoch = int((BASE + timedelta(seconds=seconds)).timestamp()) * 1000000
    return ('\t'.join([str(epoch), str(epoch + 2000), CLIENT, str(43000 + number),
        TARGET, '80', 'GET', target, '200', '1024', '2000', 'lab-replay']) + '\n').encode()


def json_lines(rows):
    return b''.join((json.dumps(row, separators=(',', ':')) + '\n').encode() for row in rows)


def correlation_config():
    return {'all_agents': True, 'assets': [{'host': 'ubuntu-endpoint', 'ips': [TARGET]}],
            'source_kinds': dict(SOURCES)}


def fixture(directory, name, records):
    directory = Path(directory) / name
    directory.mkdir()
    for source in SOURCES:
        (directory / source).write_bytes(records.get(source, b''))
    dump(directory / 'session.json', {'format': 'soc-capture/1.0', 'session_id': name,
        'scenario_id': name, 'scenario_id_is_ground_truth': False,
        'synthetic': True, 'closed': True, 'status': 'completed',
        'notice': 'SYNTHETIC CONTRACT FIXTURE: never use to claim detection quality.',
        'sha256': {source: sha256(directory / source) for source in SOURCES}})
    return directory


def replay(directory):
    """Write reproducible fixtures and report checks. No real Predictor or Docker."""
    from lab_correlation import Correlator
    from lab_context import ContextDetector
    from lab_web import apache_tsv
    from soc_ai.flow import normalize, features, FEATURE_HASH
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=False)
    checks = []

    def check(name, condition, detail):
        checks.append({'id': name, 'passed': bool(condition), 'detail': detail})

    failures = b''.join(auth(t) for t in range(10, 18))
    cases = [
        ('normal-ssh', auth(20, 'Accepted'), []),
        ('ssh-below-threshold', b''.join(auth(t) for t in range(10, 17)) + auth(20, 'Accepted'), []),
        ('ssh-fail-success', failures + auth(20, 'Accepted'), ['suspicious_login_sequence']),
        ('ssh-success-before', auth(1, 'Accepted') + failures, ['possible_password_guessing']),
        ('ssh-success-other-user', failures + auth(20, 'Accepted', user='other'), ['possible_password_guessing']),
        ('ssh-success-other-source', failures + auth(20, 'Accepted', source='192.0.2.11'), ['possible_password_guessing']),
        ('ssh-success-other-host', failures + auth(20, 'Accepted', host='other-host'), ['possible_password_guessing']),
        ('ssh-success-late', failures + auth(318, 'Accepted'), ['possible_password_guessing'])]
    for name, auth_bytes, expected in cases:
        src = fixture(root, name, {'ubuntu-auth.log': auth_bytes,
            'suricata-eve.jsonl': json_lines([flow()])})
        engine = Correlator(src, src / 'correlation', correlation_config())
        while engine.consume():
            pass
        statuses = [case['status'] for case in engine.cases]
        check(name, statuses == expected, {'expected': expected, 'actual': statuses})
        check(name + '-not-labels', all(case['training_label'] is None and
            not case['confirmed_compromise'] for case in engine.cases),
            'Cases preserve hypothesis semantics and never create training labels.')

    # The success arrives before the failures are available to a later poll.
    src = fixture(root, 'delayed-delivery', {'ubuntu-auth.log': auth(20, 'Accepted')})
    engine = Correlator(src, src / 'correlation', correlation_config())
    engine.consume()
    with (src / 'ubuntu-auth.log').open('ab') as stream:
        stream.write(failures)
    engine.consume()
    check('event-time-rebuild-across-polls',
        [case['status'] for case in engine.cases] == ['suspicious_login_sequence'],
        'Delayed old failures are rebuilt by event time; source poll order is not stage order.')
    check('provenance-is-raw', all(all('raw_sha256' in ref and 'byte_offset' in ref
        for ref in event['source_refs']) for event in engine.events.values()),
        'Raw hashes and byte offsets are retained in normalized evidence.')

    benign_urls = ['/?id=1', '/catalog', '/tools', '/assets/script.js',
                   '/?author=O%27Reilly', '/?q=union+representatives']
    bad_urls = ['/?id=1%20UNION%20SELECT%201,2', '/?id=%27%20OR%201%3D1--%20']
    for name, urls, expected_count in [('normal-http', benign_urls, 0),
                                       ('web-sqli-indicator', bad_urls, 1)]:
        src = fixture(root, name, {'apache-requests.tsv': b''.join(web(url, number=i)
            for i, url in enumerate(urls)), 'suricata-eve.jsonl': json_lines([flow(port=80)])})
        engine = Correlator(src, src / 'correlation', correlation_config())
        engine.consume()
        check(name, len(engine.cases) == expected_count,
            {'request_count': len(urls), 'case_count': len(engine.cases),
             'statuses': [case['status'] for case in engine.cases]})
        check(name + '-200-not-proof', all(not case['confirmed_compromise'] and
            case['training_label'] is None for case in engine.cases),
            'HTTP 200 and SQL indicators never prove exploitation or create an MLP SQLi class.')

    for name, ports, expected in [('scan-many-ports', range(1, 33), True),
                                  ('repeat-single-port', [22] * 32, False)]:
        events = [flow(i, port, seconds=1) for i, port in enumerate(ports)]
        src = fixture(root, name, {'suricata-eve.jsonl': json_lines(events)})
        context = ContextDetector()
        for event in events:
            context.observe_flow(event, 'suricata-eve.jsonl', 'ubuntu-endpoint')
        signals = context.snapshot()['signals']
        signal = any(row['kind'] == 'context.distinct_port_sweep' for row in signals)
        check(name + '-port-diversity', signal == expected,
            {'flows': len(events), 'distinct_ports': len(set(ports)),
             'shadow_signals': len(signals), 'threshold': 20})
        check(name + '-shadow-only', all(row.get('mode') == 'shadow' and
            row.get('training_label') is None and not row.get('confirmed_compromise') for row in signals),
            'Context has no trained model probability and cannot become ground truth.')

    for name, count, expected in [('http-normal-rate', 5, False), ('http-bounded-burst', 25, True)]:
        context = ContextDetector({'http_enabled': True, 'http_threshold': 20})
        for i in range(count):
            event = apache_tsv(web('/soc-lab-health', seconds=1 + i // 5, number=i))
            context.observe_http(event)
        signals = context.snapshot()['signals']
        check(name, any(row['kind'] == 'context.http_request_rate' for row in signals) == expected,
            {'requests': count, 'threshold_explicit_for_fixture': 20,
             'notice': 'One-source rate signal is not a validated DoS classifier.'})

    normalized = normalize(flow())
    check('flow-id-no-float-loss', normalized['flow_id'] == str(10**18), normalized['flow_id'])
    check('feature-contract-24', features(normalized).shape == (24,), {'feature_hash': FEATURE_HASH})
    check('completed-flow-availability', normalized['available_time'] >= normalized['end_time'],
          'Completed counters are not available at the flow start.')
    checks.extend(resilience_replay(root))
    fixture_manifests = []
    for path in sorted(root.glob('*/session.json')):
        state = load_object(path)
        # A replay deliberately appends across polls; close the exported fixture
        # with hashes of its final bytes rather than an obsolete initial hash.
        state['sha256'] = {name: sha256(path.parent / name) for name in SOURCES}
        dump(path, state)
        fixture_manifests.append({'id': path.parent.name,
            'path': path.relative_to(root).as_posix(), 'sha256': sha256(path)})
    report = {'schema_version': 'soc-lab-scenario-replay/1.0', 'synthetic': True,
        'accuracy_evidence': False, 'real_model_inference_performed': False,
        'network_traffic_generated': False,
        'notice': 'Pipeline contract checks only. Do not mix fixtures into real training or quality gates.',
        'checks': checks, 'passed': sum(item['passed'] for item in checks),
        'failed': sum(not item['passed'] for item in checks), 'fixtures': fixture_manifests}
    dump(root / 'replay-report.json', report)
    return report


def resilience_replay(root):
    """Exercise real cursor/outbox code with memory-only transport."""
    import contextlib
    import io
    from soc_live_collector import Collector
    from wazuh_bridge import Publisher, make_event
    results = []

    def result(name, passed, detail):
        results.append({'id': name, 'passed': bool(passed), 'detail': detail})

    class MemoryCollector(Collector):
        remote = {'/auth': ('1:100', b''), '/eve': ('1:200', b'')}
        unavailable = set()

        def command(self, argv):
            raise AssertionError('Offline replay must never call Docker')

        def container_id(self, container):
            return 'synthetic-container-id'

        def read(self, container, path, offset, count):
            if path in self.unavailable:
                raise RuntimeError('Synthetic source unavailable')
            identity, payload = self.remote[path]
            return identity, len(payload), payload[offset:offset + count]

        def old_path(self, source):
            return next((path for path, (identity, _) in self.remote.items()
                         if identity == source['identity']), None)

    args = SimpleNamespace(output_dir=str(root / 'collector'), scenario_id='SYNTHETIC-resilience',
        docker_command=sys.executable, interval=.1, grace=0, from_start=False, resume=None,
        sources=[('auth', 'ubuntu-endpoint', '/auth', 'auth.log'),
                 ('eve', 'ubuntu-endpoint', '/eve', 'eve.jsonl')])
    collector = MemoryCollector(args)
    collector.state['synthetic'] = True
    collector.state['accuracy_evidence'] = False
    collector.save()
    try:
        collector.remote['/auth'] = ('1:100', b'first\npartial')
        collector.remote['/eve'] = ('1:200', b'first-eve\n')
        collector.poll()
        result('partial-newline-withheld', (collector.folder / 'auth.log').read_bytes() == b'first\n',
               'A partial line is checkpointed, never published as a complete record.')
        collector.unavailable.add('/auth')
        collector.remote['/eve'] = ('1:200', b'first-eve\nsecond-eve\n')
        with contextlib.redirect_stdout(io.StringIO()):
            collector.poll()
        result('source-missing-other-source-continues',
            collector.state['sources'][0]['last_error'] is not None and
            (collector.folder / 'eve.jsonl').read_bytes().endswith(b'second-eve\n'),
            'The missing source has an explicit error; a healthy source commits independently.')
        collector.unavailable.clear()
        collector.remote['/auth.1'] = ('1:100', b'first\npartial-tail\n')
        collector.remote['/auth'] = ('1:101', b'new-file\n')
        with contextlib.redirect_stdout(io.StringIO()):
            collector.poll()
        result('rotation-drains-old-inode',
            (collector.folder / 'auth.log').read_bytes() == b'first\npartial-tail\nnew-file\n'
            and len(collector.state['rotations']) == 1 and not collector.state['gaps'],
            'An available renamed inode is drained before switching to the new file.')
        # Simulate bytes published before a crash but not committed to checkpoint.
        folder = collector.folder
        with (folder / 'auth.log').open('ab') as stream:
            stream.write(b'uncommitted\n')
    finally:
        collector.lock_file.close()
    args.resume = str(folder)
    with contextlib.redirect_stdout(io.StringIO()):
        resumed = MemoryCollector(args)
    try:
        before = (folder / 'auth.log').read_bytes()
        resumed.poll()
        result('restart-reconciles-committed-cursor',
            b'uncommitted' not in before and (folder / 'auth.log').read_bytes() == before
            and bool(list(folder.glob('auth.log.uncommitted-*'))),
            'Uncommitted host bytes are preserved separately; committed records are not duplicated.')
        resumed.remote.pop('/auth.1')
        resumed.remote['/auth'] = ('1:102', b'next-file\n')
        with contextlib.redirect_stdout(io.StringIO()):
            resumed.poll()
        result('missing-inode-marks-gap', bool(resumed.state['gaps']),
            'An unavailable old inode is a gap, not a lossless-capture success.')
    finally:
        resumed.lock_file.close()

    path = root / 'synthetic-outbox.sqlite'
    event = make_event('connection_test', ['synthetic-replay', 'outage'],
                       synthetic=True, accuracy_evidence=False)
    def offline(*_):
        raise RuntimeError('Synthetic manager outage')
    publisher = Publisher(path, 'original-manager', offline)
    try:
        publisher.enqueue(event)
        publisher.enqueue(event)
        publisher.flush(force=True)
        result('outbox-outage-persisted', publisher.pending == 1 and bool(publisher.last_error),
               'Stable event_id deduplicates enqueue and failed delivery stays pending.')
    finally:
        publisher.close()
    sent = []
    publisher = Publisher(path, 'other-manager', lambda *items: sent.append(items))
    try:
        publisher.flush(force=True)
        result('outbox-restart-retries-original-route', publisher.pending == 0 and len(sent) == 1
            and sent[0][0] == 'original-manager' and sent[0][2] == event['event_id'],
            'Retry preserves the stored manager and event ID. It does not prove indexer delivery.')
    finally:
        publisher.close()
    return results


def validate_evidence(path, session, scenario, expected_attack):
    """Validate explicit operator assertions; this cannot establish their truth."""
    from soc_ai.flow import parse_time
    import ipaddress
    evidence = load_object(path)
    if evidence.get('schema_version') != 'soc-lab-independent-evidence/1.0':
        raise ValueError('Unsupported independent evidence schema')
    if evidence.get('independent') is not True or evidence.get('synthetic') is not False:
        raise ValueError('Real benchmark evidence must explicitly be independent:true and synthetic:false')
    if evidence.get('capture_session_id') != session.get('session_id') or evidence.get('scenario') != scenario:
        raise ValueError('Independent evidence belongs to a different capture/scenario')
    if evidence.get('expected_attack') is not expected_attack:
        raise ValueError('Independent outcome differs from the requested outcome')
    if not isinstance(evidence.get('source'), str) or not evidence['source'].strip():
        raise ValueError('Independent evidence source is required')
    parse_time(evidence.get('collected_at'))
    scope = evidence.get('flow_scope', {})
    if not isinstance(scope, dict) or scope.get('all_selected_flows_share_outcome') is not True:
        raise ValueError('A homogeneous, independently checked flow scope is required')
    start, end = parse_time(scope.get('start_time')), parse_time(scope.get('end_time'))
    if end <= start:
        raise ValueError('Flow scope end must be after start')
    for name in ('src_ip', 'dest_ip'):
        if str(ipaddress.ip_address(scope.get(name))) != scope[name]:
            raise ValueError('Flow scope requires canonical source/destination IPs')
    if scope['src_ip'] == scope['dest_ip']:
        raise ValueError('Flow scope source and target must differ')
    ports = scope.get('dest_ports')
    if ports is not None and (not isinstance(ports, list) or not ports or any(
            type(value) is not int or not 1 <= value <= 65535 for value in ports)):
        raise ValueError('dest_ports must be a nonempty list of valid integer ports')
    artifacts = evidence.get('artifacts')
    if not isinstance(artifacts, list) or len(artifacts) < 2:
        raise ValueError('Require an operator record and separate server/packet evidence')
    kinds, checked = set(), []
    allowed = {'operator_log', 'command_transcript', 'packet_capture', 'auth_server_log',
               'web_server_log', 'application_result'}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get('kind') not in allowed:
            raise ValueError('Unsupported evidence artifact kind; AI/rule output is not ground truth')
        source = safe_relative(Path(path).parent, artifact.get('path'))
        if source.stat().st_size == 0:
            raise ValueError('Evidence artifact must not be empty: ' + str(source))
        kinds.add(artifact['kind'])
        checked.append((artifact['kind'], source))
    if len({source.resolve() for _, source in checked}) != len(checked):
        raise ValueError('Evidence artifacts must be distinct files')
    if not kinds.intersection({'operator_log', 'command_transcript'}) or not kinds.intersection(
            {'packet_capture', 'auth_server_log', 'web_server_log', 'application_result'}):
        raise ValueError('Require both operator and independent server/packet evidence')
    return evidence, checked, start, end


def register(session_path, evidence_path, directory, session_id, role, scenario,
             expected_attack, expected_class=None, eve_name='suricata-eve.jsonl'):
    """Copy scoped, hash-verified real flows into a new final-benchmark directory."""
    import re
    from soc_ai.flow import normalize, parse_time
    from soc_ai.common import CLASSES
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', session_id):
        raise ValueError('Use a simple, unique benchmark session ID')
    if role not in ('validation', 'test') or type(expected_attack) is not bool:
        raise ValueError('Role must be validation/test and expected outcome boolean')
    if scenario not in {item['id'] for item in catalogue()}:
        raise ValueError('Unknown scenario ID; inspect the plan command')
    if expected_class is not None and (expected_class not in CLASSES or
            (expected_class != 'BENIGN') != expected_attack):
        raise ValueError('Class must be a compatible existing MLP class; SQLi/burst are not new classes')
    source = Path(session_path)
    session_manifest_hash = sha256(source / 'session.json')
    session = load_object(source / 'session.json')
    if session.get('format') != 'soc-capture/1.0' or session.get('closed') is not True or session.get('status') != 'completed':
        raise ValueError('Require an explicitly closed, completed capture')
    if ('synthetic' in session and session['synthetic'] is not False) or not isinstance(session.get('session_id'), str) or not session['session_id']:
        raise ValueError('Synthetic or unidentified captures cannot establish real quality')
    if session.get('gaps') or session.get('partials'):
        raise ValueError('Capture contains gaps/partial records; keep it for resilience analysis only')
    sources = session.get('sources')
    if not isinstance(sources, list) or not sources or any(not isinstance(row, dict) or row.get('last_error') for row in sources):
        raise ValueError('Capture source metadata is missing or contains unresolved errors')
    recorded = session.get('sha256')
    if not isinstance(recorded, dict) or not recorded:
        raise ValueError('Closed capture must record raw source hashes')
    expected_names = {row.get('output') for row in sources}
    if None in expected_names or not expected_names.issubset(recorded):
        raise ValueError('Every capture source must have a recorded hash')
    for name, expected in recorded.items():
        path = safe_relative(source, name)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected) or sha256(path) != expected:
            raise ValueError('Capture SHA256 mismatch: ' + name)
    if eve_name not in expected_names or eve_name not in recorded:
        raise ValueError('Selected EVE file is not a hashed capture source')
    evidence, artifacts, start, end = validate_evidence(evidence_path, session, scenario, expected_attack)
    scope = evidence['flow_scope']
    target = Path(directory)
    if target.exists():
        raise ValueError('Output exists; choose a new benchmark directory')
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + target.name + '-building-', dir=target.parent))
    try:
        (staging / 'evidence').mkdir()
        refs, artifact_hashes = [], {}
        for index, (kind, path) in enumerate(artifacts, 1):
            name = re.sub(r'[^A-Za-z0-9._-]', '_', path.name)
            relative = 'evidence/' + str(index).zfill(2) + '-' + name
            shutil.copyfile(path, staging / relative)
            refs.append(relative)
            artifact_hashes[relative] = {'kind': kind, 'sha256': sha256(staging / relative)}
        copied_evidence = {**evidence, 'artifacts': [
            {'path': ref, **artifact_hashes[ref]} for ref in refs]}
        dump(staging / 'independent-evidence.json', copied_evidence)
        counters = Counter()
        with safe_relative(source, eve_name).open('rb') as stream, (staging / 'flows.ndjson').open('wb') as output:
            for number, raw in enumerate(iter(lambda: stream.readline(MAX_LINE + 1), b''), 1):
                if len(raw) > MAX_LINE or not raw.endswith(b'\n'):
                    raise ValueError('EVE contains an oversized or partial record at line ' + str(number))
                event = json.loads(raw)
                if not isinstance(event, dict):
                    raise ValueError('EVE record must be an object at line ' + str(number))
                if event.get('event_type') != 'flow':
                    counters['ignored_non_flow'] += 1
                    continue
                item = normalize(event)
                # Use completed flow boundaries, never alert time or AI output.
                if not (start <= parse_time(item['start_time']) and parse_time(item['end_time']) <= end):
                    counters['outside_time_scope'] += 1
                    continue
                if item['src_ip'] != scope['src_ip'] or item['dest_ip'] != scope['dest_ip'] or (
                        scope.get('dest_ports') is not None and item['dest_port'] not in scope['dest_ports']):
                    counters['outside_endpoint_scope'] += 1
                    continue
                # Raw, normalized flow contract; source identity stays in provenance.
                item['record_id'] = 'benchmark:' + hashlib.sha256(
                    (session['session_id'] + ':' + eve_name + ':' + str(number)).encode()).hexdigest()
                item['source_ref'] = {'source_file': eve_name, 'record_number': number,
                                      'raw_sha256': hashlib.sha256(raw).hexdigest()}
                output.write((json.dumps(item, separators=(',', ':'), allow_nan=False) + '\n').encode())
                counters['selected_flows'] += 1
        if not counters['selected_flows']:
            raise ValueError('Independent flow scope selects no completed flows')
        # A closed capture still may be edited by another process. Recheck the
        # input actually read so selected records cannot retain an old hash.
        if sha256(source / eve_name) != recorded[eve_name] or sha256(source / 'session.json') != session_manifest_hash:
            raise ValueError('Closed capture changed during registration; retry from an immutable copy')
        entry = {'id': session_id, 'role': role, 'scenario': scenario, 'synthetic': False,
            'flows': 'flows.ndjson', 'sha256': sha256(staging / 'flows.ndjson'),
            'expected_attack': expected_attack,
            'evidence': {'independent': True, 'source': evidence['source'],
                'collected_at': evidence['collected_at'],
                'notes': 'Operator attests a homogeneous scoped outcome. Tool checks structure/hashes, not truth.',
                'sha256': {ref: metadata['sha256'] for ref, metadata in artifact_hashes.items()}},
            'provenance': {'capture_session_id': session['session_id'],
                'generator': 'lab_scenarios.register/1.0', 'evidence_refs': refs + ['independent-evidence.json'],
                'capture_manifest_sha256': session_manifest_hash,
                'raw_eve_sha256': recorded[eve_name], 'flow_scope': scope}}
        if expected_class is not None:
            entry['expected_class'] = expected_class
        manifest = {'schema_version': 'soc-lab-benchmark/1.0', 'synthetic': False,
            'notice': 'Real operator evidence is an assertion; verify it independently before accepting quality.',
            'sessions': [entry]}
        dump(staging / 'manifest.json', manifest)
        dump(staging / 'selection-report.json', {'counts': dict(counters), 'synthetic': False,
            'capture_session_id': session['session_id'], 'flow_scope': scope,
            'not_a_training_manifest': True,
            'limitations': ['Does not independently establish operator evidence truth.',
                'No automatic relabeling from AI, Suricata or Wazuh.',
                'Flow-level metrics do not establish campaign/session independence by themselves.',
                'For mixed flow outcomes use independently scoped separate captures; do not label background traffic.']})
        # Output always new; existing directories are never merged or overwritten.
        if target.exists():
            raise ValueError('Output appeared while preparing; choose a new directory')
        staging.rename(target)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('plan', help='Print scenario plans; never execute traffic')
    plan.add_argument('--scenario', choices=[item['id'] for item in catalogue()])
    replay_cli = commands.add_parser('replay', help='Run synthetic contract replay locally; no Docker/model')
    replay_cli.add_argument('--output', type=Path, required=True)
    register_cli = commands.add_parser('register', help='Register closed real capture with independent scoped evidence')
    register_cli.add_argument('--session', type=Path, required=True)
    register_cli.add_argument('--evidence', type=Path, required=True)
    register_cli.add_argument('--output', type=Path, required=True)
    register_cli.add_argument('--id', required=True)
    register_cli.add_argument('--role', choices=('validation', 'test'), required=True)
    register_cli.add_argument('--scenario', choices=[item['id'] for item in catalogue()], required=True)
    register_cli.add_argument('--expected', choices=('benign', 'attack'), required=True)
    register_cli.add_argument('--expected-class', choices=('BENIGN', 'FTP-Patator', 'SSH-Patator', 'Bot', 'PortScan', 'DDoS'))
    register_cli.add_argument('--eve', default='suricata-eve.jsonl')
    return parser


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == 'plan':
            rows = [item for item in catalogue() if not args.scenario or item['id'] == args.scenario]
            print(json.dumps({'mode': 'plan-only', 'traffic_executed': False,
                              'scenarios': rows}, indent=2, ensure_ascii=False))
        elif args.command == 'replay':
            report = replay(args.output)
            print('SYNTHETIC_REPLAY:', args.output / 'replay-report.json')
            print('PASSED:', report['passed'], 'FAILED:', report['failed'], 'ACCURACY_EVIDENCE: false')
            return 0 if report['failed'] == 0 else 2
        else:
            value = register(args.session, args.evidence, args.output, args.id, args.role,
                             args.scenario, args.expected == 'attack', args.expected_class, args.eve)
            print('BENCHMARK_MANIFEST:', args.output / 'manifest.json')
            print('SESSION_ID:', value['sessions'][0]['id'])
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print('ERROR:', str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
