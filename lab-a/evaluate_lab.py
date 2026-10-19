"""Paired, read-only evaluation of complete Lab A bundles on declared lab sessions.

The manifest supplies independent truth. Model/rule predictions never become truth,
and unknown observations never become BENIGN. No model or threshold is changed.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
import random
import re
import sys


SCHEMA = 'soc-lab-benchmark/1.0'
REPORT_SCHEMA = 'soc-lab-benchmark-report/1.0'
CLASSES = ['BENIGN', 'FTP-Patator', 'SSH-Patator', 'Bot', 'PortScan', 'DDoS']
DEFAULT_GATE = {
    'max_benign_fpr': 0.01,
    'min_attack_recall': 0.90,
    'min_coverage': 0.95,
    'max_benign_session_fpr': 0.05,
    'min_attack_session_recall': 0.80,
    'min_benign_sessions': 5,
    'min_attack_sessions': 5,
    'min_benign_samples': 500,
    'min_attack_samples': 500,
    'min_scored_per_session': 100,
    'min_benign_scenarios': 2,
    'min_attack_scenarios': 2,
    'max_fpr_increase': 0.0,
    'max_recall_drop': 0.02,
}
_INTEGER_GATES = {key for key in DEFAULT_GATE if key.startswith('min_') and
                  key not in ('min_attack_recall', 'min_coverage', 'min_attack_session_recall')}
_MAX_LINE_BYTES = 4 * 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + str(key))
        result[key] = value
    return result


def _json(text):
    def invalid_constant(value):
        raise ValueError('Nonfinite JSON number: ' + value)
    return json.loads(text, object_pairs_hook=_no_duplicate_keys,
                      parse_constant=invalid_constant)


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(name + ' must be a nonempty string')
    return value


def _time(value, name):
    _text(value, name)
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ValueError(name + ' must be a timezone-aware ISO datetime') from error
    if result.tzinfo is None:
        raise ValueError(name + ' requires an explicit timezone')
    return result


def _relative_file(root, value, name):
    _text(value, name)
    # Reject Windows absolute/drive paths even when the evaluator runs on Linux.
    windows = PureWindowsPath(value)
    relative = Path(value)
    if (relative.is_absolute() or windows.drive or windows.root or '\\' in value or
            '..' in relative.parts or any(c in value for c in '\x00\r\n')):
        raise ValueError(name + ' must be a relative path inside the manifest directory')
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(name + ' is missing or escapes the manifest directory')
    return path


def validate_gate(value):
    if not isinstance(value, dict):
        raise ValueError('gate must be an object')
    unknown = set(value) - set(DEFAULT_GATE)
    if unknown:
        raise ValueError('Unknown gate option(s): ' + ', '.join(sorted(unknown)))
    result = {**DEFAULT_GATE, **value}
    for key, number in result.items():
        if key in _INTEGER_GATES:
            if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                raise ValueError('gate.' + key + ' must be an integer >= 1')
        elif (isinstance(number, bool) or not isinstance(number, (float, int)) or
              not math.isfinite(number) or not 0 <= number <= 1):
            raise ValueError('gate.' + key + ' must be finite and in [0,1]')
    return result


def load_manifest(path):
    path = Path(path).resolve()
    manifest_hash = sha256(path)
    manifest = _json(path.read_text(encoding='utf-8-sig'))
    if not isinstance(manifest, dict) or manifest.get('schema_version') != SCHEMA:
        raise ValueError('Expected manifest schema_version=' + SCHEMA)
    if type(manifest.get('synthetic')) is not bool:
        raise ValueError('Manifest synthetic must be an explicit boolean')
    sessions = manifest.get('sessions')
    if not isinstance(sessions, list) or not sessions:
        raise ValueError('sessions must be a nonempty array')
    result, ids, paths, capture_ids, identity_owners = [], set(), set(), set(), {}
    for index, session in enumerate(sessions):
        prefix = 'sessions[' + str(index) + ']'
        if not isinstance(session, dict):
            raise ValueError(prefix + ' must be an object')
        session_id = _text(session.get('id'), prefix + '.id')
        if session_id in ids:
            raise ValueError('Duplicate session id: ' + session_id)
        ids.add(session_id)
        if session.get('role') not in ('validation', 'test'):
            raise ValueError(prefix + '.role must be validation or test')
        _text(session.get('scenario'), prefix + '.scenario')
        if type(session.get('expected_attack')) is not bool:
            raise ValueError(prefix + '.expected_attack must be a boolean')
        expected_class = session.get('expected_class')
        if expected_class is not None:
            if expected_class not in CLASSES:
                raise ValueError(prefix + '.expected_class is outside the existing six classes')
            if (expected_class != 'BENIGN') != session['expected_attack']:
                raise ValueError(prefix + '.expected_class contradicts expected_attack')
        synthetic = session.get('synthetic', manifest['synthetic'])
        if type(synthetic) is not bool or manifest['synthetic'] and not synthetic:
            raise ValueError(prefix + '.synthetic cannot override a synthetic manifest')
        evidence = session.get('evidence')
        if not isinstance(evidence, dict) or type(evidence.get('independent')) is not bool:
            raise ValueError(prefix + '.evidence.independent must be an explicit boolean')
        _text(evidence.get('source'), prefix + '.evidence.source')
        _time(evidence.get('collected_at'), prefix + '.evidence.collected_at')
        provenance = session.get('provenance', {})
        if not isinstance(provenance, dict):
            raise ValueError(prefix + '.provenance must be an object')
        capture_id = provenance.get('capture_session_id')
        if not synthetic:
            _text(capture_id, prefix + '.provenance.capture_session_id')
        if capture_id is not None:
            _text(capture_id, prefix + '.provenance.capture_session_id')
            if capture_id in capture_ids:
                raise ValueError('Capture session reused; do not split one capture into independent sessions: ' + capture_id)
            capture_ids.add(capture_id)
        aliases = provenance.get('related_session_ids', [])
        if not isinstance(aliases, list) or any(not isinstance(v, str) or not v for v in aliases):
            raise ValueError(prefix + '.provenance.related_session_ids must be a string array')
        identities = {session_id, *aliases}
        if capture_id is not None:
            identities.add(capture_id)
        for identity in identities:
            if identity in identity_owners:
                raise ValueError('Session identities overlap; one capture cannot count as independent sessions: ' +
                                 identity_owners[identity] + ' and ' + session_id)
            identity_owners[identity] = session_id
        flow_path = _relative_file(path.parent, session.get('flows'), prefix + '.flows')
        if flow_path in paths:
            raise ValueError('Flow input reused by multiple sessions: ' + session['flows'])
        paths.add(flow_path)
        expected_hash = session.get('sha256')
        if not isinstance(expected_hash, str) or not re.fullmatch('[0-9a-f]{64}', expected_hash):
            raise ValueError(prefix + '.sha256 must be a lowercase SHA-256 hex string')
        if sha256(flow_path) != expected_hash:
            raise ValueError('Flow input SHA-256 mismatch: ' + session['flows'])
        result.append({**session, 'synthetic': synthetic, 'provenance': provenance,
                       '_path': flow_path})
    return manifest, result, validate_gate(manifest.get('gate', {})), manifest_hash


def wilson(successes, total, z=1.959963984540054):
    """Two-sided Wilson 95% interval; assumes independent Bernoulli trials."""
    if type(successes) is not int or type(total) is not int or not 0 <= successes <= total:
        raise ValueError('Invalid binomial counts')
    if not total:
        return {'estimate': None, 'lower': None, 'upper': None, 'successes': 0, 'total': 0}
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {'estimate': p, 'lower': max(0.0, center - half), 'upper': min(1.0, center + half),
            'successes': successes, 'total': total}


def _new_metrics():
    return {'counts': Counter(), 'confusion_matrix': [[0] * len(CLASSES) for _ in CLASSES]}


def _add_prediction(metrics, prediction, session):
    counts = metrics['counts']
    if prediction.get('decision') == 'out_of_training_scope':
        counts['out_of_training_scope'] += 1
        counts['scope:' + str(prediction.get('reason', 'unknown'))] += 1
        return
    decision = prediction.get('decision')
    if decision not in ('possible_attack', 'below_alert_threshold'):
        raise ValueError('Unexpected model decision; refusing to count it as BENIGN')
    label = prediction.get('predicted_label')
    if label not in CLASSES:
        raise ValueError('Unexpected model argmax class')
    score, threshold = prediction.get('attack_score'), prediction.get('attack_score_threshold')
    if (isinstance(score, bool) or not isinstance(score, (float, int)) or
            not math.isfinite(score) or not 0 <= score <= 1 or
            isinstance(threshold, bool) or not isinstance(threshold, (float, int)) or
            not math.isfinite(threshold)):
        raise ValueError('Nonfinite/invalid model score or threshold')
    if (score >= threshold) != (decision == 'possible_attack'):
        raise ValueError('Model decision contradicts its frozen threshold')
    counts['scored'] += 1
    alarm, truth = decision == 'possible_attack', session['expected_attack']
    counts['tp' if truth and alarm else 'fn' if truth else 'fp' if alarm else 'tn'] += 1
    expected_class = session.get('expected_class')
    if expected_class is not None:
        metrics['confusion_matrix'][CLASSES.index(expected_class)][CLASSES.index(label)] += 1
        counts['class_scored'] += 1
        counts['class_correct'] += label == expected_class


def _final_metrics(metrics, data_counts):
    counts = metrics['counts']
    scored = counts['scored']
    candidates = data_counts['flow_candidates'] - data_counts['duplicate_observations_removed']
    unknown = candidates - scored
    if unknown < 0:
        raise ValueError('Metric accounting mismatch')
    attack = counts['tp'] + counts['fn']
    benign = counts['fp'] + counts['tn']
    attack_unknown = data_counts.get('attack_candidates', 0) - attack
    return {
        'counts': {key: counts[key] for key in ('scored', 'tp', 'fn', 'fp', 'tn',
                                                'out_of_training_scope', 'class_scored', 'class_correct')},
        'unknown': unknown,
        'coverage': wilson(scored, candidates),
        'binary_attack': {
            'benign_false_positive_rate_scored': wilson(counts['fp'], benign),
            'recall_scored': wilson(counts['tp'], attack),
            'effective_recall_including_unknown': wilson(counts['tp'], attack + attack_unknown),
            'precision_scored': wilson(counts['tp'], counts['tp'] + counts['fp']),
            'unknown_attack_observations': attack_unknown,
            'unknown_are_not_benign_or_binary_fn': True,
        },
        'argmax_multiclass': {
            'class_order': CLASSES,
            'confusion_matrix': metrics['confusion_matrix'],
            'accuracy_scored_known_class': wilson(counts['class_correct'], counts['class_scored']),
            'unknown_not_assigned_a_class': True,
        },
        'out_of_scope_reasons': {key[6:]: value for key, value in counts.items() if key.startswith('scope:')},
    }


def _merge_metrics(target, source):
    target['counts'].update(source['counts'])
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            target['confusion_matrix'][i][j] += source['confusion_matrix'][i][j]


def observation_key(flow):
    """Stable completed-connection identity, independent of wrapper/record/model IDs."""
    endpoints = sorted(((flow['src_ip'], flow['src_port']),
                        (flow['dest_ip'], flow['dest_port'])), key=lambda e: (e[0], -1 if e[1] is None else e[1]))
    payload = [flow['protocol'], endpoints, flow['start_time'], flow['end_time']]
    return hashlib.sha256(json.dumps(payload, separators=(',', ':')).encode()).hexdigest()


def _declared_provenance(value):
    """Collect nested declared identities and hashes without treating paths as truth."""
    ids, hashes = set(), set()
    scalar_ids = {'session_id', 'capture_session_id'}
    array_ids = {'session_ids', 'capture_session_ids', 'validation_session_ids',
                 'test_session_ids', 'all_session_ids', 'related_session_ids'}

    def visit(item, parent='', hash_context=False):
        hash_context = hash_context or 'sha256' in parent.lower() or parent.lower() in ('hash', 'hashes')
        if isinstance(item, dict):
            for key, child in item.items():
                if key in scalar_ids and isinstance(child, str) and child:
                    ids.add(child)
                if key in array_ids and isinstance(child, list):
                    ids.update(v for v in child if isinstance(v, str) and v)
                visit(child, key, hash_context)
        elif isinstance(item, list):
            for child in item:
                visit(child, parent, hash_context)
        elif isinstance(item, str) and hash_context:
            if re.fullmatch('[0-9a-fA-F]{64}', item):
                hashes.add(item.lower())
    visit(value)
    return ids, hashes


def check_training_overlap(metadata, sessions, name):
    from data_markers import known_synthetic
    provenance = metadata.get('training_provenance', metadata.get('training_session_provenance'))
    known = set()
    warnings = []
    if not isinstance(provenance, dict):
        warnings.append(name + ': no training-session provenance; independence is unverified')
        return {'verified_declared_identity_isolation': False,
                'independent_source_isolation_verified': False,
                'known_session_ids': [], 'known_source_sha256': [], 'warnings': warnings}
    for key in ('session_ids', 'validation_session_ids', 'test_session_ids', 'all_session_ids', 'capture_session_ids'):
        values = provenance.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
            raise ValueError(name + ': invalid training_provenance.' + key)
        known.update(values)
    nested_ids, source_hashes = _declared_provenance(provenance)
    known.update(nested_ids)
    for session in sessions:
        identities = {session['id'], *session['provenance'].get('related_session_ids', [])}
        capture_id = session['provenance'].get('capture_session_id')
        if capture_id:
            identities.add(capture_id)
        if identities & known:
            raise ValueError(name + ': benchmark session overlaps a train-time train/validation/test session: ' + session['id'])
        _, session_hashes = _declared_provenance(session)
        if source_hashes & session_hashes:
            raise ValueError(name + ': benchmark input/source SHA-256 overlaps declared training provenance: ' + session['id'])
    declared_isolation = (provenance.get('verified') is True and
                          provenance.get('covers_all_training_sources') is True and bool(known))
    independently_verified = (declared_isolation and provenance.get('independence_verified') is True and
                              provenance.get('raw_sources_rechecked') is True and
                              not known_synthetic(metadata))
    if not declared_isolation:
        warnings.append(name + ': declared local role/cache checks do not prove isolation from all training sources')
    if not independently_verified:
        warnings.append(name + ': source/campaign independence has not been independently verified; declared IDs alone are insufficient')
    return {'verified_declared_identity_isolation': declared_isolation,
            'independent_source_isolation_verified': independently_verified,
            'known_session_ids': sorted(known), 'known_source_sha256': sorted(source_hashes),
            'verification_scope': provenance.get('verification_scope'), 'warnings': warnings}


def _session_delta(sessions, attack, field):
    differences = []
    for session in sessions:
        if session['role'] != 'test' or session['expected_attack'] != attack:
            continue
        left = session['models']['baseline']['binary_attack'][field]['estimate']
        right = session['models']['candidate']['binary_attack'][field]['estimate']
        if left is not None and right is not None:
            differences.append(right - left)
    if not differences:
        return {'candidate_minus_baseline': None, 'session_count': 0, 'bootstrap_95': None}
    interval = None
    if len(differences) >= 2:
        generator = random.Random(20261019)
        samples = sorted(sum(generator.choices(differences, k=len(differences))) / len(differences)
                         for _ in range(2000))
        interval = [samples[49], samples[1949]]
    return {'candidate_minus_baseline': sum(differences) / len(differences),
            'session_count': len(differences), 'bootstrap_95': interval,
            'method': 'paired session-mean percentile bootstrap; 2000 resamples; seed 20261019',
            'limitation': 'Small/dependent sessions or identical session results can give misleadingly narrow intervals.'}


def acceptance_gate(sessions, aggregate, provenance, policy, synthetic):
    """Report a declared operating gate; never publish/replace a model."""
    insufficient, failures = [], []
    test = [session for session in sessions if session['role'] == 'test']
    if synthetic or any(s['synthetic'] for s in test):
        insufficient.append('Synthetic fixtures test software behavior, not model quality')
    if not test:
        insufficient.append('No untouched test sessions')
    if any(s['evidence']['independent'] is not True for s in test):
        insufficient.append('Every test session needs independent evidence declared by the operator')
    if any(not provenance[name]['independent_source_isolation_verified'] for name in ('baseline', 'candidate')):
        insufficient.append('Training/calibration/internal-test isolation is not fully verified for both bundles')
    for attack, prefix in ((False, 'benign'), (True, 'attack')):
        subset = [s for s in test if s['expected_attack'] == attack]
        if len(subset) < policy['min_' + prefix + '_sessions']:
            insufficient.append('Too few independent ' + prefix + ' test sessions')
        if len({s['scenario'] for s in subset}) < policy['min_' + prefix + '_scenarios']:
            insufficient.append('Too few distinct ' + prefix + ' test scenarios')
        for session in subset:
            if session['models']['candidate']['counts']['scored'] < policy['min_scored_per_session']:
                insufficient.append('Too few scored observations in session ' + session['id'])
    candidate = aggregate['test']['candidate']
    baseline = aggregate['test']['baseline']
    c_binary, b_binary = candidate['binary_attack'], baseline['binary_attack']
    fpr = c_binary['benign_false_positive_rate_scored']
    recall = c_binary['effective_recall_including_unknown']
    if fpr['total'] < policy['min_benign_samples']:
        insufficient.append('Too few scored benign test observations')
    if candidate['counts']['tp'] + candidate['counts']['fn'] < policy['min_attack_samples']:
        insufficient.append('Too few scored attack test observations')
    if fpr['upper'] is None or fpr['upper'] > policy['max_benign_fpr']:
        failures.append('Candidate benign FPR Wilson upper bound exceeds the declared limit')
    if recall['lower'] is None or recall['lower'] < policy['min_attack_recall']:
        failures.append('Candidate effective attack recall Wilson lower bound is below the declared minimum')
    coverage = candidate['coverage']['estimate']
    if coverage is None or coverage < policy['min_coverage']:
        failures.append('Candidate aggregate test coverage is below the declared minimum')
    for session in test:
        metrics = session['models']['candidate']
        if metrics['coverage']['estimate'] is None or metrics['coverage']['estimate'] < policy['min_coverage']:
            failures.append('Insufficient coverage in session ' + session['id'])
        if session['expected_attack']:
            value = metrics['binary_attack']['effective_recall_including_unknown']['estimate']
            if value is None or value < policy['min_attack_session_recall']:
                failures.append('Attack-session effective recall too low: ' + session['id'])
        else:
            value = metrics['binary_attack']['benign_false_positive_rate_scored']['estimate']
            if value is None or value > policy['max_benign_session_fpr']:
                failures.append('Benign-session FPR too high: ' + session['id'])
    base_fpr = b_binary['benign_false_positive_rate_scored']['estimate']
    base_recall = b_binary['effective_recall_including_unknown']['estimate']
    if fpr['estimate'] is not None and base_fpr is not None and fpr['estimate'] - base_fpr > policy['max_fpr_increase'] + 1e-12:
        failures.append('Candidate FPR regression exceeds the declared paired limit')
    if recall['estimate'] is not None and base_recall is not None and base_recall - recall['estimate'] > policy['max_recall_drop'] + 1e-12:
        failures.append('Candidate effective recall regression exceeds the declared paired limit')
    status = 'insufficient_evidence' if insufficient else 'fail' if failures else 'pass'
    return {'status': status, 'policy': policy, 'insufficient_evidence': sorted(set(insufficient)),
            'failed_checks': sorted(set(failures)), 'automatic_model_replacement': False,
            'numerical_operating_criteria': {
                'status': 'fail' if failures else 'pass', 'failed_checks': sorted(set(failures)),
                'meaning': 'Numerical checks only. A numerical pass with insufficient evidence is not an acceptance or quality claim.'},
            'evidence_requirements': {
                'status': 'insufficient' if insufficient else 'sufficient_declared_evidence',
                'unresolved': sorted(set(insufficient))},
            'quality_established_for_declared_manifest': status == 'pass',
            'production_ready': False,
            'meaning': 'A pass supports review on these declared sessions and operating limits only; it is not a deployment or general accuracy guarantee.'}


def run(manifest_path, baseline_path, candidate_path, output, device='cpu'):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Output already exists; choose a new report path')
    manifest, sessions, policy, manifest_hash = load_manifest(manifest_path)
    # Keep pure metric/manifest validation usable without importing PyTorch.
    from soc_ai.flow import normalize
    from soc_ai.predict import Predictor

    predictors, bundle_info, isolation, bundle_hashes = {}, {}, {}, {}
    for name, directory in (('baseline', baseline_path), ('candidate', candidate_path)):
        directory = Path(directory).resolve()
        model = Predictor(directory, device)
        golden_error = model.verify()
        if not math.isfinite(golden_error):
            raise ValueError(name + ': nonfinite golden verification result')
        predictors[name] = model
        isolation[name] = check_training_overlap(model.metadata, sessions, name)
        bundle_hashes[name] = {filename: sha256(directory / filename) for filename in
                              ('model.json', 'model-weights.npz', 'preprocessor.json', 'features.json',
                               'golden.json', 'golden-predictions.json')}
        bundle_info[name] = {'directory': str(directory), 'golden_max_probability_difference': golden_error,
                             'sha256': bundle_hashes[name],
                             'frozen_attack_score_threshold': model.metadata['attack_score_threshold'],
                             'active_classes': model.metadata['active_classes'],
                             'prepared_data_sha256': model.metadata.get('prepared_data_sha256'),
                             'prepared_report_sha256': model.metadata.get('prepared_report_sha256')}

    raw_aggregate = {role: {name: _new_metrics() for name in predictors} for role in ('validation', 'test')}
    data_aggregate = {role: Counter() for role in ('validation', 'test')}
    seen, session_reports = {}, []
    for session in sessions:
        stats, errors = Counter(), []
        model_metrics = {name: _new_metrics() for name in predictors}
        batch = []

        def flush():
            if not batch:
                return
            for name, predictor in predictors.items():
                predictions = predictor.predict(batch)
                if len(predictions) != len(batch):
                    raise ValueError(name + ': prediction count mismatch')
                for prediction in predictions:
                    _add_prediction(model_metrics[name], prediction, session)
            batch.clear()

        def error_example(line, reason):
            if len(errors) < 10:
                errors.append({'line': line, 'reason': reason})

        # Iterate in binary mode to handle malformed UTF-8 per record, without losing
        # the rest of the session or ever silently classifying damaged input benign.
        with session['_path'].open('rb') as stream:
            for number, raw in enumerate(stream, 1):
                if not raw.strip():
                    stats['blank_lines'] += 1
                    continue
                stats['input_records'] += 1
                stats['flow_candidates'] += 1
                if len(raw) > _MAX_LINE_BYTES:
                    stats['invalid_records'] += 1
                    error_example(number, 'record_exceeds_4_MiB_limit')
                    continue
                try:
                    event = _json(raw.decode('utf-8-sig' if number == 1 else 'utf-8'))
                except (ValueError, UnicodeError):
                    stats['invalid_records'] += 1
                    error_example(number, 'invalid_json_or_encoding')
                    continue
                if not isinstance(event, dict):
                    stats['invalid_records'] += 1
                    error_example(number, 'record_is_not_an_object')
                    continue
                from data_markers import known_synthetic
                if known_synthetic(event):
                    stats['explicit_synthetic_records'] += 1
                # Preserve source identity even if a manifest gives the capture
                # a new display name. Wrapper IDs are never used as truth.
                for field in ('session_id', 'capture_session_id'):
                    source_id = event.get(field)
                    if isinstance(source_id, str):
                        for name in predictors:
                            if source_id in isolation[name]['known_session_ids']:
                                raise ValueError(name + ': input record reveals a reused train-time session in ' + session['id'])
                if event.get('schema_version') == 'soc-lab-labeled-flow/0.1' and event.get('role') == 'train':
                    raise ValueError('Training-labelled records cannot serve as independent benchmark evidence: ' + session['id'])
                if event.get('schema_version') == 'soc-lab-labeled-flow/0.1':
                    event = event.get('flow')
                    if not isinstance(event, dict):
                        stats['missing_required_fields'] += 1
                        error_example(number, 'missing_wrapped_flow')
                        continue
                if event.get('event_type') is not None and event.get('event_type') != 'flow':
                    stats['ignored_non_flow_records'] += 1
                    stats['flow_candidates'] -= 1
                    continue
                try:
                    flow = normalize(event)
                except KeyError:
                    stats['missing_required_fields'] += 1
                    error_example(number, 'missing_required_flow_field')
                    continue
                except (ValueError, TypeError, AttributeError, OverflowError):
                    stats['invalid_records'] += 1
                    error_example(number, 'invalid_or_unsupported_flow')
                    continue
                key = observation_key(flow)
                signature = {field: flow[field] for field in
                             ('protocol', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
                              'start_time', 'end_time', 'pkts_toserver', 'pkts_toclient',
                              'bytes_toserver', 'bytes_toclient', 'app_protocol',
                              'flow_state', 'flow_reason')}
                signature = hashlib.sha256(json.dumps(signature, sort_keys=True,
                                                       separators=(',', ':')).encode()).hexdigest()
                if key in seen:
                    previous, previous_signature = seen[key]
                    if previous != session['id']:
                        raise ValueError('Duplicate completed connection across sessions/splits: ' + previous + ' and ' + session['id'])
                    if signature != previous_signature:
                        raise ValueError('Conflicting observations of one completed connection in session ' + session['id'])
                    stats['duplicate_observations_removed'] += 1
                    continue
                seen[key] = (session['id'], signature)
                batch.append(flow)
                if len(batch) >= 1024:
                    flush()
        flush()
        if sha256(session['_path']) != session['sha256']:
            raise ValueError('Input changed during evaluation: ' + session['id'])
        unique_candidates = stats['flow_candidates'] - stats['duplicate_observations_removed']
        stats['attack_candidates'] = unique_candidates if session['expected_attack'] else 0
        role = session['role']
        data_aggregate[role].update(stats)
        for name in predictors:
            _merge_metrics(raw_aggregate[role][name], model_metrics[name])
        report = {key: value for key, value in session.items() if key != '_path'}
        if stats['explicit_synthetic_records']:
            report['synthetic'] = True
        report.update(data_counts=dict(stats), invalid_examples=errors,
                      models={name: _final_metrics(model_metrics[name], stats) for name in predictors})
        session_reports.append(report)
    if sha256(Path(manifest_path).resolve()) != manifest_hash:
        raise ValueError('Manifest changed during evaluation')
    for name, predictor in predictors.items():
        if any(sha256(predictor.directory / filename) != value for filename, value in bundle_hashes[name].items()):
            raise ValueError(name + ': model bundle changed during evaluation')
    aggregate = {role: {name: _final_metrics(raw_aggregate[role][name], data_aggregate[role])
                        for name in predictors} for role in ('validation', 'test')}
    gate = acceptance_gate(session_reports, aggregate, isolation, policy, manifest['synthetic'])
    report = {
        'schema_version': REPORT_SCHEMA, 'complete': True,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'manifest': {'path': str(Path(manifest_path).resolve()), 'sha256': manifest_hash,
                     'synthetic': manifest['synthetic']},
        'models': bundle_info, 'training_isolation': isolation,
        'sessions': session_reports, 'aggregate': aggregate,
        'data_counts_by_role': {role: dict(value) for role, value in data_aggregate.items()},
        'paired_comparison_test': {
            'benign_fpr_session_mean_delta': _session_delta(session_reports, False, 'benign_false_positive_rate_scored'),
            'effective_recall_session_mean_delta': _session_delta(session_reports, True, 'effective_recall_including_unknown'),
            'same_observations_and_truth_for_both_models': True,
            'statistical_superiority_automatically_claimed': False,
        },
        'acceptance_gate': gate,
        'limits': [
            'Truth/evidence and synthetic declarations are operator assertions; this tool cannot prove intent from flow statistics.',
            'Only completed-flow decisions are evaluated. Scan/brute-force/HTTP semantic or temporal detection needs separate rules/correlation evidence tests.',
            'Wilson intervals treat flows as independent; correlated flows can make them too optimistic. Inspect per-session metrics and paired session bootstrap.',
            'Session bootstrap with few/non-independent sessions is weak, and all-zero differences do not prove absence of risk.',
            'IDs/hash checks detect declared overlap/copies; renamed captures or unavailable public-dataset provenance can still conceal leakage.',
            'Validation is reported separately. Thresholds are frozen in each bundle; test outcomes never select or calibrate thresholds here.',
            'Argmax class accuracy is separate from binary threshold decisions. Softmax scores are uncalibrated.',
            'Missing/invalid/out-of-scope observations remain unknown; effective attack recall includes them as non-detections without relabeling them BENIGN.',
            'A report never replaces a bundle, changes a threshold, or proves general/production accuracy.',
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--device', choices=('cpu', 'cuda'), default='cpu')
    args = parser.parse_args(argv)
    try:
        report = run(args.manifest, args.baseline, args.candidate, args.output, args.device)
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, ImportError) as error:
        print('BENCHMARK_ERROR:', str(error), file=sys.stderr)
        return 2
    status = report['acceptance_gate']['status']
    print('BENCHMARK_REPORT:', args.output)
    print('ACCEPTANCE_GATE:', status)
    print('No model, training data, or threshold was changed.')
    return 0 if status == 'pass' else 3


if __name__ == '__main__':
    raise SystemExit(main())
