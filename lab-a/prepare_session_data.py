"""Build MLP24 data from independently reviewed, whole lab sessions (no old cache required).

Labels must come from controlled client/server evidence. Index mode creates
unlabelled drafts only; predictions, context signals and rules are not labels.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

import numpy as np

from import_lab_normal import SCHEMA, identity
from data_markers import known_synthetic as synthetic_marker
from soc_ai.common import CLASSES, digest, read_json, sha256, write_json
from soc_ai.flow import FEATURE_HASH, SPEC, features, normalize, parse_time

ROLES = ('train', 'validation', 'test')
MANIFEST = 'soc-supervised-sessions/1.0'


def local_path(root, value):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError('Manifest paths must be relative to the manifest directory')
    result = (root / value).resolve()
    if not result.is_relative_to(root.resolve()):
        raise ValueError('Manifest path escapes its directory')
    return result


def checked_file(root, entry, path_key='path'):
    path = local_path(root, entry[path_key])
    expected = entry.get('sha256')
    if not isinstance(expected, str) or len(expected) != 64 or sha256(path) != expected:
        raise ValueError('Input hash mismatch: ' + str(path))
    return path


def rows(path):
    with path.open('rb') as stream:
        for number, raw in enumerate(stream, 1):
            if len(raw) > 16 * 1024**2:
                raise ValueError('Input line exceeds 16 MiB')
            if raw.strip():
                item = json.loads(raw)
                if not isinstance(item, dict):
                    raise ValueError('Expected JSON object at line ' + str(number))
                yield number, raw.rstrip(b'\r\n'), item


def in_scope(flow):
    return (flow['protocol'] in ('TCP', 'UDP') and flow['duration_seconds'] > 0
            and flow['pkts_toserver'] + flow['pkts_toclient'] > 1
            and flow['flow_reason'] != 'tcp_reuse')


def index(eve, output, session_id, role):
    """Create an unlabelled review draft, never BENIGN-by-default."""
    if role not in ROLES or not isinstance(session_id, str) or not session_id:
        raise ValueError('Session and role required')
    count = 0
    with Path(output).open('x', encoding='utf-8', newline='\n') as stream:
        for number, raw, event in rows(Path(eve)):
            if event.get('event_type') != 'flow':
                continue
            flow = normalize(event)
            flow['record_id'] = 'lab-flow:' + identity(flow)
            item = {'schema_version': SCHEMA, 'session_id': session_id, 'role': role,
                    'record_id': flow['record_id'], 'label': None,
                    'label_method': 'REVIEW_REQUIRED', 'evidence_refs': [],
                    'raw_ref': {'evidence_id': 'raw-eve', 'line': number,
                                'raw_sha256': hashlib.sha256(raw).hexdigest()},
                    'flow': flow, 'model_scope_eligible': in_scope(flow)}
            stream.write(json.dumps(item, ensure_ascii=False, allow_nan=False) + '\n')
            count += 1
    return {'draft_only': True, 'labels_assigned': 0, 'rows': count,
            'sha256': sha256(output), 'raw_eve_sha256': sha256(eve)}


def reviewed_records(root, session, synthetic):
    """Check label decisions against immutable raw rows and independent artifacts."""
    review = session.get('label_review', {})
    if (review.get('reviewed') is not True or review.get('independent') is not True
            or not isinstance(review.get('method'), str) or not review['method'].strip()):
        raise ValueError('Explicit independent label review is required')
    parse_time(session['captured_at'])
    path = checked_file(root, {'path': session['records'], 'sha256': session['sha256']})
    evidence = {}
    for entry in session.get('evidence_files', []):
        key = entry.get('id')
        if not isinstance(key, str) or not key or key in evidence:
            raise ValueError('Evidence IDs must be unique strings')
        if entry.get('kind') not in ('raw_eve', 'operator', 'auth', 'application', 'pcap'):
            raise ValueError('Unsupported evidence kind; predictions/rules are not label sources')
        evidence[key] = {**entry, '_path': checked_file(root, entry)}
    if not any(e['kind'] == 'operator' for e in evidence.values()):
        raise ValueError('Controlled operator evidence required')
    if not any(e['kind'] in ('auth', 'application', 'pcap') for e in evidence.values()):
        raise ValueError('Independent auth/application/PCAP evidence required')
    labels = list(rows(path))
    if not labels:
        raise ValueError('Empty labelled session')
    wanted = {}
    for _, _, item in labels:
        ref = item.get('raw_ref', {})
        eid, line = ref.get('evidence_id'), ref.get('line')
        if eid not in evidence or evidence[eid]['kind'] != 'raw_eve' or type(line) is not int or line < 1:
            raise ValueError('Each label needs a specific raw EVE line reference')
        wanted.setdefault(eid, set()).add(line)
    raw_rows = {}
    for eid, numbers in wanted.items():
        for number, raw, event in rows(evidence[eid]['_path']):
            if number in numbers:
                raw_rows[(eid, number)] = (hashlib.sha256(raw).hexdigest(), event)
    for _, _, item in labels:
        refs = item.get('evidence_refs')
        if not isinstance(refs, list) or any(ref not in evidence for ref in refs):
            raise ValueError('Each label needs valid independent evidence_refs')
        kinds = {evidence[ref]['kind'] for ref in refs}
        if 'operator' not in kinds or not kinds.intersection({'auth', 'application', 'pcap'}):
            raise ValueError('Each label must cite operator and independent source evidence')
        ref = item['raw_ref']; raw_hash, original = raw_rows.get((ref['evidence_id'], ref['line']), (None, None))
        if raw_hash != ref.get('raw_sha256') or original is None:
            raise ValueError('Raw reference missing or modified')
        original_flow, labelled_flow = normalize(original), normalize(item['flow'])
        if {k: v for k, v in original_flow.items() if k != 'record_id'} != {
                k: v for k, v in labelled_flow.items() if k != 'record_id'}:
            raise ValueError('Labelled flow differs from original raw observation')
        if item.get('label_method') in (None, '', 'REVIEW_REQUIRED'):
            raise ValueError('Unreviewed draft cannot become training data')
        yield item
    if sha256(path) != session['sha256'] or any(sha256(e['_path']) != e['sha256'] for e in evidence.values()):
        raise ValueError('Source changed during preparation')


def imported_records(root, session):
    """Reuse A's controlled SSH/HTTP BENIGN imports with their original evidence checks."""
    directory = local_path(root, session['import_directory'])
    report_path = directory / 'report.json'; report = read_json(report_path)
    if (report.get('version') != 'soc-lab-import/0.1' or report.get('complete') is not True
            or report.get('feature_hash') != FEATURE_HASH or report.get('label') != 'BENIGN'
            or report.get('session_id') != session['id'] or report.get('role') != session['role']):
        raise ValueError('Import report/session mismatch')
    if sha256(report_path) != session.get('report_sha256'):
        raise ValueError('Import report hash mismatch')
    inputs = report.get('inputs', {})
    if len(inputs) < 2 or not report.get('policy', {}).get('predictions_are_not_labels'):
        raise ValueError('Import lacks independent evidence provenance')
    for entry in inputs.values():
        path = Path(entry['path'])
        if not path.is_absolute():
            path = directory / path
        if sha256(path) != entry['sha256']:
            raise ValueError('Import source evidence changed')
    path = directory / 'labeled-flows.jsonl'
    if sha256(path) != report['data_sha256']:
        raise ValueError('Imported label data changed')
    observed = 0
    for _, _, item in rows(path):
        if item.get('label') != 'BENIGN' or not item.get('evidence'):
            raise ValueError('Controlled normal importer only supports evidenced BENIGN')
        observed += 1
        yield item
    if observed != report['counts']['selected_records']:
        raise ValueError('Import count mismatch')
    if sha256(report_path) != session['report_sha256'] or sha256(path) != report['data_sha256']:
        raise ValueError('Imported report/labels changed during preparation')
    for entry in inputs.values():
        evidence_path = Path(entry['path'])
        if not evidence_path.is_absolute():
            evidence_path = directory / evidence_path
        if sha256(evidence_path) != entry['sha256']:
            raise ValueError('Import source evidence changed during preparation')


def run(manifest, output, base_prepared=None, seed=42):
    manifest, output = Path(manifest).resolve(), Path(output).resolve()
    data = read_json(manifest); root = manifest.parent; manifest_hash = sha256(manifest)
    if data.get('schema_version') != MANIFEST or type(data.get('synthetic')) is not bool:
        raise ValueError('Requires soc-supervised-sessions/1.0 and explicit synthetic boolean')
    sessions = data.get('sessions')
    if not isinstance(sessions, list) or not sessions:
        raise ValueError('Nonempty sessions list required')
    if output.exists():
        raise ValueError('Output exists; choose a new prepared directory')
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError('Invalid seed')
    base = None
    known_synthetic = synthetic_marker(data)
    names = []; columns = {k: [] for k in ('x', 'y', 'split', 'tier', 'day')}
    if base_prepared:
        from soc_ai.data_contract import load_prepared
        base = load_prepared(base_prepared)
        known_synthetic = known_synthetic or synthetic_marker(base.report)
        if base.report.get('local_inputs'):
            raise ValueError('Use original base cache, not a previously mixed cache')
        names = list(base.report['day_names'])
    session_ids, captures, flow_keys, local_inputs = set(), set(), {}, []
    raw_source_roles = {}
    golden, stats = [], Counter()
    for session in sessions:
        if not isinstance(session, dict):
            raise ValueError('Session must be an object')
        known_synthetic = synthetic_marker(session) or known_synthetic
        sid, role = session.get('id'), session.get('role')
        if not isinstance(sid, str) or not sid or sid in session_ids or role not in ROLES:
            raise ValueError('Unique session ID and a train/validation/test role required')
        capture = session.get('capture_session_id')
        if not isinstance(capture, str) or not capture or capture in captures:
            raise ValueError('Same physical capture cannot be split across roles')
        session_ids.add(sid); captures.add(capture)
        report_metadata = None
        if 'import_directory' in session:
            report_metadata = read_json(local_path(root, session['import_directory']) / 'report.json')
            known_synthetic = synthetic_marker(report_metadata) or known_synthetic
            raw_sources = [entry for name, entry in report_metadata.get('inputs', {}).items()
                           if name == 'flows' or 'eve' in name.lower()]
            evidence_hashes = [entry.get('sha256') for entry in report_metadata.get('inputs', {}).values()]
            labelled_data_hash = report_metadata.get('data_sha256')
        else:
            raw_sources = [entry for entry in session.get('evidence_files', []) if entry.get('kind') == 'raw_eve']
            evidence_hashes = [entry.get('sha256') for entry in session.get('evidence_files', [])]
            labelled_data_hash = session.get('sha256')
        for source in raw_sources:
            known = raw_source_roles.get(source.get('sha256'))
            if known is not None and known != role:
                raise ValueError('Same raw capture source cannot be divided across split roles')
            raw_source_roles[source.get('sha256')] = role
        code = len(names); names.append('LAB:' + role + ':' + sid)
        record_stream = imported_records(root, session) if 'import_directory' in session else reviewed_records(root, session, data['synthetic'])
        selected = 0; fingerprints = set()
        for item in record_stream:
            known_synthetic = synthetic_marker(item) or synthetic_marker(item.get('flow', {})) or known_synthetic
            stats['input_labelled_records'] += 1
            if (item.get('schema_version') != SCHEMA or item.get('session_id') != sid
                    or item.get('role') != role or item.get('label') not in CLASSES):
                raise ValueError('Label/session/role/schema mismatch')
            flow = normalize(item['flow']); key = identity(flow)
            if item.get('record_id') != 'lab-flow:' + key or flow['record_id'] != item['record_id']:
                raise ValueError('Label record identity mismatch')
            previous = flow_keys.get(key)
            if previous is not None:
                raise ValueError('Repeated flow or conflicting label across sessions/splits: ' + key)
            flow_keys[key] = (sid, item['label'])
            if not in_scope(flow):
                stats['excluded_out_of_model_scope'] += 1
                continue
            vector = features(flow); fingerprints.add(vector.tobytes())
            columns['x'].append(vector); columns['y'].append(CLASSES.index(item['label']))
            columns['split'].append(ROLES.index(role)); columns['tier'].append(2); columns['day'].append(code)
            if role == 'train' and len(golden) < 12:
                golden.append({'flow': flow, 'features': vector.tolist(), 'source': 'controlled_lab'})
            selected += 1
        if selected == 0:
            raise ValueError('No model-scope records in session ' + sid + '; one-packet scans need the context detector')
        local_inputs.append({'session_id': sid, 'capture_session_id': capture, 'role': role,
                             'records': selected, 'day_code': code, 'manifest_sha256': manifest_hash,
                             'data_sha256': labelled_data_hash,
                             **({'report_sha256': session['report_sha256']} if report_metadata is not None else {}),
                             'raw_source_sha256': sorted({entry['sha256'] for entry in raw_sources}),
                             'evidence_sha256': sorted(set(evidence_hashes)),
                             'unique_feature_vectors': len(fingerprints)})
    if {entry['role'] for entry in local_inputs} != set(ROLES):
        raise ValueError('Separate whole train, validation and test sessions required')
    arrays = {'x': np.stack(columns['x']).astype(np.float32), 'y': np.asarray(columns['y'], dtype=np.int64),
              'split': np.asarray(columns['split'], dtype=np.uint8), 'tier': np.asarray(columns['tier'], dtype=np.uint8),
              'day': np.asarray(columns['day'], dtype=np.uint32)}
    if base:
        arrays = {key: np.concatenate((base.arrays[key], value)) for key, value in arrays.items()}
        golden = read_json(Path(base_prepared) / 'golden.json')[:12] + golden[:4]
    if not np.any((arrays['split'] == 0) & (arrays['y'] == 0)) or not np.any((arrays['split'] == 0) & (arrays['y'] != 0)):
        raise ValueError('Training requires independently evidenced BENIGN and at least one attack class')
    if not np.any((arrays['split'] == 1) & (arrays['y'] == 0)):
        raise ValueError('Validation needs BENIGN for threshold selection')
    if sha256(manifest) != manifest_hash:
        raise ValueError('Manifest changed during preparation')
    counts = {role: {'rows': int(np.sum(arrays['split'] == j)), 'classes': {
        label: int(np.sum((arrays['split'] == j) & (arrays['y'] == i))) for i, label in enumerate(CLASSES)}}
        for j, role in enumerate(ROLES)}
    output.mkdir(parents=True)
    report = {'version': 'soc-prepared/0.1', 'complete': False, 'experimental_labels': True,
              'production_ready': False,
              'synthetic_fixture': known_synthetic,
              'seed': seed,
              'feature_hash': FEATURE_HASH, 'classes': CLASSES, 'day_names': names,
              'tier_names': ['strict', 'near_duration', 'controlled_lab'], 'local_inputs': local_inputs,
              'counts': counts, 'source_manifest_sha256': manifest_hash, 'scope_counts': dict(stats),
              'split_policy': 'Explicit whole controlled sessions; no random flow split; independent final benchmark still required',
              'provenance': {'covers_all_training_sources': base is None, 'all_session_ids': sorted(session_ids),
                             'capture_session_ids': sorted(captures), 'independence_verified': False},
              'warnings': ['Labels depend on independent controlled evidence and human review, not model output.',
                           'Source hashes prove frozen artifacts, not truthful labels or independent campaigns.',
                           'Test split here is development evaluation; use new sessions for final benchmark.',
                           'Missing training classes are masked; local-only data does not reproduce CICIDS six-class training.']}
    if base:
        report.update(base_prepared=str(Path(base_prepared).resolve()), base_data_sha256=base.data_sha256,
                      base_report_sha256=base.report_sha256)
    write_json(output / 'report.json', report)
    np.savez_compressed(output / 'data.npz', **arrays)
    write_json(output / 'features.json', SPEC); write_json(output / 'golden.json', golden)
    report.update(complete=True, data_sha256=sha256(output / 'data.npz'))
    write_json(output / 'report.json', report)
    from soc_ai.data_contract import load_prepared
    try:
        load_prepared(output)
    except Exception:
        report['complete'] = False; write_json(output / 'report.json', report)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build'); build.add_argument('--manifest', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True); build.add_argument('--base-prepared', type=Path)
    build.add_argument('--seed', type=int, default=42)
    draft = sub.add_parser('index'); draft.add_argument('--eve', type=Path, required=True)
    draft.add_argument('--output', type=Path, required=True); draft.add_argument('--session', required=True)
    draft.add_argument('--role', choices=ROLES, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'index':
            result = index(args.eve, args.output, args.session, args.role)
        else:
            result = run(args.manifest, args.output, args.base_prepared, args.seed)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, 'ERROR: ' + str(exc) + '\n')


if __name__ == '__main__':
    sys.exit(main())
