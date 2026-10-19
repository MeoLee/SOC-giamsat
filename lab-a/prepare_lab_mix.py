"""Mix an unchanged original CICIDS feature cache with evidence-backed local sessions.

Keeps the existing normalizer, feature order and training/checkpoint interfaces.
Local split roles are assigned to whole sessions; all three roles are required.
"""
import argparse
import json
from pathlib import Path
import numpy as np

from import_lab_normal import REPORT, SCHEMA, identity
from soc_ai.common import CLASSES, read_json, sha256, write_json
from soc_ai.flow import FEATURE_HASH, SPEC, features, normalize

ROLES = ('train', 'validation', 'test')


def load_local(directories):
    records = []
    reports = []
    seen_sessions = set()
    seen_flows = set()
    for directory in directories:
        directory = Path(directory).resolve()
        report = read_json(directory / 'report.json')
        target = directory / 'labeled-flows.jsonl'
        if (report.get('version') != REPORT or report.get('complete') is not True or
                report.get('feature_hash') != FEATURE_HASH):
            raise ValueError('Invalid/incomplete local import: ' + str(directory))
        if report.get('role') not in ROLES or report.get('label') != 'BENIGN':
            raise ValueError('This release supports evidence-backed BENIGN imports only')
        session = report['session_id']
        if session in seen_sessions:
            raise ValueError('Repeated session; cannot assign a capture to multiple splits')
        seen_sessions.add(session)
        if sha256(target) != report['data_sha256']:
            raise ValueError('Local data hash mismatch')
        observed = 0
        with target.open(encoding='utf-8-sig') as source:
            for line in source:
                if not line.strip():
                    continue
                item = json.loads(line)
                if (item.get('schema_version') != SCHEMA or item.get('session_id') != session or
                        item.get('role') != report['role'] or item.get('label') != report['label']):
                    raise ValueError('Record/report mismatch in local data')
                flow = normalize(item['flow'])
                key = identity(flow)
                if item['record_id'] != 'lab-flow:' + key or flow['record_id'] != item['record_id']:
                    raise ValueError('Local flow identity mismatch')
                if key in seen_flows:
                    raise ValueError('Repeated local flow across inputs or split roles')
                seen_flows.add(key)
                records.append((item, features(flow)))
                observed += 1
        if observed != report['counts']['selected_records'] or observed == 0:
            raise ValueError('Local manifest count mismatch')
        reports.append({'directory': str(directory), 'role': report['role'],
                        'session_id': session, 'records': observed,
                        'report_sha256': sha256(directory / 'report.json'),
                        'data_sha256': report['data_sha256']})
    roles = {report['role'] for report in reports}
    if roles != set(ROLES):
        raise ValueError('Need separate local train, validation and test sessions; '
                         'do not split eight rows from one session into three roles')
    return records, reports


def run(base, local, output):
    base, output = Path(base).resolve(), Path(output).resolve()
    base_report = read_json(base / 'report.json')
    if (base_report.get('version') != 'soc-prepared/0.1' or
            base_report.get('complete') is not True or
            base_report.get('feature_hash') != FEATURE_HASH or
            base_report.get('classes') != CLASSES):
        raise ValueError('Base prepared cache is incompatible')
    if base_report.get('local_inputs'):
        raise ValueError('Use the original CICIDS prepared cache, not a previously mixed cache')
    if sha256(base / 'data.npz') != base_report['data_sha256']:
        raise ValueError('Base data hash mismatch')
    if read_json(base / 'features.json') != SPEC:
        raise ValueError('Base feature definition mismatch')
    local_records, local_reports = load_local(local)
    if output.exists():
        raise ValueError('Output exists; choose a new prepared directory')
    with np.load(base / 'data.npz', allow_pickle=False) as source:
        arrays = {key: source[key].copy() for key in ('x', 'y', 'split', 'tier', 'day')}
    n = len(arrays['y'])
    if arrays['x'].shape != (n, len(SPEC['names'])) or any(len(v) != n for v in arrays.values()):
        raise ValueError('Base array shapes differ')
    if (not np.isfinite(arrays['x']).all() or
            not np.isin(arrays['split'], [0, 1, 2]).all() or
            not np.isin(arrays['y'], range(len(CLASSES))).all()):
        raise ValueError('Invalid base feature/label/split values')
    names = list(base_report['day_names'])
    if not np.isin(arrays['day'], range(len(names))).all():
        raise ValueError('Base day codes differ from report')
    day_codes = {}
    for report in local_reports:
        day_codes[report['session_id']] = len(names)
        names.append('LAB:' + report['role'] + ':' + report['session_id'][-12:])
    arrays['x'] = np.concatenate((arrays['x'], np.stack([x for _, x in local_records])))
    arrays['y'] = np.concatenate((arrays['y'], np.zeros(len(local_records), dtype=np.int64)))
    arrays['split'] = np.concatenate((arrays['split'], np.asarray(
        [ROLES.index(item['role']) for item, _ in local_records], dtype=np.uint8)))
    # Local evidence is not a CICIDS strict/near-duration matching tier.
    arrays['tier'] = np.concatenate((arrays['tier'], np.full(len(local_records), 2, dtype=np.uint8)))
    arrays['day'] = np.concatenate((arrays['day'].astype(np.uint32), np.asarray(
        [day_codes[item['session_id']] for item, _ in local_records], dtype=np.uint32)))
    counts = {}
    for code, role in enumerate(ROLES):
        selected = arrays['split'] == code
        if not selected.any():
            raise ValueError('Empty split')
        base_rows = int(base_report['counts'][role]['rows'])
        if base_rows != int(np.sum(arrays['split'][:n] == code)):
            raise ValueError('Base count/report mismatch')
        counts[role] = {'rows': int(selected.sum()),
                        'base_connection_groups': base_report['counts'][role].get('groups'),
                        'local_sessions': sum(r['role'] == role for r in local_reports),
                        'classes': {label: int(np.sum(arrays['y'][selected] == i))
                                    for i, label in enumerate(CLASSES)}}
    output.mkdir(parents=True)
    report = {'version': 'soc-prepared/0.1', 'complete': False, 'experimental_labels': True,
              'production_ready': False, 'feature_hash': FEATURE_HASH, 'classes': CLASSES,
              'seed': base_report['seed'], 'day_names': names, 'tier_names': ['strict', 'near_duration', 'controlled_lab'],
              'counts': counts, 'base_prepared': str(base),
              'base_data_sha256': base_report['data_sha256'],
              'base_report_sha256': sha256(base / 'report.json'), 'local_inputs': local_reports,
              'split_policy': base_report['split_policy'] + '; local whole-session train/validation/test roles',
              'warnings': list(base_report['warnings']) + [
                  'Local BENIGN labels require controlled normal activity and source-specific evidence.',
                  'Local attack examples are not yet included; lab attack recall is not established.',
                  'Small local samples do not establish deployment quality.',
                  'Original CICIDS validation/test rows retain the original split limitations.']}
    write_json(output / 'report.json', report)
    np.savez_compressed(output / 'data.npz', **arrays)
    write_json(output / 'features.json', SPEC)
    golden = read_json(base / 'golden.json')
    for item, vector in local_records:
        if item['role'] == 'train' and len(golden) < 16:
            golden.append({'flow': item['flow'], 'features': vector.tolist(),
                           'provisional_label': 'BENIGN', 'source': 'controlled_lab'})
    write_json(output / 'golden.json', golden)
    report.update(complete=True, data_sha256=sha256(output / 'data.npz'))
    write_json(output / 'report.json', report)
    print('LAB_MIX_PREPARED:', output, flush=True)
    print(json.dumps(counts, indent=2), flush=True)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-prepared', type=Path, required=True)
    p.add_argument('--local', type=Path, nargs='+', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        run(a.base_prepared, a.local, a.output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.exit(1, f'ERROR: {exc}\n')


if __name__ == '__main__':
    main()
