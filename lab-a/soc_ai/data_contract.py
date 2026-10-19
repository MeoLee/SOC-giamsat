"""Validate prepared caches before allocating tensors or updating model weights.

The 0.1 cache format stays compatible with older integer widths. Its arrays do
not contain connection/campaign IDs: validating this contract cannot establish
that public-dataset train/test groups are independent.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import zipfile

import numpy as np

from .common import CLASSES
from .fileio import open_shared_read, read_bytes
from .flow import FEATURE_HASH, FEATURE_NAMES, SPEC


ARRAY_KEYS = ('x', 'y', 'split', 'tier', 'day')
ROLES = ('train', 'validation', 'test')
MAX_UNCOMPRESSED_BYTES = 2 * 1024 ** 3
MAX_ROWS = 10_000_000


@dataclass
class PreparedData:
    report: dict
    arrays: dict
    data_sha256: str
    report_sha256: str
    validation: dict
    provenance: dict


def _integer(value, name, minimum=0, maximum=None):
    if (isinstance(value, bool) or not isinstance(value, int) or value < minimum
            or maximum is not None and value > maximum):
        raise ValueError(name + ' must be an integer in the supported range')
    return value


def _digest(value, name):
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(name + ' must be a lowercase SHA256 digest')
    return value


def _names(value, name):
    if (not isinstance(value, list) or not value
            or any(not isinstance(v, str) or not v.strip() for v in value)
            or len(set(value)) != len(value)):
        raise ValueError(name + ' must contain unique nonempty names')
    return value


def _stream_hash(stream):
    stream.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def _inspect_npz(stream, max_bytes, max_rows):
    """Check NPY headers and ZIP sizes before numpy materializes large arrays."""
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        expected = {name + '.npy' for name in ARRAY_KEYS}
        if len(members) != len(expected) or {m.filename for m in members} != expected:
            raise ValueError('Prepared NPZ must contain exactly x, y, split, tier and day once each')
        if sum(m.file_size for m in members) > max_bytes:
            raise ValueError('Prepared NPZ exceeds the uncompressed size limit')
        descriptors = {}
        for member in members:
            if member.flag_bits & 1:
                raise ValueError('Encrypted prepared NPZ is unsupported')
            with archive.open(member) as source:
                version = np.lib.format.read_magic(source)
                if version == (1, 0):
                    shape, _, dtype = np.lib.format.read_array_header_1_0(source)
                elif version == (2, 0):
                    shape, _, dtype = np.lib.format.read_array_header_2_0(source)
                else:
                    raise ValueError('Unsupported prepared NPY header version')
                if dtype.hasobject:
                    raise ValueError('Object arrays are forbidden in prepared data')
                name = member.filename[:-4]
                if any(not isinstance(v, int) or v < 0 for v in shape):
                    raise ValueError('Invalid prepared array shape: ' + name)
                elements = 1
                for dimension in shape:
                    elements *= dimension
                if elements * dtype.itemsize > max_bytes:
                    raise ValueError('Prepared array exceeds the uncompressed size limit: ' + name)
                if source.tell() + elements * dtype.itemsize != member.file_size:
                    raise ValueError('Prepared NPY payload size differs from its header: ' + name)
                descriptors[name] = (shape, dtype)
        shape, dtype = descriptors['x']
        if len(shape) != 2 or shape[1] != len(FEATURE_NAMES) or not 0 < shape[0] <= max_rows:
            raise ValueError('Prepared x must have shape (1..max_rows, 24)')
        if dtype.kind != 'f' or dtype.itemsize != 4:
            raise ValueError('Prepared x dtype must be float32')
        for name in ARRAY_KEYS[1:]:
            other_shape, other_dtype = descriptors[name]
            if other_shape != (shape[0],):
                raise ValueError('Prepared ' + name + ' must be one-dimensional with one value per row')
            if other_dtype.kind not in 'iu':
                raise ValueError('Prepared ' + name + ' dtype must be integer, not boolean/float')
    stream.seek(0)


def _session_provenance(report, arrays, data_hash, report_hash):
    days, splits = arrays['day'], arrays['split']
    day_names = report['day_names']
    local_days = {}
    for code, name in enumerate(day_names):
        if not name.startswith('LAB:'):
            continue
        parts = name.split(':', 2)
        if len(parts) != 3 or parts[1] not in ROLES or not parts[2]:
            raise ValueError('Local day name must declare LAB:train/validation/test:session')
        mask = days == code
        if np.any(splits[mask] != ROLES.index(parts[1])):
            raise ValueError('Local session leaks across its declared split role: ' + name)
        local_days[name] = (parts[1], int(mask.sum()))
    inputs = report.get('local_inputs', [])
    if not isinstance(inputs, list):
        raise ValueError('local_inputs must be a list')
    seen, captures, covered, sessions = set(), set(), set(), {role: [] for role in ROLES}
    for entry in inputs:
        if not isinstance(entry, dict):
            raise ValueError('Invalid local input provenance')
        session, role = entry.get('session_id'), entry.get('role')
        if not isinstance(session, str) or not session.strip() or role not in ROLES:
            raise ValueError('Invalid local session identity/role')
        if session in seen:
            raise ValueError('Repeated local session in prepared provenance')
        seen.add(session)
        capture = entry.get('capture_session_id', session)
        if not isinstance(capture, str) or not capture.strip() or capture in captures:
            raise ValueError('Repeated/invalid physical capture in prepared provenance')
        captures.add(capture)
        _integer(entry.get('records'), 'Local session records', minimum=1)
        _digest(entry.get('data_sha256'), 'Local data_sha256')
        if 'report_sha256' not in entry and 'manifest_sha256' not in entry:
            raise ValueError('Local input requires a report or manifest SHA256 digest')
        for field in ('report_sha256', 'manifest_sha256'):
            if field in entry:
                _digest(entry[field], 'Local ' + field)
        candidates = {'LAB:' + role + ':' + session, 'LAB:' + role + ':' + session[-12:]}
        if 'day_code' in entry:
            code = _integer(entry['day_code'], 'Local day_code', maximum=len(day_names) - 1)
            name = day_names[code]
            if name not in candidates:
                raise ValueError('Local day_code does not identify its declared session')
        else:
            matches = candidates.intersection(local_days)
            if len(matches) != 1:
                raise ValueError('Local session identity differs from prepared day names')
            name = matches.pop()
        if name in covered or local_days.get(name) != (role, entry['records']):
            raise ValueError('Local session count/identity differs from prepared day arrays')
        covered.add(name)
        sessions[role].append(session)
    if inputs and (covered != set(local_days) or any(not sessions[role] for role in ROLES)):
        raise ValueError('Local provenance must cover separate train, validation and test sessions')
    notes = [
        'Cache integrity and declared session assignment do not independently verify capture ground truth.',
        'Feature arrays lack public-dataset connection/campaign IDs; their independence is not established.',
    ]
    if local_days and not inputs:
        notes.append('Legacy cache has local day roles but no full session provenance; session disjointness cannot be proved.')
    elif not inputs:
        notes.append('Prepared report contains no full local session provenance.')
    source_provenance = report.get('provenance', {})
    if not isinstance(source_provenance, dict):
        raise ValueError('Prepared source provenance must be an object')
    covers_all = (bool(inputs) and sum(rows for _, rows in local_days.values()) == len(days)
                  and source_provenance.get('covers_all_training_sources') is True)
    if 'all_session_ids' in source_provenance:
        declared_ids = source_provenance['all_session_ids']
        if (not isinstance(declared_ids, list) or any(not isinstance(v, str) for v in declared_ids)
                or len(set(declared_ids)) != len(declared_ids) or set(declared_ids) != seen):
            raise ValueError('Prepared source provenance session IDs differ from local inputs')
    if 'capture_session_ids' in source_provenance:
        declared_captures = source_provenance['capture_session_ids']
        if (not isinstance(declared_captures, list) or any(not isinstance(v, str) for v in declared_captures)
                or len(set(declared_captures)) != len(declared_captures) or set(declared_captures) != captures):
            raise ValueError('Prepared physical capture IDs differ from local inputs')
    synthetic = report.get('synthetic_fixture', False)
    if not isinstance(synthetic, bool):
        raise ValueError('synthetic_fixture must be boolean')
    provenance = {
        'version': 'soc-training-provenance/0.1',
        'verified': bool(inputs),
        'verification_scope': 'prepared_cache_integrity_and_declared_whole_session_roles',
        'session_ids': sessions['train'], 'validation_session_ids': sessions['validation'],
        'test_session_ids': sessions['test'], 'all_session_ids': sorted(seen),
        'capture_session_ids': sorted(captures),
        'local_inputs': inputs, 'prepared_data_sha256': data_hash,
        'prepared_report_sha256': report_hash, 'raw_sources_rechecked': False,
        'covers_all_training_sources': covers_all, 'synthetic_fixture': synthetic,
        'independence_verified': False, 'source_provenance': source_provenance,
        'split_policy': report['split_policy'], 'notes': notes,
    }
    for field in ('base_data_sha256', 'base_report_sha256', 'cohort_sha256', 'cohort_report_sha256'):
        if field in report:
            provenance[field] = _digest(report[field], field)
    return provenance


def load_prepared(directory, *, max_uncompressed_bytes=MAX_UNCOMPRESSED_BYTES, max_rows=MAX_ROWS):
    directory = Path(directory)
    _integer(max_uncompressed_bytes, 'Uncompressed size limit', minimum=1)
    _integer(max_rows, 'Row limit', minimum=1)
    report_bytes = read_bytes(directory / 'report.json')
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    report = json.loads(report_bytes.decode('utf-8-sig'))
    if not isinstance(report, dict) or report.get('version') != 'soc-prepared/0.1' or report.get('complete') is not True:
        raise ValueError('Prepared data incomplete/wrong version')
    if report.get('feature_hash') != FEATURE_HASH or report.get('classes') != CLASSES:
        raise ValueError('Prepared feature/class schema mismatch')
    _integer(report.get('seed'), 'Prepared seed', maximum=2 ** 32 - 1)
    day_names = _names(report.get('day_names'), 'Prepared day_names')
    tier_names = _names(report.get('tier_names', ['strict', 'near_duration', 'controlled_lab']), 'Prepared tier_names')
    if not isinstance(report.get('split_policy'), str) or not report['split_policy'].strip():
        raise ValueError('Prepared split_policy is required')
    if not isinstance(report.get('warnings'), list) or any(not isinstance(w, str) for w in report['warnings']):
        raise ValueError('Prepared warnings must be a list of strings')
    expected_hash = _digest(report.get('data_sha256'), 'Prepared data_sha256')
    features_path = directory / 'features.json'
    if features_path.exists() and json.loads(read_bytes(features_path).decode('utf-8-sig')) != SPEC:
        raise ValueError('Prepared feature definition mismatch')
    try:
        with open_shared_read(directory / 'data.npz') as source:
            data_hash = _stream_hash(source)
            if data_hash != expected_hash:
                raise ValueError('Prepared data hash mismatch')
            _inspect_npz(source, max_uncompressed_bytes, max_rows)
            with np.load(source, allow_pickle=False) as cache:
                arrays = {name: cache[name].copy() for name in ARRAY_KEYS}
            if _stream_hash(source) != data_hash:
                raise ValueError('Prepared data changed while loading')
    except (zipfile.BadZipFile, EOFError) as exc:
        raise ValueError('Invalid prepared NPZ archive') from exc
    if not np.isfinite(arrays['x']).all():
        raise ValueError('Nonfinite input')
    for name, stop in (('y', len(CLASSES)), ('split', len(ROLES)), ('tier', len(tier_names)), ('day', len(day_names))):
        values = arrays[name]
        if np.any(values < 0) or np.any(values >= stop):
            raise ValueError('Prepared ' + name + ' codes are outside the declared range')
    counts = report.get('counts')
    if counts is not None:
        if not isinstance(counts, dict) or set(counts) != set(ROLES):
            raise ValueError('Prepared counts must cover train, validation and test')
        for code, role in enumerate(ROLES):
            selected = arrays['split'] == code
            declared = counts[role]
            if not isinstance(declared, dict) or _integer(declared.get('rows'), role + ' rows') != int(selected.sum()):
                raise ValueError('Prepared count/report mismatch: ' + role)
            classes = declared.get('classes')
            if not isinstance(classes, dict) or set(classes) != set(CLASSES):
                raise ValueError('Prepared class counts incomplete: ' + role)
            for label, name in enumerate(CLASSES):
                if _integer(classes[name], role + ' ' + name + ' count') != int(np.sum(arrays['y'][selected] == label)):
                    raise ValueError('Prepared class count/report mismatch: ' + role + ':' + name)
    if any(not np.any(arrays['split'] == code) for code in range(len(ROLES))):
        raise ValueError('Empty split')
    # Native-endian contiguous float32 preserves the fixed feature contract for torch.
    arrays['x'] = np.ascontiguousarray(arrays['x'], dtype=np.float32)
    original_y_dtype = str(arrays['y'].dtype)
    arrays['y'] = np.ascontiguousarray(arrays['y'], dtype=np.int64)
    validation = {
        'version': 'soc-prepared-contract/0.1', 'feature_hash': FEATURE_HASH,
        'rows': len(arrays['y']), 'feature_count': len(FEATURE_NAMES),
        'array_dtypes': {key: str(value.dtype) for key, value in arrays.items()},
        'original_label_dtype': original_y_dtype,
        'array_shapes': {key: list(value.shape) for key, value in arrays.items()},
        'declared_counts_checked': counts is not None,
        'feature_definition_checked': features_path.exists(),
        'uncompressed_size_limit': max_uncompressed_bytes, 'row_limit': max_rows,
        'group_or_campaign_independence_verified': False,
    }
    return PreparedData(report, arrays, data_hash, report_hash, validation,
                        _session_provenance(report, arrays, data_hash, report_hash))
