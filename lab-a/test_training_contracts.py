"""Prepared-data integrity, epoch-selection and resume regression checks."""
import contextlib
from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

import numpy as np

from soc_ai.common import CLASSES, read_json, sha256, write_json
from soc_ai.data_contract import load_prepared
from soc_ai.flow import FEATURE_HASH, SPEC
from soc_ai.train import LEGACY_QUALITY_SELECTION, QUALITY_SELECTION, quality_selection


def fixture(directory):
    directory.mkdir()
    rng = np.random.default_rng(42)
    arrays = {'x': rng.normal(size=(18, 24)).astype(np.float32),
              'y': np.tile(np.asarray([0, 1, 0, 1, 0, 1], dtype=np.int64), 3),
              'split': np.repeat(np.arange(3, dtype=np.uint8), 6),
              'tier': np.zeros(18, dtype=np.uint8), 'day': np.zeros(18, dtype=np.uint8)}
    report = {'version': 'soc-prepared/0.1', 'complete': True,
              'feature_hash': FEATURE_HASH, 'classes': CLASSES, 'seed': 42,
              'day_names': ['BASE'], 'split_policy': 'synthetic contract fixture',
              'warnings': ['Synthetic arrays exercise storage validation, not detection accuracy.'],
              'synthetic_fixture': True}
    save_fixture(directory, arrays, report)
    return arrays, report


def save_fixture(directory, arrays, report):
    np.savez_compressed(directory / 'data.npz', **arrays)
    report['data_sha256'] = sha256(directory / 'data.npz')
    write_json(directory / 'report.json', report)


def add_local_provenance(arrays, report, *, legacy=False):
    report['day_names'] = []
    report['local_inputs'] = []
    for code, role in enumerate(('train', 'validation', 'test')):
        session = 'session-' + role + '-unique-12345678-' + str(code)
        report['day_names'].append('LAB:' + role + ':' + (session[-12:] if legacy else session))
        entry = {'role': role, 'session_id': session, 'records': 6,
                 'data_sha256': 'a' * 64,
                 'report_sha256' if legacy else 'manifest_sha256': 'b' * 64}
        if not legacy:
            entry['day_code'] = code
        report['local_inputs'].append(entry)
    arrays['day'] = arrays['split'].astype(np.uint32)
    report['provenance'] = {'covers_all_training_sources': True,
                            'all_session_ids': [e['session_id'] for e in report['local_inputs']],
                            'independence_verified': False}


class DataContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / 'prepared'
        self.arrays, self.report = fixture(self.directory)

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        save_fixture(self.directory, self.arrays, self.report)

    def test_legacy_integer_widths_are_loaded_without_loss(self):
        self.arrays['y'] = self.arrays['y'].astype(np.int16)
        for name in ('split', 'tier', 'day'):
            self.arrays[name] = self.arrays[name].astype(np.int64)
        self.save()
        data = load_prepared(self.directory)
        self.assertEqual(data.arrays['x'].shape, (18, 24))
        self.assertEqual(data.arrays['y'].dtype, np.int64)
        self.assertEqual(data.validation['original_label_dtype'], 'int16')
        self.assertFalse(data.provenance['verified'])
        self.assertTrue(data.provenance['synthetic_fixture'])

    def test_nonfinite_features_fail_before_training(self):
        self.arrays['x'][0, 2] = np.inf
        self.save()
        with self.assertRaisesRegex(ValueError, 'Nonfinite'):
            load_prepared(self.directory)

    def test_shape_and_dtype_errors_are_not_coerced(self):
        cases = [('feature width', 'x', np.zeros((18, 23), dtype=np.float32)),
                 ('feature float64', 'x', self.arrays['x'].astype(np.float64)),
                 ('matrix labels', 'y', self.arrays['y'].reshape(18, 1)),
                 ('float labels', 'y', self.arrays['y'].astype(np.float32)),
                 ('boolean split', 'split', np.zeros(18, dtype=bool)),
                 ('short day', 'day', np.zeros(17, dtype=np.int64))]
        original = deepcopy(self.arrays)
        for name, field, value in cases:
            with self.subTest(name=name):
                self.arrays = deepcopy(original)
                self.arrays[field] = value
                self.save()
                with self.assertRaises(ValueError):
                    load_prepared(self.directory)

    def test_invalid_label_split_tier_and_day_codes_are_rejected(self):
        for name, value in (('y', -1), ('y', 6), ('split', 3), ('tier', 3), ('day', 1)):
            with self.subTest(name=name, value=value):
                arrays = deepcopy(self.arrays)
                arrays[name] = arrays[name].astype(np.int64)
                arrays[name][0] = value
                save_fixture(self.directory, arrays, self.report)
                with self.assertRaisesRegex(ValueError, 'outside the declared range'):
                    load_prepared(self.directory)

    def test_hash_mismatch_is_never_repaired_automatically(self):
        with (self.directory / 'data.npz').open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            load_prepared(self.directory)

    def test_uncompressed_size_and_row_limits_apply_before_loading(self):
        with patch('soc_ai.data_contract.np.load') as allocate:
            with self.assertRaisesRegex(ValueError, 'size limit'):
                load_prepared(self.directory, max_uncompressed_bytes=100)
            with self.assertRaisesRegex(ValueError, 'max_rows'):
                load_prepared(self.directory, max_rows=17)
            allocate.assert_not_called()

    def test_changing_cache_during_load_is_rejected(self):
        with patch('soc_ai.data_contract._stream_hash', side_effect=[self.report['data_sha256'], '0' * 64]):
            with self.assertRaisesRegex(ValueError, 'changed while loading'):
                load_prepared(self.directory)

    def test_duplicate_archive_member_is_rejected(self):
        path = self.directory / 'data.npz'
        with warnings.catch_warnings(), zipfile.ZipFile(path, 'a') as archive:
            warnings.simplefilter('ignore', UserWarning)
            archive.writestr('y.npy', archive.read('y.npy'))
        self.report['data_sha256'] = sha256(path)
        write_json(self.directory / 'report.json', self.report)
        with self.assertRaisesRegex(ValueError, 'once each'):
            load_prepared(self.directory)

    def test_object_arrays_are_rejected_without_pickle(self):
        self.arrays['y'] = self.arrays['y'].astype(object)
        self.save()
        with self.assertRaisesRegex(ValueError, 'Object arrays'):
            load_prepared(self.directory)

    def test_feature_definition_is_checked_when_present(self):
        altered = deepcopy(SPEC)
        altered['names'][0] = 'wrong-feature'
        write_json(self.directory / 'features.json', altered)
        with self.assertRaisesRegex(ValueError, 'feature definition'):
            load_prepared(self.directory)

    def test_seed_day_names_and_schema_are_strict(self):
        for field, value in (('seed', True), ('seed', -1), ('day_names', ['BASE', 'BASE']),
                             ('feature_hash', '0' * 64), ('classes', list(reversed(CLASSES)))):
            with self.subTest(field=field, value=value):
                report = deepcopy(self.report)
                report[field] = value
                save_fixture(self.directory, self.arrays, report)
                with self.assertRaises(ValueError):
                    load_prepared(self.directory)

    def test_declared_row_and_class_counts_match_arrays(self):
        self.report['counts'] = {}
        for role in ('train', 'validation', 'test'):
            self.report['counts'][role] = {'rows': 6, 'classes': {name: 3 if i < 2 else 0 for i, name in enumerate(CLASSES)}}
        self.save()
        self.assertTrue(load_prepared(self.directory).validation['declared_counts_checked'])
        self.report['counts']['test']['classes']['BENIGN'] = 2
        self.save()
        with self.assertRaisesRegex(ValueError, 'class count/report mismatch'):
            load_prepared(self.directory)

    def test_complete_local_session_provenance_preserves_full_identities(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                add_local_provenance(self.arrays, self.report, legacy=legacy)
                self.save()
                provenance = load_prepared(self.directory).provenance
                self.assertTrue(provenance['verified'])
                self.assertTrue(provenance['covers_all_training_sources'])
                self.assertFalse(provenance['independence_verified'])
                self.assertEqual(provenance['session_ids'], [self.report['local_inputs'][0]['session_id']])
                self.assertEqual(len(provenance['all_session_ids']), 3)

    def test_local_session_cannot_cross_declared_roles(self):
        add_local_provenance(self.arrays, self.report)
        self.arrays['day'][6] = 0
        self.save()
        with self.assertRaisesRegex(ValueError, 'leaks across'):
            load_prepared(self.directory)

    def test_repeated_session_and_incorrect_counts_fail(self):
        for mutation in ('duplicate', 'count', 'day_code', 'missing_manifest', 'physical_capture'):
            with self.subTest(mutation=mutation):
                arrays, report = deepcopy(self.arrays), deepcopy(self.report)
                add_local_provenance(arrays, report)
                if mutation == 'duplicate':
                    report['local_inputs'][1]['session_id'] = report['local_inputs'][0]['session_id']
                elif mutation == 'count':
                    report['local_inputs'][0]['records'] = 7
                elif mutation == 'day_code':
                    report['local_inputs'][0]['day_code'] = 2
                elif mutation == 'physical_capture':
                    report['local_inputs'][0]['capture_session_id'] = 'same-physical-capture'
                    report['local_inputs'][1]['capture_session_id'] = 'same-physical-capture'
                else:
                    report['local_inputs'][0].pop('manifest_sha256')
                save_fixture(self.directory, arrays, report)
                with self.assertRaises(ValueError):
                    load_prepared(self.directory)

    def test_base_rows_prevent_claiming_complete_local_source_coverage(self):
        add_local_provenance(self.arrays, self.report)
        self.report['day_names'].append('BASE')
        additions = {'x': self.arrays['x'][:1], 'y': np.asarray([0], dtype=np.int64),
                     'split': np.asarray([0], dtype=np.uint8), 'tier': np.asarray([0], dtype=np.uint8),
                     'day': np.asarray([3], dtype=np.uint32)}
        self.arrays = {key: np.concatenate((value, additions[key])) for key, value in self.arrays.items()}
        self.save()
        self.assertFalse(load_prepared(self.directory).provenance['covers_all_training_sources'])

    def test_legacy_day_suffixes_do_not_claim_verified_identity(self):
        self.report['day_names'] = ['LAB:train:old', 'LAB:validation:old', 'LAB:test:old']
        self.arrays['day'] = self.arrays['split'].copy()
        self.save()
        provenance = load_prepared(self.directory).provenance
        self.assertFalse(provenance['verified'])
        self.assertFalse(provenance['covers_all_training_sources'])
        self.assertEqual(provenance['all_session_ids'], [])


class SelectionTests(unittest.TestCase):
    def test_absent_classes_do_not_depress_quality_present_class_score(self):
        y = np.asarray([0, 2, 0, 0])
        probs = np.zeros((4, 6), dtype=np.float32)
        probs[np.arange(4), y] = 1
        local = np.asarray([False, False, True, True])
        active = np.asarray([True, False, True, False, False, False])
        score, detail = quality_selection(y, probs, local, .5, active)
        self.assertEqual(score, 1.0)
        self.assertEqual(detail['components']['external_present_class_macro_f1'], 1.0)
        self.assertFalse(detail['test_used_for_selection'])
        self.assertEqual(detail['external_class_support']['DDoS'], 0)

    def test_one_missed_attack_type_cannot_hide_behind_dominant_attack(self):
        y = np.asarray([0] + [1] * 100 + [2] + [0] * 4)
        probs = np.zeros((len(y), 6), dtype=np.float32)
        probs[np.arange(len(y)), y] = 1
        probs[101] = [1, 0, 0, 0, 0, 0]
        local = np.zeros(len(y), dtype=bool)
        local[-4:] = True
        active = np.asarray([True, True, True, False, False, False])
        score, detail = quality_selection(y, probs, local, .5, active)
        self.assertEqual(score, 0.0)
        self.assertEqual(detail['components']['base_attack_class_minimum_recall'], 0.0)
        self.assertEqual(detail['components']['base_attack_class_macro_recall'], .5)

    def test_missing_active_validation_class_is_explicit(self):
        y = np.asarray([0, 1, 0, 0])
        probs = np.eye(6, dtype=np.float32)[y]
        active = np.asarray([True, True, True, False, False, False])
        with self.assertRaisesRegex(ValueError, 'SSH-Patator'):
            quality_selection(y, probs, np.asarray([False, False, True, True]), .5, active)

    def test_legacy_objective_retains_six_class_macro_for_checkpoint_resume(self):
        y = np.asarray([0, 2, 0, 0])
        probs = np.eye(6, dtype=np.float32)[y]
        score, detail = quality_selection(y, probs, np.asarray([False, False, True, True]), .5,
            np.asarray([True, False, True, False, False, False]), policy=LEGACY_QUALITY_SELECTION)
        self.assertAlmostEqual(score, .6)
        self.assertEqual(detail['policy'], LEGACY_QUALITY_SELECTION)


class ResumePreprocessorTests(unittest.TestCase):
    def test_zero_primary_score_still_tracks_validation_learning_progress(self):
        from soc_ai import charts
        from soc_ai.train import run
        from test_quality_training import prepared
        # A rare missed attack class can hold the harmonic objective at zero.
        # Other validation improvements must still reset patience in an exact tie.
        decisions = [(0.0, {'policy': QUALITY_SELECTION, 'components': {'minimum_attack_recall': 0.0},
                              'exact_tie_breaker': {'policy': 'mean validation components', 'value': value}})
                     for value in (.1, .2, .3)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared(root / 'prepared')
            with patch.object(charts, 'epoch'), patch.object(charts, 'final'), \
                    patch('soc_ai.train.quality_selection', side_effect=decisions), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run(root / 'prepared', root / 'run', epochs=3, batch_size=256,
                    device_name='cpu', skip_baseline=True, local_loss_fraction=.2, patience=1), 'completed')
            self.assertEqual(len(read_json(root / 'run/history.json')), 3)
            metadata = read_json(root / 'run/model.json')
            self.assertEqual(metadata['best_epoch'], 3)
            self.assertEqual(metadata['best_selection_score'], 0.0)
            self.assertFalse(metadata['production_ready'])

    def test_checkpoint_without_selection_version_keeps_legacy_quality_policy(self):
        from soc_ai import charts, checkpoint
        from soc_ai.train import run
        from test_quality_training import prepared
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared(root / 'prepared')
            with patch.object(charts, 'epoch'), patch.object(charts, 'final'), contextlib.redirect_stdout(io.StringIO()):
                run(root / 'prepared', root / 'run', epochs=1, batch_size=64, device_name='cpu',
                    skip_baseline=True, local_loss_fraction=.2, pause_after_batches=1)
                path = root / 'run/checkpoints/latest.pt'
                saved = checkpoint.load(path)
                saved['config'].pop('selection_policy')
                saved['metadata'].pop('selection_policy')
                saved['metadata']['software_version'] = '0.2.1-quality'
                checkpoint.save(path, saved)
                self.assertEqual(run(None, root / 'run', resume=True), 'completed')
            metadata = read_json(root / 'run/model.json')
            self.assertEqual(metadata['software_version'], '0.2.1-quality')
            self.assertEqual(metadata['selection_policy'], LEGACY_QUALITY_SELECTION)
            self.assertIn('external_six_class_macro_f1', metadata['best_validation_selection']['components'])

    def test_modified_preprocessor_is_rejected_on_resume(self):
        from soc_ai import charts
        from soc_ai.train import run
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root / 'prepared')
            with patch.object(charts, 'epoch'), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run(root / 'prepared', root / 'run', epochs=2, batch_size=2,
                    device_name='cpu', skip_baseline=True, pause_after_batches=1), 'paused')
                preprocessor = read_json(root / 'run/preprocessor.json')
                preprocessor['mean'][0] += 1
                write_json(root / 'run/preprocessor.json', preprocessor)
                with self.assertRaisesRegex(ValueError, 'Resume preprocessor mismatch'):
                    run(None, root / 'run', resume=True)


if __name__ == '__main__':
    unittest.main()
