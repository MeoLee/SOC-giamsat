"""Contract/metric checks plus a tiny deterministic bundle CLI round trip.

All records here are synthetic software fixtures, never accuracy evidence.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import evaluate_lab as benchmark


def flow(index=0):
    start = datetime(2026, 10, 19, tzinfo=timezone.utc) + timedelta(seconds=index * 10)
    return {'event_type': 'flow', 'timestamp': (start + timedelta(seconds=3)).isoformat(),
            'flow_id': str(1000 + index), 'src_ip': '192.0.2.10', 'dest_ip': '192.0.2.20',
            'src_port': 30000 + index, 'dest_port': 22, 'proto': 'TCP', 'app_proto': 'ssh',
            'flow': {'start': start.isoformat(), 'end': (start + timedelta(seconds=2)).isoformat(),
                     'state': 'closed', 'reason': 'timeout', 'pkts_toserver': 5,
                     'pkts_toclient': 4, 'bytes_toserver': 500, 'bytes_toclient': 800}}


def session(root, session_id='normal', attack=False, records=None, role='test'):
    path = root / (session_id + '.jsonl')
    data = ''.join(json.dumps(record) + '\n' for record in (records if records is not None else [flow()]))
    path.write_text(data, encoding='utf-8')
    return {'id': session_id, 'role': role, 'scenario': 'ssh-attack' if attack else 'normal-ssh',
            'flows': path.name, 'sha256': benchmark.sha256(path), 'expected_attack': attack,
            'expected_class': 'SSH-Patator' if attack else 'BENIGN',
            'evidence': {'independent': False, 'source': 'Synthetic test fixture only',
                         'collected_at': '2026-10-19T07:00:00+07:00'},
            'provenance': {'capture_session_id': 'capture-' + session_id}}


def manifest(root, sessions, **extra):
    path = root / 'benchmark.json'
    path.write_text(json.dumps({'schema_version': benchmark.SCHEMA, 'synthetic': True,
                                'sessions': sessions, **extra}), encoding='utf-8')
    return path


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.item = session(self.root)

    def test_valid_synthetic_manifest_is_explicit(self):
        path = manifest(self.root, [self.item])
        data, items, policy, digest = benchmark.load_manifest(path)
        self.assertTrue(data['synthetic'])
        self.assertTrue(items[0]['synthetic'])
        self.assertEqual(policy['min_benign_sessions'], 5)
        self.assertEqual(digest, benchmark.sha256(path))

    def test_root_synthetic_cannot_be_omitted(self):
        path = manifest(self.root, [self.item])
        data = json.loads(path.read_text())
        del data['synthetic']
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'synthetic'):
            benchmark.load_manifest(path)

    def test_synthetic_cannot_be_redeclared_real_by_session(self):
        self.item['synthetic'] = False
        with self.assertRaisesRegex(ValueError, 'cannot override'):
            benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_real_session_requires_capture_identity(self):
        del self.item['provenance']
        with self.assertRaisesRegex(ValueError, 'capture_session_id'):
            benchmark.load_manifest(manifest(self.root, [self.item], synthetic=False))

    def test_hash_mismatch_is_fatal(self):
        self.item['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_path_traversal_and_windows_drive_rejected(self):
        for path in ('../outside.jsonl', '/tmp/outside.jsonl', 'C:\\Lab\\flow.jsonl', '\\\\server\\share\\flow.jsonl'):
            with self.subTest(path=path):
                self.item['flows'] = path
                with self.assertRaisesRegex(ValueError, 'relative path'):
                    benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_missing_file_is_not_a_benign_session(self):
        self.item['flows'] = 'missing.jsonl'
        with self.assertRaisesRegex(ValueError, 'missing'):
            benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_duplicate_session_and_capture_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate session id'):
            benchmark.load_manifest(manifest(self.root, [self.item, self.item]))
        other = session(self.root, 'other', records=[flow(1)], role='validation')
        other['provenance'] = self.item['provenance']
        with self.assertRaisesRegex(ValueError, 'Capture session reused'):
            benchmark.load_manifest(manifest(self.root, [self.item, other]))

    def test_shared_alias_and_cross_field_identity_cannot_inflate_sessions(self):
        other = session(self.root, 'other', records=[flow(1)])
        self.item['provenance']['related_session_ids'] = ['physical-original']
        other['provenance']['related_session_ids'] = ['physical-original']
        with self.assertRaisesRegex(ValueError, 'Session identities overlap'):
            benchmark.load_manifest(manifest(self.root, [self.item, other]))
        del other['provenance']['related_session_ids']
        other['provenance']['capture_session_id'] = self.item['id']
        with self.assertRaisesRegex(ValueError, 'Session identities overlap'):
            benchmark.load_manifest(manifest(self.root, [self.item, other]))

    def test_truth_consistency_and_independent_boolean(self):
        self.item['expected_class'] = 'SSH-Patator'
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            benchmark.load_manifest(manifest(self.root, [self.item]))
        self.item['expected_class'] = 'BENIGN'
        self.item['evidence']['independent'] = 'true'
        with self.assertRaisesRegex(ValueError, 'explicit boolean'):
            benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_evidence_timestamp_requires_timezone(self):
        self.item['evidence']['collected_at'] = '2026-10-19T07:00:00'
        with self.assertRaisesRegex(ValueError, 'timezone'):
            benchmark.load_manifest(manifest(self.root, [self.item]))

    def test_unknown_gate_or_boolean_sample_count_is_rejected(self):
        for value in ({'max_fpr_typo': .01}, {'min_benign_samples': True}, {'min_coverage': float('nan')}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    benchmark.load_manifest(manifest(self.root, [self.item], gate=value))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            benchmark._json('{"synthetic": true, "synthetic": false}')


class MetricTests(unittest.TestCase):
    def test_zero_observations_are_unknown(self):
        result = benchmark.wilson(0, 0)
        self.assertIsNone(result['estimate'])
        self.assertIsNone(result['lower'])

    def test_no_false_positives_still_have_nonzero_upper_bound(self):
        interval = benchmark.wilson(0, 500)
        self.assertEqual(interval['estimate'], 0)
        self.assertGreater(interval['upper'], 0.007)
        self.assertLess(interval['upper'], 0.008)
        with self.assertRaises(ValueError):
            benchmark.wilson(6, 5)

    def test_argmax_and_threshold_decision_are_distinct(self):
        metrics = benchmark._new_metrics()
        benchmark._add_prediction(metrics, {
            'decision': 'possible_attack', 'predicted_label': 'BENIGN',
            'attack_score': .4, 'attack_score_threshold': .3},
            {'expected_attack': False, 'expected_class': 'BENIGN'})
        report = benchmark._final_metrics(metrics, {'flow_candidates': 1,
                                                   'duplicate_observations_removed': 0})
        self.assertEqual(report['counts']['fp'], 1)
        self.assertEqual(report['argmax_multiclass']['accuracy_scored_known_class']['estimate'], 1)

    def test_missing_invalid_out_of_scope_never_become_true_negative(self):
        metrics = benchmark._new_metrics()
        benchmark._add_prediction(metrics, {'decision': 'out_of_training_scope', 'reason': 'tcp_reuse'},
                                  {'expected_attack': True})
        report = benchmark._final_metrics(metrics, {'flow_candidates': 3,
                                                   'duplicate_observations_removed': 0,
                                                   'attack_candidates': 3})
        self.assertEqual(report['unknown'], 3)
        self.assertEqual(report['counts']['tn'], 0)
        self.assertEqual(report['counts']['fn'], 0)
        self.assertEqual(report['binary_attack']['effective_recall_including_unknown']['estimate'], 0)
        self.assertIsNone(report['binary_attack']['recall_scored']['estimate'])

    def test_model_decision_must_agree_with_frozen_threshold(self):
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            benchmark._add_prediction(benchmark._new_metrics(), {
                'decision': 'below_alert_threshold', 'predicted_label': 'BENIGN',
                'attack_score': .8, 'attack_score_threshold': .3}, {'expected_attack': False})

    def test_all_train_time_roles_block_test_reuse(self):
        item = {'id': 'fresh-name', 'provenance': {'capture_session_id': 'old-session'}}
        for role in ('session_ids', 'validation_session_ids', 'test_session_ids', 'all_session_ids', 'capture_session_ids'):
            with self.subTest(role=role):
                with self.assertRaisesRegex(ValueError, 'overlaps'):
                    benchmark.check_training_overlap({'training_provenance': {role: ['old-session']}}, [item], 'candidate')

    def test_partial_or_missing_training_provenance_is_unverified(self):
        for metadata in ({}, {'training_provenance': {'verified': True, 'session_ids': ['train-a'],
                                                    'covers_all_training_sources': False}}):
            self.assertFalse(benchmark.check_training_overlap(metadata, [], 'baseline')['independent_source_isolation_verified'])
        complete = {'training_provenance': {'verified': True, 'covers_all_training_sources': True,
                                           'all_session_ids': ['train-a'],
                                           'independence_verified': True, 'raw_sources_rechecked': True}}
        self.assertTrue(benchmark.check_training_overlap(complete, [], 'candidate')['independent_source_isolation_verified'])

    def test_declared_cache_isolation_does_not_prove_source_independence(self):
        metadata = {'training_provenance': {'verified': True, 'covers_all_training_sources': True,
                                           'all_session_ids': ['train-a'],
                                           'independence_verified': False, 'raw_sources_rechecked': False}}
        result = benchmark.check_training_overlap(metadata, [], 'candidate')
        self.assertTrue(result['verified_declared_identity_isolation'])
        self.assertFalse(result['independent_source_isolation_verified'])

    def test_nested_capture_ids_and_source_hashes_block_renamed_copies(self):
        metadata = {'training_provenance': {'local_inputs': [
            {'capture_session_id': 'raw-training-capture', 'data_sha256': 'a' * 64,
             'raw_source_sha256': ['b' * 64], 'evidence_sha256': ['c' * 64]}]}}
        for item in ({'id': 'fresh-name', 'provenance': {'capture_session_id': 'raw-training-capture'}},
                     {'id': 'fresh-name', 'sha256': 'a' * 64, 'provenance': {}},
                     {'id': 'fresh-name', 'sha256': '0' * 64, 'provenance': {'raw_eve_sha256': 'b' * 64}},
                     {'id': 'fresh-name', 'evidence': {'sha256': {'auth.log': 'c' * 64}}, 'provenance': {}}):
            with self.subTest(item=item):
                with self.assertRaisesRegex(ValueError, 'overlaps'):
                    benchmark.check_training_overlap(metadata, [item], 'candidate')


def _gate_inputs():
    raw = {name: benchmark._new_metrics() for name in ('baseline', 'candidate')}
    stats = {'flow_candidates': 10000, 'duplicate_observations_removed': 0, 'attack_candidates': 5000}
    for value in raw.values():
        value['counts'].update(scored=10000, tp=5000, tn=5000)
    aggregate = {'test': {name: benchmark._final_metrics(value, stats) for name, value in raw.items()}}
    sessions = []
    for attack in (False, True):
        for index in range(5):
            local = benchmark._new_metrics()
            local['counts'].update(scored=1000, tp=1000 if attack else 0, tn=0 if attack else 1000)
            metrics = benchmark._final_metrics(local, {'flow_candidates': 1000,
                                                       'duplicate_observations_removed': 0,
                                                       'attack_candidates': 1000 if attack else 0})
            sessions.append({'id': ('attack' if attack else 'benign') + str(index),
                             'role': 'test', 'expected_attack': attack, 'synthetic': False,
                             'scenario': ('attack' if attack else 'benign') + str(index % 2),
                             'evidence': {'independent': True},
                             'models': {'baseline': metrics, 'candidate': metrics}})
    provenance = {name: {'independent_source_isolation_verified': True} for name in raw}
    return sessions, aggregate, provenance


class AcceptanceTests(unittest.TestCase):
    def test_explicit_adequate_counts_pass_only_declared_gate(self):
        sessions, aggregate, provenance = _gate_inputs()
        gate = benchmark.acceptance_gate(sessions, aggregate, provenance, benchmark.DEFAULT_GATE, False)
        self.assertEqual(gate['status'], 'pass')
        self.assertFalse(gate['automatic_model_replacement'])
        self.assertFalse(gate['production_ready'])

    def test_synthetic_or_unverified_cannot_establish_quality(self):
        sessions, aggregate, provenance = _gate_inputs()
        gate = benchmark.acceptance_gate(sessions, aggregate, provenance, benchmark.DEFAULT_GATE, True)
        self.assertEqual(gate['status'], 'insufficient_evidence')
        self.assertEqual(gate['numerical_operating_criteria']['status'], 'pass')
        self.assertEqual(gate['evidence_requirements']['status'], 'insufficient')
        provenance['baseline']['independent_source_isolation_verified'] = False
        gate = benchmark.acceptance_gate(sessions, aggregate, provenance, benchmark.DEFAULT_GATE, False)
        self.assertEqual(gate['status'], 'insufficient_evidence')

    def test_single_session_cannot_establish_quality_with_many_flows(self):
        sessions, aggregate, provenance = _gate_inputs()
        gate = benchmark.acceptance_gate(sessions[:1], aggregate, provenance, benchmark.DEFAULT_GATE, False)
        self.assertEqual(gate['status'], 'insufficient_evidence')

    def test_validation_metrics_never_enter_acceptance_gate(self):
        sessions, aggregate, provenance = _gate_inputs()
        validation = deepcopy(sessions[0])
        validation.update(id='validation-only', role='validation')
        validation['models']['candidate']['coverage']['estimate'] = 0
        gate = benchmark.acceptance_gate(sessions + [validation], aggregate, provenance, benchmark.DEFAULT_GATE, False)
        self.assertEqual(gate['status'], 'pass')

    def test_paired_session_delta_has_counts_and_limits(self):
        sessions, _, _ = _gate_inputs()
        delta = benchmark._session_delta(sessions, False, 'benign_false_positive_rate_scored')
        self.assertEqual(delta['session_count'], 5)
        self.assertEqual(delta['candidate_minus_baseline'], 0)
        self.assertEqual(delta['bootstrap_95'], [0, 0])
        self.assertIn('misleadingly narrow', delta['limitation'])


def _bundle(root, name, alert=False):
    import numpy as np
    import torch
    from soc_ai.common import write_json
    from soc_ai.flow import FEATURE_HASH, FEATURE_NAMES, SPEC, features, normalize
    from soc_ai.model import FlowMLP, save_weights
    from soc_ai.predict import Predictor
    directory = root / name
    directory.mkdir()
    model = FlowMLP()
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.zero_()
        model.net[-1].bias[2 if alert else 0] = 2
    save_weights(model, directory / 'model-weights.npz')
    write_json(directory / 'features.json', SPEC)
    write_json(directory / 'preprocessor.json', {'feature_hash': FEATURE_HASH,
                                                'mean': [0] * len(FEATURE_NAMES),
                                                'std': [1] * len(FEATURE_NAMES), 'clip': 10})
    metadata = {'version': 'soc-flow-model/0.1', 'complete': True, 'feature_hash': FEATURE_HASH,
                'classes': benchmark.CLASSES, 'active_classes': [True] * len(benchmark.CLASSES),
                'weights_sha256': benchmark.sha256(directory / 'model-weights.npz'),
                'preprocessor_sha256': benchmark.sha256(directory / 'preprocessor.json'),
                'attack_score_threshold': .5}
    write_json(directory / 'model.json', metadata)
    golden = normalize(flow(999))
    write_json(directory / 'golden.json', [{'flow': golden, 'features': features(golden).tolist()}])
    probabilities = Predictor(directory).probabilities([golden])
    write_json(directory / 'golden-predictions.json', np.asarray(probabilities).tolist())
    return directory


class BundleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import torch  # noqa: F401
        except ImportError as error:
            raise unittest.SkipTest('PyTorch required for tiny bundle integration') from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.baseline = _bundle(self.root, 'baseline')
        self.candidate = _bundle(self.root, 'candidate', alert=True)

    def test_real_cli_same_evidence_accounting_and_create_only_output(self):
        good, out_of_scope, missing = flow(1), flow(2), flow(3)
        out_of_scope['flow']['end'] = out_of_scope['flow']['start']
        del missing['flow']['bytes_toclient']
        normal = session(self.root, 'normal', records=[good, good, out_of_scope, missing,
                                                      {'event_type': 'alert'}])
        path = self.root / normal['flows']
        with path.open('ab') as stream:
            stream.write(b'{broken-json}\n')
        normal['sha256'] = benchmark.sha256(path)
        attack = session(self.root, 'attack', attack=True, records=[flow(4), flow(5)])
        manifest_path = manifest(self.root, [normal, attack])
        output = self.root / 'report.json'
        command = [sys.executable, str(Path(benchmark.__file__).resolve()),
                   '--manifest', str(manifest_path), '--baseline', str(self.baseline),
                   '--candidate', str(self.candidate), '--output', str(output)]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['acceptance_gate']['status'], 'insufficient_evidence')
        data = report['sessions'][0]
        self.assertEqual(data['data_counts']['duplicate_observations_removed'], 1)
        self.assertEqual(data['data_counts']['ignored_non_flow_records'], 1)
        self.assertEqual(data['data_counts']['invalid_records'], 1)
        self.assertEqual(data['data_counts']['missing_required_fields'], 1)
        self.assertEqual(data['models']['candidate']['unknown'], 3)
        self.assertEqual(data['models']['candidate']['counts']['tn'], 0)
        self.assertEqual(data['models']['candidate']['counts']['fp'], 1)
        self.assertEqual(data['models']['candidate']['coverage']['estimate'], .25)
        self.assertEqual(report['aggregate']['test']['candidate']['counts']['tp'], 2)
        self.assertEqual(report['aggregate']['test']['baseline']['counts']['fn'], 2)
        original = output.read_bytes()
        second = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(output.read_bytes(), original)

    def test_same_completed_connection_cannot_cross_validation_and_test(self):
        validation = session(self.root, 'validation', records=[flow(1)], role='validation')
        copied = flow(1)
        copied['flow_id'] = 'renamed-id'
        test = session(self.root, 'test', records=[copied])
        path = manifest(self.root, [validation, test])
        with self.assertRaisesRegex(ValueError, 'Duplicate completed connection'):
            benchmark.run(path, self.baseline, self.candidate, self.root / 'report.json')
        self.assertFalse((self.root / 'report.json').exists())

    def test_inconsistent_snapshots_of_one_connection_are_rejected(self):
        original, changed = flow(1), flow(1)
        changed['flow']['bytes_toserver'] += 20
        item = session(self.root, records=[original, changed])
        with self.assertRaisesRegex(ValueError, 'Conflicting observations'):
            benchmark.run(manifest(self.root, [item]), self.baseline, self.candidate,
                          self.root / 'report.json')

    def test_golden_mismatch_rejects_bundle_before_reporting(self):
        (self.candidate / 'golden-predictions.json').write_text('[[0,0,0,0,0,1]]')
        item = session(self.root)
        with self.assertRaisesRegex(ValueError, 'Golden inference mismatch'):
            benchmark.run(manifest(self.root, [item]), self.baseline, self.candidate,
                          self.root / 'report.json')
        self.assertFalse((self.root / 'report.json').exists())

    def test_source_wrapper_reveals_train_time_session_despite_renamed_manifest(self):
        metadata_path = self.candidate / 'model.json'
        metadata = json.loads(metadata_path.read_text())
        metadata['training_provenance'] = {'all_session_ids': ['historical-source']}
        metadata_path.write_text(json.dumps(metadata))
        wrapped = {'schema_version': 'soc-lab-labeled-flow/0.1',
                   'session_id': 'historical-source', 'role': 'test', 'flow': flow(1)}
        item = session(self.root, 'fresh-name', records=[wrapped])
        with self.assertRaisesRegex(ValueError, 'reveals a reused train-time session'):
            benchmark.run(manifest(self.root, [item]), self.baseline, self.candidate,
                          self.root / 'report.json')

    def test_explicit_synthetic_record_cannot_be_hidden_by_real_manifest_flag(self):
        record = flow(1)
        record['synthetic'] = True
        item = session(self.root, records=[record])
        item['evidence']['independent'] = True
        result = benchmark.run(manifest(self.root, [item], synthetic=False), self.baseline,
                               self.candidate, self.root / 'report.json')
        self.assertTrue(result['sessions'][0]['synthetic'])
        self.assertTrue(any('Synthetic' in text for text in result['acceptance_gate']['insufficient_evidence']))

    def test_wrapped_flow_synthetic_marker_cannot_be_erased(self):
        inner = flow(1); inner['synthetic'] = True
        record = {'schema_version': 'soc-lab-labeled-flow/0.1', 'role': 'test',
                  'synthetic': False, 'flow': inner}
        item = session(self.root, records=[record]); item['evidence']['independent'] = True
        result = benchmark.run(manifest(self.root, [item], synthetic=False), self.baseline,
                               self.candidate, self.root / 'report.json')
        self.assertTrue(result['sessions'][0]['synthetic'])

    def test_bundle_synthetic_marker_overrides_conflicting_provenance(self):
        metadata = {'synthetic_fixture': True, 'training_provenance': {
            'verified': True, 'covers_all_training_sources': True, 'all_session_ids': ['source'],
            'independence_verified': True, 'raw_sources_rechecked': True, 'synthetic_fixture': False}}
        result = benchmark.check_training_overlap(metadata, [], 'candidate')
        self.assertFalse(result['independent_source_isolation_verified'])


if __name__ == '__main__':
    unittest.main()
