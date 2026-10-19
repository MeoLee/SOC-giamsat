import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lab_scenarios as scenarios


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / 'capture'
        self.capture.mkdir()
        self.eve = self.capture / 'suricata-eve.jsonl'
        self.eve.write_bytes(scenarios.json_lines([
            scenarios.flow(0, 22, 1),
            scenarios.flow(1, 22, 50),  # Outside independent time scope.
            scenarios.flow(2, 22, 1, source='192.0.2.99'),
            {'event_type': 'stats', 'timestamp': scenarios.stamp()}]))
        (self.capture / 'ubuntu-auth.log').write_bytes(scenarios.auth(1, 'Accepted'))
        self.session = {'format': 'soc-capture/1.0', 'session_id': 'real-session-001',
            'closed': True, 'status': 'completed', 'gaps': [], 'partials': [],
            'sources': [{'output': 'suricata-eve.jsonl', 'last_error': None},
                        {'output': 'ubuntu-auth.log', 'last_error': None}]}
        self.save_session()
        self.evidence = self.root / 'operator'
        self.evidence.mkdir()
        (self.evidence / 'commands.txt').write_text('Operator recorded a normal SSH session.\n')
        (self.evidence / 'auth.txt').write_bytes(scenarios.auth(1, 'Accepted'))
        self.descriptor = {'schema_version': 'soc-lab-independent-evidence/1.0',
            'independent': True, 'synthetic': False, 'capture_session_id': 'real-session-001',
            'scenario': 'normal-ssh', 'expected_attack': False,
            'source': 'Operator transcript plus independent endpoint authentication log.',
            'collected_at': '2026-10-19T07:10:00+07:00',
            'flow_scope': {'all_selected_flows_share_outcome': True,
                'start_time': scenarios.stamp(0), 'end_time': scenarios.stamp(10),
                'src_ip': scenarios.CLIENT, 'dest_ip': scenarios.TARGET, 'dest_ports': [22]},
            'artifacts': [{'kind': 'operator_log', 'path': 'commands.txt'},
                          {'kind': 'auth_server_log', 'path': 'auth.txt'}]}
        self.descriptor_path = self.evidence / 'evidence.json'
        self.save_evidence()

    def save_session(self):
        self.session['sha256'] = {name: scenarios.sha256(self.capture / name)
                                 for name in ('suricata-eve.jsonl', 'ubuntu-auth.log')}
        scenarios.dump(self.capture / 'session.json', self.session)

    def save_evidence(self):
        scenarios.dump(self.descriptor_path, self.descriptor)

    def register(self, **kwargs):
        settings = dict(session_path=self.capture, evidence_path=self.descriptor_path,
            directory=self.root / 'registered', session_id='normal-ssh-day2', role='test',
            scenario='normal-ssh', expected_attack=False, expected_class='BENIGN')
        settings.update(kwargs)
        return scenarios.register(**settings)

    def test_replay_contracts_without_any_subprocess(self):
        with patch('subprocess.run', side_effect=AssertionError('No external command permitted')):
            report = scenarios.replay(self.root / 'replay')
        self.assertTrue(report['synthetic'])
        self.assertFalse(report['accuracy_evidence'])
        self.assertFalse(report['real_model_inference_performed'])
        self.assertEqual(report['failed'], 0, [r for r in report['checks'] if not r['passed']])
        self.assertGreaterEqual(report['passed'], 30)
        for name in ('scan-many-ports-port-diversity', 'repeat-single-port-port-diversity',
                     'rotation-drains-old-inode', 'restart-reconciles-committed-cursor',
                     'missing-inode-marks-gap', 'outbox-restart-retries-original-route'):
            self.assertTrue(next(row['passed'] for row in report['checks'] if row['id'] == name))

    def test_registered_flows_are_scoped_hashed_and_not_auto_labeled(self):
        manifest = self.register()
        self.assertIs(manifest['synthetic'], False)
        row = manifest['sessions'][0]
        self.assertEqual(row['provenance']['capture_session_id'], 'real-session-001')
        self.assertTrue(row['evidence']['independent'])
        flows_path = self.root / 'registered' / row['flows']
        self.assertEqual(scenarios.sha256(flows_path), row['sha256'])
        flows = [json.loads(line) for line in flows_path.read_text().splitlines()]
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]['flow_id'], str(10**18))
        self.assertNotIn('label', flows[0])
        self.assertNotIn('predicted_label', flows[0])
        self.assertEqual(flows[0]['source_ref']['record_number'], 1)
        for path, expected in row['evidence']['sha256'].items():
            self.assertEqual(scenarios.sha256(self.root / 'registered' / path), expected)
        report = scenarios.load_object(self.root / 'registered' / 'selection-report.json')
        self.assertEqual(report['counts']['selected_flows'], 1)
        self.assertEqual(report['counts']['outside_time_scope'], 1)
        self.assertEqual(report['counts']['outside_endpoint_scope'], 1)

    def test_raw_hash_tamper_is_rejected(self):
        with self.eve.open('ab') as stream:
            stream.write(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            self.register()
        self.assertFalse((self.root / 'registered').exists())

    def test_unclosed_degraded_and_synthetic_captures_rejected(self):
        for change in ({'closed': False}, {'status': 'degraded'}, {'synthetic': True}, {'synthetic': 'false'},
                       {'gaps': [{'source': 'eve'}]}, {'partials': [{'source': 'eve'}]}):
            original = dict(self.session)
            self.session.update(change)
            self.save_session()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.register()
            self.session = original

    def test_all_raw_sources_verified_not_only_selected_eve(self):
        (self.capture / 'ubuntu-auth.log').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'ubuntu-auth.log'):
            self.register()

    def test_capture_missing_any_source_hash_rejected(self):
        del self.session['sha256']['ubuntu-auth.log']
        scenarios.dump(self.capture / 'session.json', self.session)
        with self.assertRaisesRegex(ValueError, 'Every capture source'):
            self.register()

    def test_wrong_capture_and_naive_evidence_time_rejected(self):
        for name, value in [('capture_session_id', 'other-session'),
                            ('collected_at', '2026-10-19T07:10:00')]:
            original = self.descriptor[name]
            self.descriptor[name] = value
            self.save_evidence()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.register()
            self.descriptor[name] = original

    def test_synthetic_independent_flags_are_strict_booleans(self):
        for change in ({'independent': 1}, {'synthetic': None}, {'synthetic': True}):
            original = dict(self.descriptor)
            self.descriptor.update(change)
            self.save_evidence()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'independent:true'):
                self.register()
            self.descriptor = original

    def test_flow_scope_requires_homogeneous_attestation(self):
        self.descriptor['flow_scope']['all_selected_flows_share_outcome'] = False
        self.save_evidence()
        with self.assertRaisesRegex(ValueError, 'homogeneous'):
            self.register()

    def test_outcome_and_class_are_not_inferred_from_scenario(self):
        with self.assertRaisesRegex(ValueError, 'Class must be'):
            self.register(expected_class='SQLi')
        with self.assertRaisesRegex(ValueError, 'Class must be'):
            self.register(expected_class='DDoS')
        with self.assertRaisesRegex(ValueError, 'Independent outcome differs'):
            self.register(expected_attack=True, expected_class=None)

    def test_ai_or_rule_alone_is_not_independent_evidence(self):
        self.descriptor['artifacts'] = [{'kind': 'operator_log', 'path': 'commands.txt'},
                                        {'kind': 'ai_prediction', 'path': 'auth.txt'}]
        self.save_evidence()
        with self.assertRaisesRegex(ValueError, 'not ground truth'):
            self.register()

    def test_paths_cannot_escape_artifact_directory(self):
        for path in ('../secret.txt', '/etc/passwd', 'C:\\secret.txt', '..\\secret.txt'):
            self.descriptor['artifacts'][0]['path'] = path
            self.save_evidence()
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.register()

    def test_empty_evidence_and_duplicate_artifacts_rejected(self):
        (self.evidence / 'commands.txt').write_text('')
        with self.assertRaisesRegex(ValueError, 'must not be empty'):
            self.register()
        (self.evidence / 'commands.txt').write_text('restored\n')
        self.descriptor['artifacts'][1]['path'] = 'commands.txt'
        self.save_evidence()
        with self.assertRaisesRegex(ValueError, 'distinct files'):
            self.register()

    def test_zero_selected_flows_leaves_no_partial_output(self):
        self.descriptor['flow_scope']['dest_ports'] = [443]
        self.save_evidence()
        with self.assertRaisesRegex(ValueError, 'no completed flows'):
            self.register()
        self.assertFalse((self.root / 'registered').exists())
        self.assertEqual(list(self.root.glob('.registered-building-*')), [])

    def test_partial_eve_record_rejected_even_if_hash_matches(self):
        with self.eve.open('ab') as stream:
            stream.write(b'{"event_type":"flow"}')
        self.save_session()
        with self.assertRaisesRegex(ValueError, 'partial record'):
            self.register()
        self.assertFalse((self.root / 'registered').exists())

    def test_existing_output_never_overwritten(self):
        self.register()
        marker = self.root / 'registered' / 'keep.txt'
        marker.write_text('keep')
        with self.assertRaisesRegex(ValueError, 'Output exists'):
            self.register()
        self.assertEqual(marker.read_text(), 'keep')

    def test_capture_changed_after_validation_is_not_registered_under_old_hash(self):
        validate = scenarios.validate_evidence
        def changed_after_hash_check(*args):
            evidence = validate(*args)
            with self.eve.open('ab') as stream:
                stream.write(scenarios.json_lines([scenarios.flow(5, 22, 60)]))
            return evidence
        with patch.object(scenarios, 'validate_evidence', side_effect=changed_after_hash_check):
            with self.assertRaisesRegex(ValueError, 'changed during registration'):
                self.register()
        self.assertFalse((self.root / 'registered').exists())

    def test_plan_command_has_no_execute_mode(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = scenarios.main(['plan', '--scenario', 'normal-ssh'])
        self.assertEqual(code, 0)
        self.assertIs(json.loads(output.getvalue())['traffic_executed'], False)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            scenarios.parser().parse_args(['plan', '--execute'])


if __name__ == '__main__':
    unittest.main()
