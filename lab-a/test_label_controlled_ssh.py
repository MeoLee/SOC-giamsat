from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from label_controlled_ssh import run
from lab_scenarios import dump, flow, json_lines, load_object, sha256


def capture_fixture(root, name='normal', role='train', attack=False, day=19):
    folder = root / name; folder.mkdir()
    capture = folder / 'capture'; capture.mkdir()
    origin = datetime(2026, 10, day, tzinfo=timezone.utc)
    def stamp(seconds):
        return (origin + timedelta(seconds=seconds)).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    events, auth = [], []
    for i in range(8 if attack else 1):
        start = 2 + i * 4
        event = flow(i, 22, seconds=start)
        event['timestamp'] = stamp(start + 2)
        event['flow']['start'], event['flow']['end'] = stamp(start), stamp(start + 1)
        event['flow']['bytes_toserver'] += i * 10
        event['src_port'] = 45000 + i + (100 if attack else 0)
        events.append(event)
        auth.append((f'{stamp(start + .5)} ubuntu-endpoint sshd[123]: '
            f'{"Failed" if attack else "Accepted"} password for labtest '
            f'from 192.0.2.10 port {event["src_port"]} ssh2\n').encode())
    (capture / 'suricata-eve.jsonl').write_bytes(json_lines(events))
    (capture / 'ubuntu-auth.log').write_bytes(b''.join(auth))
    marker = {'format': 'soc-capture/1.0', 'synthetic': True,
        'session_id': 'capture-' + name, 'closed': True, 'status': 'completed',
        'started_at_utc': stamp(-10), 'ended_at_utc': stamp(120),
        'gaps': [], 'partials': [],
        'sources': [{'output': name, 'last_error': None} for name in ('suricata-eve.jsonl', 'ubuntu-auth.log')],
        'sha256': {name: sha256(capture / name) for name in ('suricata-eve.jsonl', 'ubuntu-auth.log')}}
    dump(capture / 'session.json', marker)
    transcript = folder / 'commands.txt'
    transcript.write_text('SYNTHETIC controlled operator transcript. Never real training/quality evidence.\n')
    operator = {'schema_version': 'soc-controlled-ssh/1.0', 'synthetic': True,
        'id': name, 'role': role, 'capture_session_id': marker['session_id'],
        'source_ip': '192.0.2.10', 'target_ip': '192.0.2.20',
        'target_host': 'ubuntu-endpoint', 'username': 'labtest',
        'start_time': stamp(0), 'end_time': stamp(100), 'captured_at': stamp(110),
        'intent': 'ssh_password_guessing' if attack else 'normal_ssh',
        'controlled': True, 'independent': True, 'reviewed': True, 'reviewer': 'synthetic-test-operator',
        'tool_output': {'path': 'commands.txt', 'sha256': sha256(transcript)}}
    dump(folder / 'operator.json', operator)
    return folder, capture, operator, events, auth


class ControlledSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder, self.capture, self.operator, self.events, self.auth = capture_fixture(self.root)

    def refresh(self):
        marker = load_object(self.capture / 'session.json')
        marker['sha256'] = {name: sha256(self.capture / name) for name in ('suricata-eve.jsonl', 'ubuntu-auth.log')}
        dump(self.capture / 'session.json', marker)

    def save_auth(self, content):
        (self.capture / 'ubuntu-auth.log').write_bytes(content)
        self.refresh()

    def save_eve(self, events):
        (self.capture / 'suricata-eve.jsonl').write_bytes(json_lines(events))
        self.refresh()

    def label(self):
        dump(self.folder / 'operator.json', self.operator)
        return run(self.capture, self.folder / 'operator.json', self.folder / 'labels')

    def records(self):
        return [json.loads(line) for line in (self.folder / 'labels/labels.jsonl').read_text().splitlines()]

    def test_normal_native_accepted_flow_and_exact_raw_provenance(self):
        result = self.label()
        row = self.records()[0]
        self.assertTrue(result['synthetic'])
        self.assertTrue(row['synthetic'])
        self.assertEqual(row['label'], 'BENIGN')
        self.assertEqual(row['flow']['src_port'], 45000)
        self.assertEqual(row['raw_ref']['line'], 1)
        self.assertEqual(row['raw_ref']['byte_offset'], 0)
        first = (self.capture / 'suricata-eve.jsonl').read_bytes().splitlines()[0]
        self.assertEqual(row['raw_ref']['raw_sha256'], hashlib.sha256(first).hexdigest())
        self.assertEqual(row['evidence']['auth_refs'][0]['line'], 1)
        self.assertIn('auth', row['evidence_refs'])
        self.assertTrue(result['sessions'][0]['label_review']['independent'])

    def test_normal_publickey_success_is_supported(self):
        self.save_auth(self.auth[0].replace(b'Accepted password', b'Accepted publickey'))
        self.label()
        self.assertEqual(self.records()[0]['label'], 'BENIGN')

    def test_controlled_guessing_labels_only_failure_flows(self):
        folder, capture, _, _, _ = capture_fixture(self.root, 'attack', attack=True)
        fragment = run(capture, folder / 'operator.json', folder / 'labels')
        records = [json.loads(line) for line in (folder / 'labels/labels.jsonl').read_text().splitlines()]
        self.assertEqual(len(records), 8)
        self.assertEqual({row['label'] for row in records}, {'SSH-Patator'})
        self.assertTrue(fragment['synthetic'])

    def test_accidental_single_failure_does_not_become_attack(self):
        self.operator['intent'] = 'ssh_password_guessing'
        self.save_auth(self.auth[0].replace(b'Accepted', b'Failed'))
        with self.assertRaisesRegex(ValueError, 'at least 8'):
            self.label()
        self.assertFalse((self.folder / 'labels').exists())

    def test_eight_failures_outside_scope_do_not_authorize_attack(self):
        folder, capture, operator, _, _ = capture_fixture(self.root, 'attack', attack=True)
        operator['start_time'] = operator['end_time'].replace('01:40.', '01:20.')
        dump(folder / 'operator.json', operator)
        with self.assertRaisesRegex(ValueError, 'at least 8'):
            run(capture, folder / 'operator.json', folder / 'labels')

    def test_mixed_success_failure_connection_is_excluded_not_benign(self):
        self.save_auth(self.auth[0] + self.auth[0].replace(b'Accepted', b'Failed'))
        with self.assertRaisesRegex(ValueError, 'No unambiguous'):
            self.label()

    def test_attack_mixed_connection_excluded_but_other_failures_keep_evidence(self):
        folder, capture, _, _, auth = capture_fixture(self.root, 'attack', attack=True)
        auth_path = capture / 'ubuntu-auth.log'
        auth_path.write_bytes(b''.join(auth) + auth[0].replace(b'Failed', b'Accepted'))
        marker = load_object(capture / 'session.json'); marker['sha256']['ubuntu-auth.log'] = sha256(auth_path)
        dump(capture / 'session.json', marker)
        run(capture, folder / 'operator.json', folder / 'labels')
        report = load_object(folder / 'labels/report.json')
        self.assertEqual(report['counts']['selected_records'], 7)
        self.assertEqual(report['counts']['excluded_mixed_auth_outcomes'], 1)

    def test_auth_source_port_user_host_and_time_must_match(self):
        original = self.auth[0]
        changes = [(b'192.0.2.10', b'192.0.2.99'), (b'port 45000', b'port 45001'),
                   (b'for labtest', b'for other'), (b'ubuntu-endpoint', b'other-host'),
                   (b'00:00:02.500000Z', b'00:01:02.500000Z')]
        for before, after in changes:
            self.save_auth(original.replace(before, after))
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, 'No unambiguous'):
                self.label()

    def test_flow_target_protocol_app_and_scope_must_match(self):
        changes = [('dest_ip', '192.0.2.99'), ('dest_port', 2222), ('proto', 'UDP'), ('app_proto', 'http')]
        for key, value in changes:
            altered = deepcopy(self.events[0]); altered[key] = value
            self.save_eve([altered])
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'No unambiguous'):
                self.label()
        self.save_eve(self.events)
        self.operator['start_time'] = self.operator['start_time'].replace('00:00:00.', '00:00:03.')
        with self.assertRaisesRegex(ValueError, 'No unambiguous'):
            self.label()

    def test_out_of_scope_and_inconsistent_observations_are_not_labeled(self):
        altered = deepcopy(self.events[0]); altered['flow']['pkts_toserver'] = 1; altered['flow']['pkts_toclient'] = 0
        self.save_eve([altered])
        with self.assertRaisesRegex(ValueError, 'No unambiguous'):
            self.label()
        altered = deepcopy(self.events[0]); altered['flow']['bytes_toserver'] += 1
        self.save_eve(self.events + [altered])
        with self.assertRaisesRegex(ValueError, 'No unambiguous'):
            self.label()

    def test_duplicate_native_observation_is_not_duplicate_training_record(self):
        self.save_eve(self.events * 2)
        self.label()
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(len(self.records()[0]['evidence']['all_observation_refs']), 2)

    def test_one_auth_event_matching_multiple_overlapping_flows_is_ambiguous(self):
        overlapping = deepcopy(self.events[0])
        overlapping['flow']['start'] = overlapping['flow']['start'].replace('00:00:02.', '00:00:01.')
        self.save_eve(self.events + [overlapping])
        with self.assertRaisesRegex(ValueError, 'No unambiguous'):
            self.label()

    def test_missing_auth_eve_hash_and_modified_sources_are_rejected(self):
        marker = load_object(self.capture / 'session.json')
        del marker['sha256']['ubuntu-auth.log']; dump(self.capture / 'session.json', marker)
        with self.assertRaisesRegex(ValueError, 'missing hashes'):
            self.label()
        self.refresh()
        (self.capture / 'suricata-eve.jsonl').write_text('changed\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.label()

    def test_unclosed_degraded_or_gapped_capture_is_rejected(self):
        original = load_object(self.capture / 'session.json')
        for change in ({'closed': False}, {'status': 'degraded'}, {'gaps': [{'source': 'eve'}]},
                       {'partials': [{'source': 'auth'}]}):
            dump(self.capture / 'session.json', {**original, **change})
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.label()

    def test_operator_requires_independent_controlled_review_and_capture_identity(self):
        original = dict(self.operator)
        for change in ({'controlled': False}, {'independent': False}, {'reviewed': False},
                       {'capture_session_id': 'other-capture'}, {'synthetic': False}, {'synthetic': 'true'},
                       {'role': 'final_test'}, {'intent': 'AI_says_attack'}):
            self.operator = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.label()

    def test_naive_time_and_window_outside_capture_are_rejected(self):
        original = dict(self.operator)
        for change in ({'captured_at': '2026-10-19T01:00:00'},
                       {'start_time': '2026-10-18T23:00:00Z'}):
            self.operator = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.label()

    def test_operator_transcript_hash_and_path_must_be_valid(self):
        (self.folder / 'commands.txt').write_text('tampered\n')
        with self.assertRaisesRegex(ValueError, 'transcript hash'):
            self.label()
        self.operator['tool_output']['path'] = '../outside.txt'
        with self.assertRaises(ValueError):
            self.label()

    def test_partial_raw_auth_is_rejected_even_with_matching_file_hash(self):
        self.save_auth(self.auth[0].rstrip(b'\n'))
        with self.assertRaisesRegex(ValueError, 'partial'):
            self.label()

    def test_output_is_create_only(self):
        self.label()
        with self.assertRaisesRegex(ValueError, 'Output exists'):
            self.label()

    def test_fragments_directly_build_prepared_data_and_keep_synthetic_provenance(self):
        from prepare_session_data import run as build
        from soc_ai.data_contract import load_prepared
        sessions = []
        for day, role in enumerate(('train', 'validation', 'test'), 20):
            for attack in (False, True):
                name = role + ('-attack' if attack else '-normal')
                folder, capture, _, _, _ = capture_fixture(self.root, name, role, attack, day)
                fragment = run(capture, folder / 'operator.json', folder / 'labels')
                entry = fragment['sessions'][0]
                prefix = folder.name + '/labels/'
                entry['records'] = prefix + entry['records']
                for evidence in entry['evidence_files']:
                    evidence['path'] = prefix + evidence['path']
                sessions.append(entry)
        manifest = self.root / 'sessions.json'
        dump(manifest, {'schema_version': 'soc-supervised-sessions/1.0', 'synthetic': True, 'sessions': sessions})
        report = build(manifest, self.root / 'prepared')
        data = load_prepared(self.root / 'prepared')
        self.assertTrue(report['synthetic_fixture'])
        self.assertEqual(data.arrays['x'].shape, (27, 24))
        self.assertEqual({row['role'] for row in report['local_inputs']}, {'train', 'validation', 'test'})
        self.assertEqual(len(report['provenance']['capture_session_ids']), 6)


if __name__ == '__main__':
    unittest.main()
