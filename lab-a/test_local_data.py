import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np
import import_lab_normal as importer
import prepare_lab_mix as mixer
from soc_ai.common import CLASSES, sha256, write_json
from soc_ai.flow import FEATURE_HASH, SPEC, features, normalize, utc


def event(port=50001, seconds=5, start='2026-10-14T03:00:00Z'):
    begin = datetime.fromisoformat(start.replace('Z', '+00:00'))
    end = begin + timedelta(seconds=seconds)
    return {'event_type': 'flow', 'timestamp': utc(end + timedelta(seconds=120)),
            'flow_id': port * 12345, 'src_ip': '172.20.0.4', 'src_port': port,
            'dest_ip': '172.20.0.3', 'dest_port': 22, 'proto': 'TCP', 'app_proto': 'ssh',
            'flow': {'start': utc(begin), 'end': utc(end), 'pkts_toserver': 30,
                     'pkts_toclient': 40, 'bytes_toserver': 3200, 'bytes_toclient': 5100,
                     'state': 'closed', 'reason': 'timeout'}}


class LocalDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def json(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def capture(self, name, events=None, accepted=True, extra_auth=''):
        events = [event()] if events is None else events
        session = self.root / name
        target = session / 'capture-1'
        target.mkdir(parents=True)
        earliest = min(datetime.fromisoformat(e['flow']['start'].replace('Z', '+00:00')) for e in events)
        marker = {'version': 'lab-flow-check/0.1', 'context': 'normal-ssh-training',
                  'start_time': utc(earliest - timedelta(seconds=1)),
                  'endpoints': ['172.20.0.3', '172.20.0.4'],
                  'container_started_at': '2026-10-14T01:46:43Z',
                  'context_is_not_a_training_label': True}
        self.json(session / 'session.json', marker)
        self.json(target / 'summary.json', {'complete': True, 'session': marker,
                  'capture_counts': {'selected_flows': len(events)},
                  'predicted_labels': {'SSH-Patator': len(events)}})
        (target / 'flows.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
        lines = []
        if accepted:
            seen = set()
            for item in events:
                t = datetime.fromisoformat(item['flow']['start'].replace('Z', '+00:00')) + timedelta(seconds=.5)
                # Matches Ubuntu auth.log offset and date rollover, not just UTC strings.
                local = t.astimezone(timezone(timedelta(hours=-4)))
                line = (f'{local.isoformat()} ubuntu-endpoint sshd-session[425]: '
                        f'Accepted password for labuser from 172.20.0.4 port {item["src_port"]} ssh2\n')
                if line not in seen:
                    lines.append(line)
                    seen.add(line)
        (session / 'auth.log').write_text(''.join(lines) + extra_auth, encoding='utf-8')
        return target

    def imported(self, name, role, port=50001, start='2026-10-14T03:00:00Z'):
        source = self.capture(name, [event(port=port, start=start)])
        output = self.root / (name + '-import')
        with contextlib.redirect_stdout(io.StringIO()):
            report = importer.run(source, output, role)
        return output, report

    def base(self):
        path = self.root / 'base'
        path.mkdir()
        flow = normalize(event())
        x = np.stack([features(flow)] * 4)
        y = np.asarray([0, 2, 0, 2], dtype=np.int64)
        split = np.asarray([0, 0, 1, 2], dtype=np.uint8)
        np.savez_compressed(path / 'data.npz', x=x, y=y, split=split,
                            tier=np.asarray([0, 1, 0, 0], dtype=np.uint8),
                            day=np.asarray([0, 0, 1, 1], dtype=np.uint8))
        counts = {role: {'rows': int(np.sum(split == i)), 'groups': int(np.sum(split == i)),
                         'classes': {label: int(np.sum((split == i) & (y == j)))
                                     for j, label in enumerate(CLASSES)}}
                  for i, role in enumerate(mixer.ROLES)}
        self.json(path / 'report.json', {'version': 'soc-prepared/0.1', 'complete': True,
                  'feature_hash': FEATURE_HASH, 'classes': CLASSES, 'seed': 42,
                  'day_names': ['Tuesday', 'Friday'], 'counts': counts,
                  'data_sha256': sha256(path / 'data.npz'), 'warnings': ['Experimental CICIDS labels'],
                  'split_policy': 'base original tuple groups'})
        self.json(path / 'features.json', SPEC)
        self.json(path / 'golden.json', [{'flow': flow, 'features': features(flow).tolist()}])
        return path

    def all_roles(self):
        return [self.imported(role, role, 50001 + i,
                             f'2026-10-14T03:0{i}:00Z')[0]
                for i, role in enumerate(mixer.ROLES)]

    def test_success_evidence_and_same_features(self):
        output, report = self.imported('success', 'train')
        item = json.loads((output / 'labeled-flows.jsonl').read_text())
        self.assertEqual(item['label'], 'BENIGN')  # Fake model says SSH-Patator in summary.
        self.assertEqual(item['evidence']['source_port'], 50001)
        self.assertTrue(item['evidence']['timestamp'].startswith('2026-10-14T03:00:00.5'))
        np.testing.assert_array_equal(features(item['flow']), features(normalize(event())))
        self.assertTrue(report['complete'])

    def test_no_auth_cannot_be_labeled(self):
        source = self.capture('no-auth', accepted=False)
        output = self.root / 'rejected'
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, output)
        self.assertFalse(json.loads((output / 'report.json').read_text())['complete'])

    def test_old_auth_same_port_is_not_evidence(self):
        line = '2026-10-13T02:00:00Z ubuntu-endpoint sshd[3]: Accepted password for labuser from 172.20.0.4 port 50001 ssh2\n'
        source = self.capture('old-auth', accepted=False, extra_auth=line)
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, self.root / 'old-rejected')

    def test_other_user_not_evidence(self):
        source = self.capture('other-user')
        auth = source.parent / 'auth.log'
        auth.write_text(auth.read_text().replace('for labuser', 'for anotheruser'))
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, self.root / 'user-rejected')

    def test_naive_auth_timestamp_not_accepted(self):
        source = self.capture('naive')
        auth = source.parent / 'auth.log'
        auth.write_text(auth.read_text().replace('-04:00', ''))
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, self.root / 'naive-rejected')

    def test_exact_observations_deduplicated(self):
        original = event()
        duplicate = {**original, 'flow_id': 999999, 'record_id': 'different-source-line'}
        source = self.capture('duplicate', [original, duplicate])
        with contextlib.redirect_stdout(io.StringIO()):
            report = importer.run(source, self.root / 'duplicate-import')
        self.assertEqual(report['counts']['selected_records'], 1)
        self.assertEqual(report['counts']['duplicate_observations_removed'], 1)

    def test_conflicting_observations_not_arbitrarily_selected(self):
        first = event()
        second = {**first, 'flow': {**first['flow'], 'bytes_toserver': 9000}}
        source = self.capture('conflict', [first, second])
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, self.root / 'conflict-import')

    def test_attack_context_rejected(self):
        source = self.capture('attack')
        marker = json.loads((source.parent / 'session.json').read_text())
        marker['context'] = 'hydra'
        self.json(source.parent / 'session.json', marker)
        summary = json.loads((source / 'summary.json').read_text())
        summary['session'] = marker
        self.json(source / 'summary.json', summary)
        with self.assertRaisesRegex(ValueError, 'normal SSH'):
            importer.run(source, self.root / 'attack-import')

    def test_manifest_mismatch_rejected(self):
        source = self.capture('bad-count')
        summary = json.loads((source / 'summary.json').read_text())
        summary['capture_counts']['selected_flows'] = 2
        self.json(source / 'summary.json', summary)
        with self.assertRaisesRegex(ValueError, 'count'):
            importer.run(source, self.root / 'count-import')

    def test_multiple_auth_success_is_ambiguous(self):
        source = self.capture('ambiguous')
        auth = source.parent / 'auth.log'
        auth.write_text(auth.read_text() + auth.read_text().replace('00.500000', '01.500000'))
        with self.assertRaisesRegex(ValueError, 'No evidence-backed'):
            importer.run(source, self.root / 'ambiguous-import')

    def test_mixed_cache_preserves_base_and_assigns_whole_sessions(self):
        base = self.base()
        before = sha256(base / 'data.npz')
        local = self.all_roles()
        output = self.root / 'mixed'
        with contextlib.redirect_stdout(io.StringIO()):
            report = mixer.run(base, local, output)
        with np.load(base / 'data.npz', allow_pickle=False) as old, \
             np.load(output / 'data.npz', allow_pickle=False) as new:
            for key in ('x', 'y', 'split', 'tier', 'day'):
                np.testing.assert_array_equal(new[key][:4], old[key])
            np.testing.assert_array_equal(new['split'][4:], [0, 1, 2])
            np.testing.assert_array_equal(new['tier'][4:], [2, 2, 2])
        self.assertEqual(before, sha256(base / 'data.npz'))
        self.assertEqual(report['counts']['train']['rows'], 3)
        self.assertEqual(report['counts']['validation']['rows'], 2)
        self.assertEqual(report['data_sha256'], sha256(output / 'data.npz'))
        self.assertTrue(report['complete'])

    def test_train_only_session_cannot_be_split_into_validation_test(self):
        base = self.base()
        output, _ = self.imported('train-only', 'train')
        with self.assertRaisesRegex(ValueError, 'separate local train'):
            mixer.run(base, [output], self.root / 'mix-failed')

    def test_same_session_cannot_be_used_twice(self):
        base = self.base()
        output, _ = self.imported('same-session', 'train')
        with self.assertRaisesRegex(ValueError, 'Repeated session'):
            mixer.run(base, [output, output], self.root / 'repeat-mix')

    def test_same_flow_across_split_roles_rejected(self):
        base = self.base()
        outputs = []
        for role in ('train', 'validation', 'test'):
            source = self.capture('copy-' + role)
            # Distinct declared sessions, but the same captured flow must not be reused.
            marker = json.loads((source.parent / 'session.json').read_text())
            marker['context'] += '-' + role
            self.json(source.parent / 'session.json', marker)
            summary = json.loads((source / 'summary.json').read_text())
            summary['session'] = marker
            self.json(source / 'summary.json', summary)
            output = self.root / ('copy-import-' + role)
            with contextlib.redirect_stdout(io.StringIO()):
                importer.run(source, output, role)
            outputs.append(output)
        with self.assertRaisesRegex(ValueError, 'Repeated local flow'):
            mixer.run(base, outputs, self.root / 'leak-mix')

    def test_changed_labeled_file_rejected(self):
        base = self.base()
        outputs = self.all_roles()
        target = outputs[0] / 'labeled-flows.jsonl'
        target.write_text(target.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            mixer.run(base, outputs, self.root / 'bad-hash-mix')

    def test_previously_mixed_cache_not_appended_again(self):
        base = self.base()
        outputs = self.all_roles()
        mixed = self.root / 'once'
        with contextlib.redirect_stdout(io.StringIO()):
            mixer.run(base, outputs, mixed)
        with self.assertRaisesRegex(ValueError, 'original CICIDS'):
            mixer.run(mixed, outputs, self.root / 'twice')


if __name__ == '__main__':
    unittest.main()
