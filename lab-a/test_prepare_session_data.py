from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prepare_session_data import index, run, MANIFEST
from soc_ai.common import read_json, sha256, write_json
from soc_ai.data_contract import load_prepared
from test_lab_live import flow


def fixture(root):
    sessions = []
    for role_index, role in enumerate(('train', 'validation', 'test')):
        for label_index, label in enumerate(('BENIGN', 'SSH-Patator')):
            sid = f'{role}-{label_index}'
            folder = root / sid; folder.mkdir()
            raw = []
            for i in range(6):
                event = flow(30000 + role_index * 100 + label_index * 20 + i)
                event['timestamp'] = f'2026-10-{10+role_index:02d}T14:01:00Z'
                event['flow']['start'] = f'2026-10-{10+role_index:02d}T14:00:00Z'
                event['flow']['end'] = f'2026-10-{10+role_index:02d}T14:00:{10+i:02d}Z'
                raw.append(event)
            eve = folder / 'eve.jsonl'; eve.write_text(''.join(json.dumps(e) + '\n' for e in raw))
            operator = folder / 'operator.log'; operator.write_text('Synthetic operator evidence; never real model quality.\n')
            auth = folder / 'auth.log'; auth.write_text('Synthetic server evidence; never real model quality.\n')
            draft = folder / 'labels.jsonl'; index(eve, draft, sid, role)
            labels = [json.loads(line) for line in draft.read_text().splitlines()]
            for item in labels:
                item.update(label=label, label_method='reviewed_synthetic_test_fixture', evidence_refs=['operator', 'auth'])
            draft.write_text(''.join(json.dumps(item) + '\n' for item in labels))
            session = {'id': sid, 'capture_session_id': sid, 'role': role,
                       'records': str(draft.relative_to(root)), 'sha256': sha256(draft),
                       'captured_at': f'2026-10-{10+role_index:02d}T14:02:00Z',
                       'label_review': {'reviewed': True, 'independent': True, 'method': 'Synthetic unit fixture only'},
                       'evidence_files': [{'id': key, 'kind': kind, 'path': str(path.relative_to(root)), 'sha256': sha256(path)}
                                          for key, kind, path in [('raw-eve', 'raw_eve', eve), ('operator', 'operator', operator), ('auth', 'auth', auth)]]}
            sessions.append(session)
    path = root / 'sessions.json'
    write_json(path, {'schema_version': MANIFEST, 'synthetic': True, 'sessions': sessions})
    return path


class SessionPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.manifest = fixture(self.root)

    def modify(self, action):
        data = read_json(self.manifest); action(data); write_json(self.manifest, data)

    def test_from_scratch_has_whole_session_roles_and_contract_provenance(self):
        report = run(self.manifest, self.root / 'prepared')
        prepared = load_prepared(self.root / 'prepared')
        self.assertTrue(report['synthetic_fixture'])
        self.assertEqual(prepared.arrays['x'].shape, (36, 24))
        self.assertTrue(prepared.provenance['covers_all_training_sources'])
        self.assertFalse(prepared.provenance['independence_verified'])
        for entry in report['local_inputs']:
            mask = prepared.arrays['day'] == entry['day_code']
            self.assertTrue((prepared.arrays['split'][mask] == ('train', 'validation', 'test').index(entry['role'])).all())

    def test_draft_does_not_assign_benign(self):
        target = self.root / 'draft.jsonl'
        result = index(self.root / 'train-0/eve.jsonl', target, 'new-session', 'train')
        self.assertEqual(result['labels_assigned'], 0)
        self.assertTrue(all(json.loads(line)['label'] is None for line in target.read_text().splitlines()))

    def test_same_capture_cannot_be_split_with_new_session_names(self):
        self.modify(lambda data: data['sessions'][2].update(capture_session_id=data['sessions'][0]['id']))
        with self.assertRaisesRegex(ValueError, 'physical capture'): run(self.manifest, self.root / 'prepared')

    def test_changed_evidence_blocks_training(self):
        (self.root / 'train-0/auth.log').write_text('Changed\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'): run(self.manifest, self.root / 'prepared')

    def test_unreviewed_or_ai_only_labels_rejected(self):
        self.modify(lambda data: data['sessions'][0].update(label_review={'reviewed': True, 'independent': False, 'method': 'prediction'}))
        with self.assertRaisesRegex(ValueError, 'independent label review'): run(self.manifest, self.root / 'prepared')

    def test_labelled_counters_cannot_differ_from_raw(self):
        data = read_json(self.manifest); session = data['sessions'][0]; path = self.root / session['records']
        labels = [json.loads(line) for line in path.read_text().splitlines()]
        labels[0]['flow']['bytes_toserver'] += 1
        path.write_text(''.join(json.dumps(row) + '\n' for row in labels)); session['sha256'] = sha256(path); write_json(self.manifest, data)
        with self.assertRaisesRegex(ValueError, 'differs from original'): run(self.manifest, self.root / 'prepared')

    def test_path_escape_rejected(self):
        self.modify(lambda data: data['sessions'][0].update(records='../outside.jsonl'))
        with self.assertRaisesRegex(ValueError, 'escapes'): run(self.manifest, self.root / 'prepared')

    def test_missing_attack_class_cannot_be_invented(self):
        data = read_json(self.manifest)
        data['sessions'] = [s for s in data['sessions'] if s['id'].endswith('-0')]
        write_json(self.manifest, data)
        with self.assertRaisesRegex(ValueError, 'at least one attack class'): run(self.manifest, self.root / 'prepared')

    def test_full_synthetic_prepare_train_export_has_only_observed_classes(self):
        from soc_ai.train import run as train
        from soc_ai.predict import Predictor
        from soc_ai import charts
        run(self.manifest, self.root / 'prepared')
        with patch.object(charts, 'epoch'), patch.object(charts, 'final'), contextlib.redirect_stdout(io.StringIO()):
            train(self.root / 'prepared', self.root / 'model', epochs=1, batch_size=8,
                  device_name='cpu', skip_baseline=True)
        predictor = Predictor(self.root / 'model'); predictor.verify()
        self.assertEqual(predictor.metadata['active_classes'], [True, False, True, False, False, False])
        self.assertTrue(predictor.metadata['synthetic_fixture'])
        self.assertTrue(predictor.metadata['training_provenance']['covers_all_training_sources'])


if __name__ == '__main__':
    unittest.main()
