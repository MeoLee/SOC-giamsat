import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from chain_dashboard import (objects, detail_objects, encoded, COLUMNS, INDEX_ID, TABLE_ID,
                             DASHBOARD_ID, DETAIL_DASHBOARD_ID, CONTEXT_ID, EVIDENCE_ID, QUERY)
from lab_correlation import build_cases, DEFAULTS
from lab_risk import case_assessment
from live_activity import Activities
from test_lab_correlation import sequence
from wazuh_bridge import Publisher


class ChainDashboardTests(unittest.TestCase):
    def test_chain_transition_keeps_identity_and_existing_scores(self):
        events = sequence()
        before = build_cases(events[:-1], DEFAULTS)[0]
        after = build_cases(events, DEFAULTS)[0]
        self.assertEqual(before['chain_id'], after['chain_id'])
        self.assertEqual((before['risk_score'], after['risk_score']), (75, 95))
        self.assertEqual((before['attack_chain_stage_count'], after['attack_chain_stage_count']), (2, 3))
        self.assertEqual(after['risk_score_base'], 85)
        self.assertEqual(after['risk_score_recon_bonus'], 10)
        self.assertFalse(after['confirmed_compromise'])
        self.assertFalse(after['risk_is_probability'])
        self.assertFalse(after['attack_chain_is_causal_proof'])

    def test_technique_candidates_follow_evidence_not_assumed_ssh_commands(self):
        case = build_cases(sequence(), DEFAULTS)[0]
        self.assertEqual(case['techniques'], 'T1046;T1110.001;T1078')
        self.assertTrue(case['techniques_are_hypotheses'])
        self.assertNotIn('T1059', case['techniques'])
        self.assertNotIn('T1105', case['techniques'])
        self.assertNotIn('T1071', case['techniques'])
        self.assertIn('compromise unconfirmed', case['conclusion'])
        self.assertNotIn('Full kill chain', case['attack_summary'])
        self.assertEqual([n['candidate_technique'] for n in case['attack_chain_graph']['nodes']],
                         ['T1046', 'T1110.001', 'T1078'])
        other = {**case, 'case_id': 'another-case'}
        self.assertNotEqual(case['chain_id'], case_assessment(other)['chain_id'])

    def test_unknown_stage_cannot_be_presented_as_execution_without_a_detector(self):
        case = build_cases(sequence(), DEFAULTS)[0]
        case['stages'] = [{**case['stages'][0], 'name': 'unverified_command_execution'}]
        with self.assertRaises(KeyError):
            case_assessment(case)

    def test_investigation_details_follow_unique_evidence_and_source_event_times(self):
        case = build_cases(sequence(), DEFAULTS)[0]
        self.assertEqual(case['chain_evidence_count'], 29)
        self.assertEqual(case['chain_password_failure_count'], 8)
        self.assertEqual(case['chain_duration_seconds'], 20)
        self.assertEqual(len(case['chain_stage_details'].splitlines()), 3)
        self.assertIn('distinct ports=20; threshold=20 within 10s', case['chain_stage_details'])
        self.assertIn('password failures=8; threshold=8 within 60s', case['chain_stage_details'])
        # Duplicate references are not new evidence. Different offsets must be
        # ordered as instants, not by their text representation.
        changed = {**case, 'stages': [dict(s) for s in case['stages']]}
        changed['stages'][0]['evidence_ids'] = case['stages'][0]['evidence_ids'] * 2
        changed['stages'][0]['start_time'] = '2026-10-14T21:00:00+07:00'
        details = case_assessment(changed)
        self.assertEqual(details['chain_evidence_count'], 29)
        self.assertEqual(details['chain_duration_seconds'], 20)
        self.assertEqual(details['chain_started_at'], '2026-10-14T21:00:00+07:00')
        self.assertIn('20 evidence event(s)', details['chain_stage_details'])

    def test_published_chain_contains_dashboard_fields_and_separate_history_revisions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            publisher = Publisher(root/'outbox.sqlite', 'manager', lambda *_: None)
            self.addCleanup(publisher.close)
            acts = Activities(root, publisher)
            events = sequence()
            engine = SimpleNamespace(events={e['event_id']: e for e in events}, web_activity=[],
                                     cases=build_cases(events[:-1], DEFAULTS), snapshot=root/'cases.json')
            with contextlib.redirect_stdout(io.StringIO()):
                acts.correlation(engine)
                engine.cases = build_cases(events, DEFAULTS)
                acts.correlation(engine)
                acts.correlation(engine)
            rows = [json.loads(row[0]) for row in publisher.db.execute('SELECT payload FROM delivery ORDER BY rowid')]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['chain_id'], rows[1]['chain_id'])
            self.assertEqual([r['risk_score'] for r in rows], [75, 95])
            self.assertNotEqual(rows[0]['event_id'], rows[1]['event_id'])
            for field, _ in COLUMNS:
                if field.startswith('data.'):
                    self.assertIn(field.removeprefix('data.'), rows[-1])
            self.assertIsInstance(rows[-1]['attack_chain_json'], str)
            self.assertEqual(rows[-1]['chain_evidence_count'], 29)
            self.assertEqual(rows[-1]['chain_password_failure_count'], 8)
            self.assertIn('3. Login after password guessing', rows[-1]['chain_stage_details'])
            self.assertLess(len(json.dumps(rows[-1]).encode()), 6000)

    def test_saved_objects_are_deterministic_and_all_references_resolve(self):
        rows = objects()
        bundled = Path(__file__).with_name('dashboards')/'soc-ai-attack-chain.ndjson'
        self.assertEqual(bundled.read_text(), ''.join(encoded(row)+'\n' for row in rows))
        identities = {(row['type'], row['id']) for row in rows}
        self.assertEqual(len(identities), 5)
        self.assertEqual(len(identities), len(rows))
        for row in rows:
            for ref in row['references']:
                self.assertIn((ref['type'], ref['id']), identities)
        self.assertFalse(any(r['type'] in ('config', 'index-template') for r in rows))
        self.assertEqual(next(r for r in rows if r['id'] == INDEX_ID)['attributes']['title'], 'wazuh-alerts-*')
        self.assertIn('data.chain_id: *', QUERY)

    def test_investigation_import_keeps_existing_dashboard_and_references_separate(self):
        rows = detail_objects()
        bundled = Path(__file__).with_name('dashboards')/'soc-ai-chain-investigation.ndjson'
        self.assertEqual(bundled.read_text(), ''.join(encoded(row)+'\n' for row in rows))
        identities = {(r['type'], r['id']) for r in rows}
        self.assertEqual(len(identities), 7)
        self.assertTrue(identities.isdisjoint({(r['type'], r['id']) for r in objects()}))
        for row in rows:
            for ref in row['references']:
                self.assertIn((ref['type'], ref['id']), identities)
        context = next(r for r in rows if r['id'] == CONTEXT_ID)
        aggs = json.loads(context['attributes']['visState'])['aggs']
        self.assertEqual(aggs[0]['params']['field'], 'data.chain_id')
        for metric in aggs[1:]:
            self.assertEqual(metric['type'], 'top_hits')
            self.assertEqual(metric['params']['size'], 1)
            self.assertEqual(metric['params']['sortField'], 'data.event_time')
            self.assertEqual(metric['params']['sortOrder'], 'desc')
        evidence = next(r for r in rows if r['id'] == EVIDENCE_ID)
        self.assertIn('data.chain_stage_details', evidence['attributes']['columns'])
        self.assertIn('data.evidence_file', evidence['attributes']['columns'])
        dashboard = next(r for r in rows if r['id'] == DETAIL_DASHBOARD_ID)
        self.assertEqual(len(json.loads(dashboard['attributes']['panelsJSON'])), 5)
        self.assertEqual(dashboard['attributes']['refreshInterval'], {'pause': False, 'value': 1000})
        self.assertFalse(any(r['type'] in ('config', 'index-template') for r in rows))
        summary = next(r for r in rows if r['id'] == 'soc-ai-chain-investigation-summary-v1')
        self.assertTrue(all(a['params']['sortField'] == 'data.event_time'
                            for a in json.loads(summary['attributes']['visState'])['aggs'][1:]))

    def test_table_uses_latest_per_chain_instead_of_sum_or_average_of_revisions(self):
        rows = objects()
        table = next(r for r in rows if r['id'] == TABLE_ID)
        state = json.loads(table['attributes']['visState'])
        buckets = [a for a in state['aggs'] if a['schema'] == 'bucket']
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0]['params']['field'], 'data.chain_id')
        for metric in (a for a in state['aggs'] if a['schema'] == 'metric'):
            self.assertEqual(metric['type'], 'top_hits')
            self.assertEqual(metric['params']['size'], 1)
            self.assertEqual(metric['params']['sortField'], 'timestamp')
            self.assertEqual(metric['params']['sortOrder'], 'desc')
        self.assertFalse(state['params']['showTotal'])
        dashboard = next(r for r in rows if r['id'] == DASHBOARD_ID)
        self.assertEqual(dashboard['attributes']['refreshInterval'], {'pause': False, 'value': 1000})


if __name__ == '__main__':
    unittest.main()
