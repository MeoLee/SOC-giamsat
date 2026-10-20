"""Contracts for the native reader, independent of model/endpoint data."""
import json
import unittest
from urllib.parse import unquote

from chain_dashboard import detail_objects, latest_source_sort, objects
from chain_profile import PROFILE_ID, READER_ID, STEPS, FOLLOW_UP
from lab_risk import STAGE_LABELS


class ChainProfileTests(unittest.TestCase):
    def test_click_link_encodes_filter_and_keeps_current_host(self):
        index = next(r for r in detail_objects() if r['type'] == 'index-pattern')
        fmt = json.loads(index['attributes']['fieldFormatMap'])['data.chain_id']
        self.assertEqual(fmt['id'], 'url')
        params = fmt['params']
        self.assertNotIn('{{rawValue}}', params['urlTemplate'])
        self.assertIn('data.chain_id: "{{value}}"', unquote(params['urlTemplate']))
        self.assertTrue(params['urlTemplate'].startswith('dashboards#/view/'+PROFILE_ID))
        self.assertEqual(params['labelTemplate'], '{{value}}')
        self.assertTrue(params['openLinkInCurrentTab'])
        self.assertEqual(next(r for r in objects() if r['type']=='index-pattern')['attributes']['fieldFormatMap'], '{}')

    def test_every_stage_has_evidence_requirements_and_separate_hypothesis(self):
        self.assertEqual({r['key'] for r in STEPS}, set(STAGE_LABELS))
        self.assertEqual({r['after'] for r in FOLLOW_UP}, set(STAGE_LABELS))
        for row in STEPS:
            self.assertTrue(row['meaning'] and row['requirement'])
            self.assertEqual(row['technique'], STAGE_LABELS[row['key']][1] or 'unmapped')
        self.assertNotIn('T1071', {r['technique'] for r in STEPS})
        for row in FOLLOW_UP:
            self.assertTrue(row['label'].startswith('Giả thuyết'))
            self.assertTrue(row['detail'])

    def test_reader_honors_filters_sessions_and_historical_unmapped_indices(self):
        rows = detail_objects()
        reader = next(r for r in rows if r['id']==READER_ID)
        state = json.loads(reader['attributes']['visState'])
        self.assertEqual(state['type'], 'vega')
        spec = json.loads(state['params']['spec'])
        data = {r['name']:r for r in spec['data']}
        url = data['records']['url']
        self.assertTrue(url['%context%'])
        self.assertEqual(url['%timefield%'], 'timestamp')
        self.assertEqual(url['index'], 'wazuh-alerts-*')
        sessions = url['body']['aggs']['cases']['aggs']['chains']['aggs']['sessions']
        self.assertEqual(sessions['terms']['field'], 'data.session_id')
        self.assertEqual(sessions['aggs']['latest']['top_hits']['sort'], latest_source_sort())
        self.assertEqual(data['selected']['transform'][0]['expr'], "length(data('records')) == 1")
        self.assertEqual(url['body']['size'], 0)
        self.assertNotIn('http://', json.dumps(url))
        self.assertNotIn('https://', json.dumps(url))
        dashboard = next(r for r in rows if r['id']==PROFILE_ID)
        self.assertTrue(dashboard['attributes']['refreshInterval']['pause'])
        self.assertEqual(dashboard['attributes']['timeFrom'], 'now-30d')


if __name__ == '__main__':
    unittest.main()
