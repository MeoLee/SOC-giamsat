import json
from pathlib import Path
import tempfile
import unittest

from lab_live import FlowObserver, LiveCollector


def flow(port=22, duration=True):
    return {'event_type': 'flow', 'flow_id': port, 'timestamp': '2026-10-14T14:01:00Z',
        'src_ip': '172.20.0.4', 'src_port': 44000, 'dest_ip': '172.20.0.3',
        'dest_port': port, 'proto': 'TCP', 'app_proto': 'ssh',
        'flow': {'start': '2026-10-14T14:00:00Z',
            'end': '2026-10-14T14:00:01Z' if duration else '2026-10-14T14:00:00Z',
            'pkts_toserver': 4, 'pkts_toclient': 3, 'bytes_toserver': 400,
            'bytes_toclient': 300, 'state': 'closed', 'reason': 'timeout'}}


class FakePredictor:
    directory = Path('fake-model')
    metadata = {'weights_sha256': 'test-hash', 'feature_hash': 'test-feature'}

    def __init__(self):
        self.calls = []

    def predict(self, batch):
        self.calls.append(batch)
        from soc_ai.flow import normalize
        output = []
        for e in batch:
            f = normalize(e)
            decision = 'out_of_training_scope' if f['duration_seconds'] <= 0 else 'possible_attack'
            result = {'record_id': e['record_id'], 'decision': decision, 'flow_id': str(e['flow_id'])}
            if decision == 'possible_attack':
                result['predicted_label'] = 'SSH-Patator'
            output.append(result)
        return output


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.eve = self.root / 'suricata-eve.jsonl'
        self.eve.touch()
        self.predictor = FakePredictor()
        self.observer = FlowObserver(self.root, self.predictor, ['172.20.0.3', '172.20.0.4'])

    def push(self, data):
        with self.eve.open('ab') as s:
            s.write(data)
        return self.observer.consume()

    def records(self, name):
        return [json.loads(x) for x in (self.root/name).read_text().splitlines()]

    def test_partial_line_waits_and_is_emitted_once(self):
        payload = (json.dumps(flow())+'\n').encode()
        self.push(payload[:100])
        self.assertEqual(self.records('ai-predictions.jsonl'), [])
        self.push(payload[100:])
        self.observer.consume()
        self.assertEqual(len(self.records('ai-predictions.jsonl')), 1)

    def test_alert_and_stats_not_sent_to_predictor(self):
        self.push(b'{"event_type":"stats"}\n{"event_type":"alert"}\n')
        self.assertEqual(self.predictor.calls, [])
        self.assertEqual(self.observer.counts['ignored_non_flow'], 2)

    def test_duplicate_observation_with_new_flow_id_not_repeated(self):
        a = flow(); b = {**a, 'flow_id': 777, 'timestamp': '2026-10-14T14:02:00Z'}
        self.push((json.dumps(a)+'\n'+json.dumps(b)+'\n').encode())
        self.assertEqual(len(self.records('ai-predictions.jsonl')), 1)
        self.assertEqual(self.observer.counts['duplicate_observation'], 1)

    def test_other_endpoints_filtered(self):
        a = flow(); a['dest_ip'] = '192.168.1.1'
        self.push((json.dumps(a)+'\n').encode())
        self.assertEqual(self.observer.counts['other_endpoints'], 1)
        self.assertEqual(self.records('ai-predictions.jsonl'), [])

    def test_all_flows_mode(self):
        self.observer.endpoints = None
        a = flow(); a['dest_ip'] = '192.168.1.1'
        self.push((json.dumps(a)+'\n').encode())
        self.assertEqual(len(self.records('ai-predictions.jsonl')), 1)

    def test_invalid_records_logged_without_stopping_next_valid_flow(self):
        self.push(('bad-json\n[]\n'+json.dumps(flow())+'\n').encode())
        self.assertEqual(len(self.records('ai-errors.jsonl')), 2)
        self.assertEqual(len(self.records('ai-predictions.jsonl')), 1)

    def test_missing_counters_not_filled_with_zero(self):
        a = flow(); del a['flow']['bytes_toserver']
        self.push((json.dumps(a)+'\n').encode())
        self.assertEqual(self.records('ai-predictions.jsonl'), [])
        self.assertEqual(len(self.records('ai-errors.jsonl')), 1)

    def test_single_packet_scope_is_preserved(self):
        self.push((json.dumps(flow(duration=False))+'\n').encode())
        self.assertEqual(self.records('ai-predictions.jsonl')[0]['decision'], 'out_of_training_scope')

    def test_prediction_not_promoted_to_training_label(self):
        self.push((json.dumps(flow())+'\n').encode())
        p = self.records('ai-predictions.jsonl')[0]
        self.assertTrue(p['prediction_is_not_ground_truth'])
        self.assertEqual(p['mode'], 'observe')
        self.assertEqual(p['model_weights_sha256'], 'test-hash')
        self.assertNotIn('label', p)

    def test_prediction_failure_stops_instead_of_silently_skipping(self):
        def broken(batch):
            raise RuntimeError('inference failed')
        self.predictor.predict = broken
        with self.assertRaisesRegex(RuntimeError, 'inference failed'):
            self.push((json.dumps(flow())+'\n').encode())

    def test_truncation_is_detected(self):
        self.push((json.dumps(flow())+'\n').encode())
        self.eve.write_bytes(b'')
        with self.assertRaisesRegex(RuntimeError, 'truncated'):
            self.observer.consume()

    def test_batches_are_bounded_and_input_identity_matches(self):
        self.push(('\n'.join(json.dumps(flow(p)) for p in range(1, 301))+'\n').encode())
        self.assertEqual([len(x) for x in self.predictor.calls], [128, 128, 44])
        inputs = self.records('ai-input-flows.jsonl'); outputs = self.records('ai-predictions.jsonl')
        self.assertEqual([x['record_id'] for x in inputs], [x['record_id'] for x in outputs])

    def test_collector_to_inference_preserves_three_raw_sources(self):
        from types import SimpleNamespace
        import sys
        from soc_live_collector import SOURCES

        class MockDockerCollector(LiveCollector):
            remote = {path: b'' for _, _, path, _ in SOURCES}

            def container_id(self, container):
                return container + ':id'

            def read(self, container, path, offset, count):
                data = self.remote[path]
                return '1:' + str(list(self.remote).index(path) + 1), len(data), data[offset:offset+count]

        args = SimpleNamespace(output_dir=str(self.root/'capture'), scenario_id='live-observe',
            interval=.1, grace=0, from_start=False, resume=None, docker_command=sys.executable,
            all_flows=False, endpoints=['172.20.0.3', '172.20.0.4'])
        live = MockDockerCollector(args, FakePredictor())
        self.addCleanup(live.lock_file.close)
        live.remote['/var/log/auth.log'] = b'accepted-raw-line\n'
        live.remote['/var/ossec/logs/alerts/alerts.json'] = b'{"rule":{"id":"119110"}}\n'
        payload = (json.dumps(flow())+'\n').encode()
        live.remote['/var/log/suricata/eve.json'] = payload
        live.poll()
        live.poll()
        self.assertEqual((live.folder/'suricata-eve.jsonl').read_bytes(), payload)
        self.assertEqual((live.folder/'ubuntu-auth.log').read_bytes(), b'accepted-raw-line\n')
        self.assertEqual(len((live.folder/'ai-predictions.jsonl').read_text().splitlines()), 1)
        state = json.loads((live.folder/'ai-session.json').read_text())
        self.assertTrue(state['correlation_implemented'])


if __name__ == '__main__':
    unittest.main()
