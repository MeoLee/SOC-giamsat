import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from context_runtime import ContextJournal
from lab_live import LiveCollector, parser
from soc_ai.common import read_json
from test_lab_live import FakePredictor, flow
from test_lab_web import tsv


class ContextRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = [{'kind': 'eve', 'container': 'sensor', 'path': '/eve', 'output': 'eve.jsonl'},
                        {'kind': 'web', 'container': 'sensor', 'path': '/apache.tsv', 'output': 'apache.tsv'}]
        for source in self.sources: (self.root / source['output']).touch()

    def test_partial_flow_then_sweep_triggers_shadow_with_raw_offset(self):
        journal = ContextJournal(self.root, self.sources)
        first = json.dumps(flow()).encode()
        (self.root / 'eve.jsonl').write_bytes(first[:30]); journal.consume()
        self.assertFalse(journal.write_status('completed')['complete'])
        events = []
        for port in range(1, 22):
            event = flow(30000 + port); event['dest_port'] = port
            event['flow']['pkts_toserver'] = 1; event['flow']['pkts_toclient'] = 0
            events.append(event)
        with (self.root / 'eve.jsonl').open('ab') as stream:
            stream.write(first[30:] + b'\n' + b''.join((json.dumps(e) + '\n').encode() for e in events))
        journal.consume(); result = journal.write_status('completed')
        self.assertTrue(result['complete'])
        self.assertEqual(result['signals'][0]['kind'], 'context.distinct_port_sweep')
        updates = [json.loads(line) for line in journal.signals.read_text().splitlines()]
        self.assertTrue(all(row['publication_enabled'] is False and row['mode'] == 'shadow' for row in updates))
        ref = updates[0]['trigger_raw_ref']
        raw = (self.root / ref['source_file']).read_bytes()[ref['byte_offset']:].splitlines()[0]
        import hashlib
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ref['raw_sha256'])

    def test_invalid_json_and_detector_rejection_are_visible_and_referenced(self):
        journal = ContextJournal(self.root, self.sources)
        event = flow(); del event['flow']['bytes_toclient']
        (self.root / 'eve.jsonl').write_text('not json\n' + json.dumps(event) + '\n')
        journal.consume(); result = journal.write_status('completed')
        self.assertFalse(result['complete']); self.assertTrue(result['quality']['incomplete'])
        self.assertEqual(result['runtime_counts']['invalid_input_records'], 1)
        self.assertEqual(result['runtime_counts']['rejected_context_records'], 1)
        errors = [json.loads(line) for line in journal.errors.read_text().splitlines()]
        self.assertEqual(len(errors), 2)
        self.assertEqual(errors[1]['byte_offset'], len('not json\n'))

    def test_disabled_http_is_not_consumed_or_treated_as_model_coverage(self):
        journal = ContextJournal(self.root, self.sources)
        (self.root / 'apache.tsv').write_text('bad web row\n')
        journal.consume(); result = journal.write_status('completed')
        self.assertTrue(result['complete'])
        self.assertEqual([s['kind'] for s in result['sources']], ['eve'])

    def test_http_request_count_works_independent_of_correlation(self):
        journal = ContextJournal(self.root, self.sources, {'http_enabled': True, 'http_threshold': 3})
        payload = []
        for i in range(4):
            fields = tsv().decode().strip().split('\t'); fields[0] = str(int(fields[0]) + i)
            fields[1] = str(int(fields[1]) + i); payload.append('\t'.join(fields) + '\n')
        (self.root / 'apache.tsv').write_text(''.join(payload))
        journal.consume(); result = journal.write_status('completed')
        signal = next(s for s in result['signals'] if s['kind'] == 'context.http_request_rate')
        self.assertEqual(signal['request_count'], 4)
        self.assertFalse(result['publication_enabled'])

    def test_bad_prediction_input_cannot_finish_as_complete_live_session(self):
        class MockLive(LiveCollector):
            remote = {'/eve': b''}
            def container_id(self, container): return container + ':id'
            def read(self, container, path, offset, count):
                data = self.remote[path]; return '1:1', len(data), data[offset:offset+count]
        source = self.sources[0]
        runtime = {'sources': [source], 'correlation': {}, 'context': {'enabled': True}}
        args = SimpleNamespace(output_dir=str(self.root / 'live'), scenario_id='test', interval=.1,
                               grace=0, from_start=False, resume=None, docker_command=sys.executable,
                               all_flows=True, endpoints=None, runtime=runtime, no_correlation=True,
                               sources=[('eve', source['container'], source['path'], source['output'])])
        live = MockLive(args, FakePredictor()); self.addCleanup(live.lock_file.close)
        live.remote['/eve'] = b'not-json\n'
        with contextlib.redirect_stdout(io.StringIO()): live.poll()
        live.state['status'] = 'completed'
        status = live.write_status('completed')
        self.assertEqual(status['status'], 'degraded'); self.assertFalse(status['complete'])
        self.assertTrue(status['context_shadow']['quality']['incomplete'])
        self.assertFalse(status['context_shadow']['complete'])

    def test_context_scope_flags_are_explicit_and_mutually_exclusive(self):
        self.assertIsNone(parser().parse_args(['--model', 'model']).context)
        self.assertTrue(parser().parse_args(['--model', 'model', '--context']).context)
        self.assertFalse(parser().parse_args(['--model', 'model', '--no-context']).context)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser().parse_args(['--model', 'model', '--context', '--no-context'])


if __name__ == '__main__':
    unittest.main()
