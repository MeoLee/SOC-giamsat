import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from lab_live import FlowObserver, parser
from lab_correlation import DEFAULTS, normalize_line, digest, build_cases
from live_config import load_config
from live_activity import Activities
from setup_wazuh import config_update, check_collisions, RULE_PATH, LOCATION
from wazuh_bridge import Publisher, make_event
from test_lab_live import FakePredictor, flow
from test_lab_correlation import auth, recon


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_cli_default_is_no_ip_filter(self):
        args = parser().parse_args(['--model', 'model'])
        self.assertIsNone(args.endpoints)
        observer = FlowObserver(self.root, FakePredictor())
        event = flow(); event['src_ip'] = '10.1.2.3'; event['dest_ip'] = '198.51.100.4'
        observer.process_lines([json.dumps(event).encode()])
        self.assertEqual(observer.counts['written_predictions'], 1)

    def test_mutually_exclusive_scope_options(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser().parse_args(['--model', 'model', '--all-flows', '--endpoints', 'a', 'b'])

    def test_multiple_sensors_preserve_provenance_and_identical_observations(self):
        observer = FlowObserver(self.root, FakePredictor())
        for name, container in [('one.jsonl', 'sensor-one'), ('two.jsonl', 'sensor-two')]:
            (self.root/name).write_text(json.dumps(flow())+'\n')
            observer.consume(name, container)
            observer.consume(name, container)
        rows = [json.loads(l) for l in (self.root/'ai-predictions.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual({r['source_container'] for r in rows}, {'sensor-one', 'sensor-two'})
        self.assertEqual(len({r['record_id'] for r in rows}), 2)

    def test_source_output_traversal_and_collision_rejected(self):
        for output in ('../bad', '..\\bad', 'C:bad', 'checkpoint.json', 'ai-predictions.jsonl', 'scenario-operation.json'):
            cfg = self.root/'config.json'
            cfg.write_text(json.dumps({'sources': [{'kind': 'eve', 'container': 's', 'path': '/eve', 'output': output}]}))
            with self.assertRaises(ValueError): load_config(cfg)

    def test_other_agent_auth_supported_without_attacker_ip_whitelist(self):
        config = {**DEFAULTS, 'all_agents': True, 'assets': [{'host': 'other-host', 'ips': ['10.0.0.8']}]}
        line = auth(10, host='other-host', ip='198.51.100.88')
        wrapper = {'agent': {'id': '099', 'name': 'other-host'}, 'full_log': line.decode()}
        event = normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), config)
        self.assertEqual(event['target_ip'], '10.0.0.8')
        self.assertEqual(event['source_ip'], '198.51.100.88')

    def test_wazuh_host_identity_mismatch_is_reported(self):
        wrapper = {'agent': {'id': '099', 'name': 'other-host'}, 'full_log': auth(10).decode()}
        with self.assertRaisesRegex(ValueError, 'identity'):
            normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), {**DEFAULTS, 'all_agents': True})

    def test_unknown_agent_is_not_dropped_and_unknown_target_ip_is_not_fabricated(self):
        line = auth(10, host='new-host')
        wrapper = {'agent': {'id': '123', 'name': 'new-host', 'ip': '172.18.0.99'}, 'full_log': line.decode()}
        e = normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), {**DEFAULTS, 'all_agents': True, 'assets': []})
        self.assertEqual(e['target_host'], 'new-host')
        self.assertIsNone(e['target_ip'])

    def test_ai_wazuh_output_cannot_feed_back_into_correlation(self):
        wrapper = {'agent': {'id': '001', 'name': 'ubuntu-endpoint'}, 'data': {'soc_ai_producer': 'soc-ai-live'},
                   'full_log': auth(10).decode()}
        self.assertIsNone(normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), DEFAULTS))

    def test_failed_delivery_survives_restart_and_deduplicates_enqueue(self):
        path = self.root/'outbox.sqlite'
        def broken(*_): raise RuntimeError('offline')
        event = make_event('model_summary', ['one'], source_ip='10.1.1.1')
        pub = Publisher(path, 'manager-original', broken)
        pub.enqueue(event); pub.enqueue(event); pub.flush(force=True)
        self.assertEqual(pub.pending, 1)
        self.assertEqual(pub.last_error, 'offline')
        pub.close()
        sent = []
        pub = Publisher(path, 'manager-new', lambda *args: sent.append(args))
        try:
            pub.flush(force=True)
            self.assertEqual(pub.pending, 0)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0][0], 'manager-original')
            pub.enqueue(event); pub.flush(force=True)
            self.assertEqual(len(sent), 1)
        finally: pub.close()

    def test_duplicate_publisher_cannot_share_outbox(self):
        path = self.root/'outbox.sqlite'
        pub = Publisher(path, 'manager', lambda *_: None)
        try:
            with self.assertRaisesRegex(RuntimeError, 'Another'):
                Publisher(path, 'manager', lambda *_: None)
        finally: pub.close()

    def test_thousand_scan_flows_one_summary_and_no_false_evidence(self):
        sent = []
        pub = Publisher(self.root/'outbox.sqlite', 'manager', lambda *args: sent.append(json.loads(args[1])))
        try:
            activities = Activities(self.root, pub)
            event = flow()
            with contextlib.redirect_stdout(io.StringIO()):
                for i in range(1000):
                    activities.prediction({**event, 'dest_port': i+1}, {'decision': 'possible_attack', 'predicted_label': 'PortScan', 'attack_score': .9})
                activities.flush(force=True)
            pub.flush(force=True)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]['flow_count'], 1000)
            self.assertNotIn('case_status', sent[0])
            self.assertTrue(sent[0]['prediction_is_not_ground_truth'])
        finally: pub.close()

    def test_below_threshold_flow_displayed_locally_but_not_published_as_attack(self):
        pub = Publisher(self.root/'outbox.sqlite', 'manager', lambda *_: None)
        try:
            activities = Activities(self.root, pub)
            activities.prediction(flow(), {'decision': 'below_alert_threshold', 'predicted_label': 'BENIGN'})
            with contextlib.redirect_stdout(io.StringIO()): activities.flush(force=True)
            self.assertEqual(pub.pending, 0)
            self.assertEqual(len(activities.path.read_text().splitlines()), 1)
        finally: pub.close()

    def test_case_transitions_publish_once_each_and_keep_evidence(self):
        from types import SimpleNamespace
        pub = Publisher(self.root/'outbox.sqlite', 'manager', lambda *_: None)
        try:
            acts = Activities(self.root, pub)
            config = {**DEFAULTS, 'all_agents': True}
            raw_events = [normalize_line('suricata-eve.jsonl', json.dumps(recon()).encode(), config)]
            raw_events += [normalize_line('ubuntu-auth.log', auth(t), config) for t in range(10, 18)]
            events = [{**e, 'event_id': digest(e), 'source_refs': []} for e in raw_events]
            engine = SimpleNamespace(events={e['event_id']: e for e in events}, cases=build_cases(events, config), snapshot=self.root/'cases.json')
            with contextlib.redirect_stdout(io.StringIO()):
                acts.correlation(engine); acts.correlation(engine)
                self.assertEqual(pub.pending, 1)
                e = normalize_line('ubuntu-auth.log', auth(20, 'Accepted'), config)
                events.append({**e, 'event_id': digest(e), 'source_refs': []})
                engine.cases = build_cases(events, config)
                acts.correlation(engine); acts.correlation(engine)
            self.assertEqual(pub.pending, 2)
            rows = [json.loads(p) for (p,) in pub.db.execute('SELECT payload FROM delivery')]
            self.assertEqual(rows[-1]['case_status'], 'suspicious_login_sequence')
            self.assertFalse(rows[-1]['confirmed_compromise'])
            self.assertTrue(rows[-1]['evidence_ids'])
        finally: pub.close()

    def test_manager_config_insert_is_idempotent_and_preserves_other_sections(self):
        old = '<ossec_config><global><jsonout_output>yes</jsonout_output></global></ossec_config>\n<ossec_config></ossec_config>'
        new = config_update(old)
        self.assertEqual(new.count(LOCATION), 1)
        self.assertEqual(config_update(new), new)
        self.assertIn('<jsonout_output>yes</jsonout_output>', new)

    def test_duplicate_or_wrong_format_ai_input_is_rejected(self):
        entry = '<localfile><log_format>json</log_format><location>'+LOCATION+'</location></localfile>'
        with self.assertRaises(ValueError): config_update('<ossec_config>'+entry*2+'</ossec_config>')
        with self.assertRaises(ValueError): config_update('<ossec_config>'+entry.replace('json', 'syslog', 1)+'</ossec_config>')

    def test_rule_id_collision_rejected_and_old_lab_rules_preserved(self):
        rules = Path(__file__).with_name('soc_ai_bridge_rules.xml').read_text()
        check_collisions(rules, {'old.xml': '<group><rule id="119110" level="8" /></group>'})
        with self.assertRaisesRegex(ValueError, 'collision'):
            check_collisions(rules, {'other.xml': '<group><rule id="119202" level="3" /></group>'})
        with self.assertRaisesRegex(ValueError, 'unmanaged'):
            check_collisions(rules, {RULE_PATH: '<group />'})

    def test_terminal_escape_in_log_is_neutralized(self):
        from live_activity import safe
        self.assertNotIn('\x1b', safe('bad\x1b[2J\nlog'))

    def test_installer_remote_payload_is_complete_python(self):
        from setup_wazuh import remote_script
        script = remote_script()
        compile(script, '<manager-installer>', 'exec')
        self.assertTrue(script.endswith('install_remote(json.load(sys.stdin))\n'))

    def test_configured_collectors_feed_both_sensors_without_pair_filter(self):
        import sys
        from types import SimpleNamespace
        from lab_live import LiveCollector
        class MockLive(LiveCollector):
            remote = {'/eve-one': b'', '/eve-two': b''}
            def container_id(self, container): return container+':id'
            def read(self, container, path, offset, count):
                data = self.remote[path]
                return '1:'+str(list(self.remote).index(path)), len(data), data[offset:offset+count]
        runtime = {'sources': [
            {'kind': 'eve', 'container': 'one', 'path': '/eve-one', 'output': 'one.jsonl'},
            {'kind': 'eve', 'container': 'two', 'path': '/eve-two', 'output': 'two.jsonl'}],
            'correlation': {'all_agents': True, 'assets': [], 'source_kinds': {'one.jsonl': 'eve', 'two.jsonl': 'eve'}}}
        args = SimpleNamespace(output_dir=str(self.root/'capture'), scenario_id='live-observe', interval=.1,
            grace=0, from_start=False, resume=None, docker_command=sys.executable,
            all_flows=False, endpoints=None, runtime=runtime,
            sources=[('eve'+str(i), s['container'], s['path'], s['output']) for i,s in enumerate(runtime['sources'])])
        live = MockLive(args, FakePredictor())
        try:
            one = flow(); one['dest_ip'] = '198.51.100.10'
            two = flow(); two['src_ip'] = '10.0.0.99'
            live.remote['/eve-one'] = (json.dumps(one)+'\n').encode()
            live.remote['/eve-two'] = (json.dumps(two)+'\n').encode()
            with contextlib.redirect_stdout(io.StringIO()): live.poll()
            self.assertEqual(live.observer.counts['written_predictions'], 2)
            self.assertEqual(live.observer.counts['other_endpoints'], 0)
            state = json.loads((live.folder/'ai-session.json').read_text())
            self.assertIsNone(state['endpoints'])
            self.assertEqual(len(state['sources']), 2)
        finally: live.lock_file.close()


if __name__ == '__main__': unittest.main()
