from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lab_correlation import Correlator, DEFAULTS, normalize_line
from lab_doctor import diagnose
from live_config import load_config
from soc_ai.flow import FEATURE_HASH, identifier, normalize
from test_lab_correlation import auth, recon, syn
from test_lab_live import flow


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def config_file(self, data):
        path = self.root / 'config.json'
        path.write_text(json.dumps(data))
        return path

    def test_ambiguous_asset_address_rejected_including_ipv6_equivalents(self):
        assets = [{'host': 'one', 'ips': ['2001:db8::1']},
                  {'host': 'two', 'ips': ['2001:0db8:0:0:0:0:0:1']}]
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            load_config(self.config_file({'assets': assets}))

    def test_windows_case_collisions_and_device_names_rejected(self):
        source = {'kind': 'eve', 'container': 'sensor', 'path': '/eve', 'output': 'Eve.jsonl'}
        for output in ('eve.jsonl', 'NUL.jsonl', 'COM1', 'AI-predictions.jsonl', 'log.', 'log\nname'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                load_config(self.config_file({'sources': [source, {**source, 'path': '/other', 'output': output}]}))

    def test_duplicate_real_source_rejected_even_with_different_output(self):
        source = {'kind': 'eve', 'container': 'sensor', 'path': '/var/log/eve', 'output': 'one.jsonl'}
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            load_config(self.config_file({'sources': [source, {**source, 'path': '/var/log/./eve', 'output': 'two.jsonl'}]}))

    def test_container_options_and_boolean_threshold_rejected(self):
        for config in ({'wazuh_manager': '--privileged'}, {'correlation': {'failure_threshold': True}},
                       {'sources': [None]}, [], {'assets': {'host': 'one'}}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                load_config(self.config_file(config))

    def test_replay_source_traversal_rejected_before_reading(self):
        with self.assertRaises(ValueError):
            Correlator(self.root, self.root / 'out', {'source_kinds': {'../outside': 'auth'}})
        self.assertFalse((self.root / 'out').exists())

    def test_native_big_id_and_ipv6_preserved_in_wazuh_decoded_eve(self):
        event = recon(fid=9007199254740993, dst='2001:db8::3')
        event.update(src_ip='2001:db8::4', src_port=44000)
        data = deepcopy(event)
        data.update(flow_id=str(event['flow_id']), src_port='44000', dest_port='55')
        wrapper = {'agent': {'id': '009', 'name': 'sensor', 'ip': '10.1.1.1'},
                   'timestamp': '2030-01-01T00:00:00Z', 'data': data}
        direct = normalize_line('suricata-eve.jsonl', json.dumps(event).encode(), DEFAULTS)
        decoded = normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), {**DEFAULTS, 'all_agents': True})
        self.assertEqual(direct, decoded)
        self.assertEqual(decoded['flow_id'], '9007199254740993')
        self.assertEqual(decoded['target_ip'], '2001:db8::3')
        self.assertEqual(decoded['source_port'], 44000)
        self.assertTrue(decoded['event_time'].startswith('2026-'))

    def test_missing_native_eve_time_is_reported_without_wrapper_time_fallback(self):
        data = recon(); del data['timestamp']
        wrapper = {'agent': {'id': '001', 'name': 'ubuntu-endpoint'}, 'data': data,
                   'timestamp': '2026-10-19T00:00:00Z'}
        engine = Correlator(self.root, self.root / 'out')
        engine.process('wazuh-alerts.jsonl', json.dumps(wrapper).encode())
        self.assertEqual(engine.counts['invalid_source_records'], 1)
        self.assertEqual(len(engine.events), 0)
        data['timestamp'] = None
        engine.process('wazuh-alerts.jsonl', json.dumps(wrapper).encode())
        self.assertEqual(engine.counts['invalid_source_records'], 2)

    def test_float_and_boolean_ids_rejected_without_changing_feature_contract(self):
        self.assertEqual(FEATURE_HASH, '5e023c54512136448cfb711ab424a19c5ba2c9bf3240c0543c8fc4d0c1b0a065')
        for value in (float(9007199254740993), True, -1, ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                identifier(value)
        event = flow(); event['flow_id'] = 1.5
        with self.assertRaises(ValueError): normalize(event)
        event = flow(); event['timestamp'] = None
        with self.assertRaises(ValueError): normalize(event)

    def test_late_cross_poll_chain_deduplicates_decoded_wrapper_and_keeps_offsets(self):
        config = load_config(self.config_file({'sources': [
            {'kind': 'auth', 'container': 'ubuntu-endpoint', 'path': '/var/log/auth.log', 'output': 'auth.log'},
            {'kind': 'eve', 'container': 'ubuntu-endpoint', 'path': '/var/log/eve.json', 'output': 'eve.jsonl'},
            {'kind': 'wazuh', 'container': 'manager', 'path': '/alerts.json', 'output': 'wazuh.jsonl'}],
            'assets': [{'host': 'ubuntu-endpoint', 'ips': ['172.20.0.3']}]}))['correlation']
        for name in config['source_kinds']: (self.root / name).touch()
        engine = Correlator(self.root, self.root / 'out', config)
        # Success arrives first; failures are split across two polls and a partial line.
        success = auth(20, 'Accepted')
        (self.root / 'auth.log').write_bytes(success + b'\r\n' + auth(10) + b'\n' + auth(11)[:30])
        engine.consume()
        self.assertEqual(engine.cases, [])
        with (self.root / 'auth.log').open('ab') as stream:
            stream.write(auth(11)[30:] + b'\n')
            stream.write(b'\n'.join(auth(t) for t in range(12, 18)) + b'\n')
        engine.consume()
        self.assertEqual(engine.cases[0]['status'], 'suspicious_login_sequence')
        probes=[syn(port=port) for port in range(1,21)]
        (self.root / 'eve.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in probes))
        (self.root / 'wazuh.jsonl').write_text(''.join(json.dumps({
            'agent':{'id':'001','name':'ubuntu-endpoint'},'data':e})+'\n' for e in probes))
        engine.consume(); engine.consume()
        self.assertEqual(len(engine.events), 29)
        self.assertEqual(engine.counts['duplicate_views'], 20)
        self.assertEqual(len(engine.cases), 1)
        self.assertEqual([s['name'] for s in engine.cases[0]['stages']],
                         ['possible_recon', 'repeated_auth_failures', 'auth_success_after_failures'])
        first_failure = next(e for e in engine.events.values() if e['kind'] == 'auth.failure' and '14:00:10' in e['event_time'])
        ref = first_failure['source_refs'][0]
        self.assertEqual(ref['byte_offset'], len(success) + 2)
        self.assertEqual(ref['source_path'], '/var/log/auth.log')
        raw = (self.root / ref['source_file']).read_bytes()[ref['byte_offset']:].splitlines()[0]
        import hashlib
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ref['raw_sha256'])

    def test_doctor_does_not_call_docker_without_runtime(self):
        def forbidden(*args, **kwargs): raise AssertionError('Docker must not be called')
        report = diagnose(self.config_file({}), runner=forbidden)
        self.assertTrue(report['checks_passed'])
        self.assertFalse(report['lab_end_to_end_verified'])

    def test_doctor_reports_each_missing_source_and_never_modifies_container(self):
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'missing')
        report = diagnose(self.config_file({}), runtime=True, bridge=True, runner=runner)
        self.assertFalse(report['checks_passed'])
        self.assertEqual(len(report['checks']), 7)
        self.assertTrue(all(c[0:2] == ['docker', 'exec'] for c in calls))
        self.assertEqual({c[3] for c in calls}, {'stat', 'pgrep', 'python3', 'cat'})

    def test_doctor_accepts_empty_endpoint_log_and_nonempty_log_by_inode_mode(self):
        config = self.config_file({'sources': [
            {'kind': 'endpoint', 'container': 'ubuntu-endpoint',
             'path': '/var/log/soc-lab/endpoint-probe.jsonl', 'output': 'endpoint-probe.jsonl'},
            {'kind': 'auth', 'container': 'ubuntu-endpoint',
             'path': '/var/log/auth.log', 'output': 'ubuntu-auth.log'}]})
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            # 0x81a0 is S_IFREG | 0640. Size zero does not change the type.
            size = 0 if args[-1].endswith('endpoint-probe.jsonl') else 123
            return SimpleNamespace(returncode=0, stdout=f'81a0|147|324032|{size}\n'.encode(), stderr=b'')
        report = diagnose(config, runtime=True, runner=runner)
        self.assertTrue(report['checks_passed'], report)
        self.assertEqual([c['detail']['bytes'] for c in report['checks'][1:]], [0,123])
        self.assertTrue(all(args[3:6] == ['stat','-Lc','%f|%d|%i|%s'] for args in calls))
        self.assertFalse(report['lab_end_to_end_verified'])
        self.assertFalse(report['checks'][1]['detail']['activity_or_capture_coverage_established'])

    def test_doctor_still_rejects_directories_pipes_devices_and_invalid_stat(self):
        config = self.config_file({'sources': [{'kind':'endpoint','container':'ubuntu-endpoint',
            'path':'/var/log/soc-lab/endpoint-probe.jsonl','output':'endpoint-probe.jsonl'}]})
        for mode in ('41ed', '11a4', 'c1ed', '21b6', '61a4', 'invalid'):
            with self.subTest(mode=mode):
                def runner(args, **kwargs):
                    return SimpleNamespace(returncode=0,stdout=(mode+'|147|324032|0\n').encode(),stderr=b'')
                report=diagnose(config,runtime=True,runner=runner)
                self.assertFalse(report['checks_passed'])
                self.assertFalse(report['checks'][1]['passed'])


if __name__ == '__main__':
    unittest.main()
