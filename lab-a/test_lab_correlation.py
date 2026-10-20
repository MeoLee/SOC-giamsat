from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from lab_correlation import Correlator, SOURCES, DEFAULTS, build_cases, normalize_line, digest

BASE = datetime(2026, 10, 14, 14, 0, tzinfo=timezone.utc)


def time_at(seconds):
    return (BASE+timedelta(seconds=seconds)).isoformat()


def auth(seconds, outcome='Failed', user='labuser', ip='172.20.0.4', host='ubuntu-endpoint'):
    return f'{time_at(seconds)} {host} sshd-session[123]: {outcome} password for {user} from {ip} port 40000 ssh2'.encode()


def recon(seconds=0, fid=999, dst='172.20.0.3'):
    return {'timestamp': time_at(seconds), 'event_type': 'alert', 'flow_id': fid,
        'src_ip': '172.20.0.4', 'src_port': 44000, 'dest_ip': dst, 'dest_port': 55,
        'alert': {'signature_id': 9900001}}


def syn(seconds=0,port=1,fid=None,dst='172.20.0.3'):
    return {**recon(seconds,fid if fid is not None else port,dst),
        'proto':'TCP','src_port':44000+port,'dest_port':port,
        'alert':{'signature_id':9900003,'signature':'SOC LAB TCP SYN observation','severity':3}}


def scan(seconds=0,dst='172.20.0.3'):
    return [normalized('suricata-eve.jsonl',json.dumps(syn(seconds,port,dst=dst)).encode())
            for port in range(1,21)]


def normalized(source, line):
    event = normalize_line(source, line, DEFAULTS)
    return {**event, 'event_id': 'event:'+digest(event), 'source_refs': []}


def sequence(success_time=20, success_user='labuser', success_ip='172.20.0.4', host='ubuntu-endpoint',
             recon_time=0,recon_dst='172.20.0.3'):
    events = scan(recon_time,recon_dst)
    events += [normalized('ubuntu-auth.log', auth(t, host=host)) for t in range(10, 18)]
    events.append(normalized('ubuntu-auth.log', auth(success_time, 'Accepted', success_user, success_ip, host)))
    return events


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for n in SOURCES:
            (self.root/n).touch()

    def test_success_only_creates_no_incident(self):
        e = normalized('ubuntu-auth.log', auth(20, 'Accepted'))
        self.assertEqual(build_cases([e], DEFAULTS), [])

    def test_one_failure_then_success_no_bruteforce(self):
        events = [normalized('ubuntu-auth.log', auth(10)), normalized('ubuntu-auth.log', auth(20, 'Accepted'))]
        self.assertEqual(build_cases(events, DEFAULTS), [])

    def test_full_chain_has_evidence_but_does_not_prove_compromise(self):
        cases = build_cases(sequence(), DEFAULTS)
        self.assertEqual(len(cases), 1)
        c = cases[0]
        self.assertEqual([s['name'] for s in c['stages']],
                         ['possible_recon', 'repeated_auth_failures', 'auth_success_after_failures'])
        self.assertEqual(c['stages'][1]['failure_count'], 8)
        self.assertFalse(c['confirmed_compromise'])
        self.assertIsNone(c['training_label'])

    def test_success_after_300_seconds_does_not_complete_chain(self):
        c = build_cases(sequence(success_time=318), DEFAULTS)[0]
        self.assertEqual(c['status'], 'possible_password_guessing')

    def test_success_at_window_boundary_is_included(self):
        self.assertEqual(build_cases(sequence(success_time=317), DEFAULTS)[0]['status'], 'suspicious_login_sequence')

    def test_same_timestamp_does_not_prove_success_after_burst(self):
        cases = build_cases(sequence(success_time=17), DEFAULTS)
        self.assertTrue(all(c['status'] != 'suspicious_login_sequence' for c in cases))

    def test_failed_publickey_is_not_password_guessing(self):
        events = [normalized('ubuntu-auth.log', auth(t).replace(b'Failed password', b'Failed publickey')) for t in range(10, 18)]
        self.assertEqual(build_cases(events, DEFAULTS), [])

    def test_different_source_success_not_linked(self):
        cases = build_cases(sequence(success_ip='172.20.0.99'), DEFAULTS)
        self.assertTrue(all(c['status'] != 'suspicious_login_sequence' for c in cases))

    def test_different_account_success_not_linked(self):
        cases = build_cases(sequence(success_user='another-user'), DEFAULTS)
        self.assertTrue(all(c['status'] != 'suspicious_login_sequence' for c in cases))

    def test_different_target_host_not_linked_to_scan(self):
        cases = build_cases(sequence(host='another-host'), DEFAULTS)
        self.assertEqual(len(cases), 2)
        full = next(c for c in cases if c['username'])
        self.assertNotIn('possible_recon', [s['name'] for s in full['stages']])

    def test_wrong_scan_target_not_linked(self):
        events = sequence(recon_dst='172.20.0.99')
        cases = build_cases(events, DEFAULTS)
        self.assertEqual(len(cases), 2)

    def test_recon_after_failures_does_not_become_preceding_stage(self):
        events = sequence(recon_time=30)
        full = next(c for c in build_cases(events, DEFAULTS) if c['username'])
        self.assertEqual(len(full['stages']), 2)

    def test_scan_outside_ten_minute_window_not_linked(self):
        events = sequence(recon_time=-591)
        full = next(c for c in build_cases(events, DEFAULTS) if c['username'])
        self.assertEqual(len(full['stages']), 2)

    def test_failures_spread_outside_sixty_seconds_no_burst(self):
        events = [normalized('ubuntu-auth.log', auth(t)) for t in range(0, 161, 20)]
        self.assertEqual(build_cases(events, DEFAULTS), [])

    def test_out_of_order_replay_matches_sorted(self):
        events = sequence()
        self.assertEqual(build_cases(events, DEFAULTS), build_cases(list(reversed(events)), DEFAULTS))

    def test_timezone_offsets_resolve_to_same_event(self):
        line = auth(10)
        shifted = line.replace(time_at(10).encode(), b'2026-10-14T10:00:10-04:00')
        self.assertEqual(normalized('ubuntu-auth.log', line), normalized('ubuntu-auth.log', shifted))

    def test_naive_timestamp_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Timezone'):
            normalize_line('ubuntu-auth.log', auth(10).replace(b'+00:00', b''), DEFAULTS)

    def test_legacy_auth_format_reported_instead_of_silently_ignored(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported SSH'):
            normalize_line('ubuntu-auth.log', b'Oct 14 14:00:00 ubuntu-endpoint sshd[123]: Failed password for labuser from 172.20.0.4 port 40000 ssh2', DEFAULTS)

    def test_wazuh_and_auth_not_double_counted(self):
        engine = Correlator(self.root, self.root/'out')
        for t in range(10, 14):
            line = auth(t)
            engine.process('ubuntu-auth.log', line)
            wrapper = {'agent': {'id': '001', 'name': 'ubuntu-endpoint'},
                'rule': {'id': '119100'}, 'full_log': line.decode()}
            engine.process('wazuh-alerts.jsonl', json.dumps(wrapper).encode())
        self.assertEqual(len(engine.events), 4)
        self.assertEqual(engine.counts['duplicate_views'], 4)
        self.assertEqual(build_cases(list(engine.events.values()), DEFAULTS), [])

    def test_suricata_and_wazuh_same_scan_not_double_counted(self):
        engine = Correlator(self.root, self.root/'out')
        payload = json.dumps(recon())
        engine.process('suricata-eve.jsonl', payload.encode())
        engine.process('wazuh-alerts.jsonl', json.dumps({'agent': {'id': '001', 'name': 'ubuntu-endpoint'},
            'rule': {'id': '119110'}, 'full_log': payload}).encode())
        self.assertEqual(len(engine.events), 1)
        self.assertEqual(len(next(iter(engine.events.values()))['source_refs']), 2)

    def test_two_scans_grouped_without_thousands_of_ai_alerts(self):
        events = scan(0)+scan(30)
        cases = build_cases(events, DEFAULTS)
        self.assertEqual(len(cases), 1)
        self.assertEqual(len(cases[0]['stages'][0]['evidence_ids']), 40)

    def test_mlp_label_does_not_create_auth_evidence(self):
        prediction = {'decision': 'possible_attack', 'predicted_label': 'SSH-Patator'}
        self.assertIsNone(normalize_line('suricata-eve.jsonl', json.dumps(prediction).encode(), DEFAULTS))

    def test_partial_host_line_and_replay_once(self):
        engine = Correlator(self.root, self.root/'out')
        payload = auth(10, 'Accepted')+b'\n'
        path = self.root/'ubuntu-auth.log'
        path.write_bytes(payload[:50]); engine.consume()
        self.assertEqual(len(engine.events), 0)
        with path.open('ab') as stream:
            stream.write(payload[50:])
        engine.consume(); engine.consume()
        self.assertEqual(len(engine.events), 1)
        self.assertEqual(engine.cases, [])

    def test_wazuh_other_agent_rejected(self):
        wrapper = {'agent': {'id': '002', 'name': 'other'}, 'full_log': auth(10).decode()}
        self.assertIsNone(normalize_line('wazuh-alerts.jsonl', json.dumps(wrapper).encode(), DEFAULTS))

    def test_event_limit_fails_with_raw_inputs_preserved(self):
        engine = Correlator(self.root, self.root/'out', {'max_events': 1})
        engine.process('ubuntu-auth.log', auth(10))
        with self.assertRaisesRegex(RuntimeError, 'limit reached'):
            engine.process('ubuntu-auth.log', auth(11))


if __name__ == '__main__':
    unittest.main()
