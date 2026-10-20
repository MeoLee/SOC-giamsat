import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from endpoint_probe import SCHEMA, PAYLOAD, PAYLOAD_SHA256, SHELL_ARGV, transfer_argv
from lab_correlation import DEFAULTS, build_cases, digest, normalize_line
from lab_endpoint import normalize
from test_lab_correlation import sequence, time_at, auth

CONFIG = {**DEFAULTS, 'source_kinds': {'endpoint-probe.jsonl': 'endpoint'},
          'source_origins': {'endpoint-probe.jsonl': {'source_container': 'ubuntu-endpoint'}}}


def raw_action(kind='process.execution', **changes):
    row = {'schema_version': SCHEMA, 'lab_probe': True, 'probe_id': 'a'*32,
           'source_ip': '172.20.0.4', 'source_port': 40000, 'target_ip': '172.20.0.3',
           'target_port': 22, 'username': 'labuser', 'uid': 1003, 'returncode': 0,
           'started_at': time_at(21 if kind == 'process.execution' else 24),
           'event_time': time_at(22 if kind == 'process.execution' else 25), 'kind': kind}
    if kind == 'process.execution':
        row.update(argv=SHELL_ARGV, stdout_sha256=hashlib.sha256(b'fixture').hexdigest())
    else:
        path = '/tmp/soc-lab-probe-fixture.txt'
        row.update(argv=transfer_argv(row['source_ip'], row['probe_id'], path),
                   artifact_path=path, artifact_bytes=len(PAYLOAD), artifact_sha256=PAYLOAD_SHA256,
                   payload_verified=True)
    row.update(changes)
    return row


def action(kind='process.execution', **changes):
    row = normalize(json.dumps(raw_action(kind, **changes)), CONFIG, 'endpoint-probe.jsonl')
    return {**row, 'event_id': 'event:'+digest(row), 'source_refs': []}


class EndpointTests(unittest.TestCase):
    def test_five_real_action_stages_keep_same_case_and_capped_score(self):
        events = sequence()
        initial = build_cases(events, CONFIG)[0]
        execution = build_cases(events+[action()], CONFIG)[0]
        transfer = build_cases(events+[action(), action('file.transfer')], CONFIG)[0]
        self.assertEqual({c['chain_id'] for c in (initial, execution, transfer)}, {initial['chain_id']})
        self.assertEqual([c['attack_chain_stage_count'] for c in (initial, execution, transfer)], [3,4,5])
        self.assertEqual(transfer['risk_score'], 95)
        self.assertEqual(transfer['chain_evidence_count'], 31)
        self.assertEqual(transfer['chain_password_failure_count'], 8)
        self.assertEqual(transfer['chain_duration_seconds'], 25)
        self.assertEqual(transfer['techniques'], 'T1046;T1110.001;T1078;T1059.004;T1105')
        self.assertEqual(transfer['endpoint_evidence_scope'], 'controlled_lab_probe_only')
        self.assertFalse(transfer['confirmed_compromise'])
        self.assertNotIn('T1071', transfer['techniques'])

    def test_unrelated_account_port_target_time_or_probe_cannot_complete_chain(self):
        for change in ({'username':'other'}, {'source_port':40001}, {'target_host':'other'},
                       {'target_ip':'172.20.0.9'}, {'source_ip':'172.20.0.9'},
                       {'started_at':time_at(321), 'event_time':time_at(322)},
                       {'started_at':time_at(19)}, {'lab_probe':False}):
            event={**action(), **change}
            with self.subTest(change=change):
                self.assertEqual(build_cases(sequence()+[event,action('file.transfer')],CONFIG)[0]['attack_chain_stage_count'],3)
        transfer = {**action('file.transfer'), 'probe_id':'b'*32}
        self.assertEqual(build_cases(sequence()+[action(),transfer],CONFIG)[0]['attack_chain_stage_count'],4)

    def test_transfer_requires_prior_execution_and_successful_login(self):
        self.assertEqual(build_cases(sequence()+[action('file.transfer')],CONFIG)[0]['attack_chain_stage_count'],3)
        events = sequence()[:-1]+[action(),action('file.transfer')]
        self.assertEqual(build_cases(events,CONFIG)[0]['attack_chain_stage_count'],2)
        transfer = {**action('file.transfer'), 'started_at':time_at(21), 'event_time':time_at(21.5)}
        self.assertEqual(build_cases(sequence()+[action(),transfer],CONFIG)[0]['attack_chain_stage_count'],4)
        rows = sequence()+[action(),action('file.transfer')]
        self.assertEqual(build_cases(rows,CONFIG),build_cases(list(reversed(rows)),CONFIG))

    def test_failed_actions_bad_hash_unknown_source_and_wrong_command_are_rejected(self):
        self.assertIsNone(normalize(json.dumps(raw_action(returncode=1)),CONFIG,'endpoint-probe.jsonl'))
        for row in [raw_action('file.transfer',artifact_sha256='0'*64),
                    raw_action(argv=['/bin/sh','-c','unobserved command']),
                    raw_action(uid=0),raw_action(source_port=True),raw_action(lab_probe=False)]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                normalize_line('endpoint-probe.jsonl',json.dumps(row).encode(),CONFIG)
        with self.assertRaises(ValueError):
            normalize(json.dumps(raw_action()),{**CONFIG,'source_origins':{}},'endpoint-probe.jsonl')

    def test_publisher_emits_four_revisions_without_new_rule_or_training_label(self):
        from live_activity import Activities
        from wazuh_bridge import Publisher
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); pub=Publisher(root/'outbox.sqlite','unused',lambda *_:None)
            try:
                acts=Activities(root,pub)
                complete=sequence()+[action(),action('file.transfer')]
                for size in (28,29,30,31,31):
                    events=complete[:size]
                    engine=SimpleNamespace(events={e['event_id']:e for e in events},
                        cases=build_cases(events,CONFIG),web_activity=[],snapshot=root/'cases.json')
                    with contextlib.redirect_stdout(io.StringIO()):acts.correlation(engine)
                rows=[json.loads(r[0]) for r in pub.db.execute('SELECT payload FROM delivery ORDER BY rowid')]
                self.assertEqual([r['attack_chain_stage_count'] for r in rows],[2,3,4,5])
                self.assertEqual([r['risk_score'] for r in rows],[75,95,95,95])
                self.assertEqual(len({r['chain_id'] for r in rows}),1)
                self.assertTrue(all(len(json.dumps(r).encode())<6000 for r in rows))
                self.assertEqual(json.loads(rows[-1]['attack_chain_json'])['nodes'][-1]['candidate_technique'],'T1105')
            finally:pub.close()

    def test_optional_installer_preserves_config_and_scenario_plan_never_executes(self):
        from setup_chain_telemetry import candidate_config
        from live_config import load_config
        from wazuh_scenarios import main, ssh_command
        from unittest.mock import patch
        import sys
        original=json.loads(Path(__file__).with_name('live-config.json').read_text())
        changed=candidate_config(original,'ubuntu-endpoint')
        self.assertEqual(len(changed['sources']),len(original['sources'])+1)
        self.assertEqual(changed['context'],original['context'])
        self.assertEqual(candidate_config(changed,'ubuntu-endpoint'),changed)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'config.json';path.write_text(json.dumps(changed))
            self.assertEqual(load_config(path)['sources'][-1]['kind'],'endpoint')
        with patch.object(sys,'argv',['wazuh_scenarios.py','plan','--scenario','chain-extended']),patch('subprocess.run') as runner,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(),0); runner.assert_not_called()
        argv=ssh_command('kali','172.20.0.3','soctest',probe_token='a'*32)
        self.assertTrue(argv[-1].startswith('python3 /usr/local/lib/soc-lab/endpoint_probe.py --token '))
        with self.assertRaises(ValueError):ssh_command('kali','172.20.0.3','soctest',probe_token='bad; command')

    def test_trace_requires_raw_actions_same_auth_connection_and_server_hash(self):
        from wazuh_trace import endpoint_outcomes
        events=sequence()+[action(),action('file.transfer')]
        snapshot={'config':CONFIG,'cases':build_cases(events,CONFIG)}
        operator={'complete':True,'endpoint_probe_id':'a'*32,'started_at':time_at(0),'ended_at':time_at(30),
                  'scope':{'source_ip':'172.20.0.4','target_ip':'172.20.0.3'},'username':'labuser',
                  'transfer_server_evidence':{'kind':'transfer_served','probe_id':'a'*32,
                      'peer_ip':'172.20.0.3','sha256':PAYLOAD_SHA256,'bytes_sent':len(PAYLOAD),
                      'path':'/'+'a'*32+'.txt'}}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'correlation-cases.json').write_text(json.dumps(snapshot))
            (root/'ubuntu-auth.log').write_bytes(b'\n'.join([auth(t) for t in range(10,18)]+[auth(20,'Accepted')])+b'\n')
            endpoint=root/'endpoint-probe.jsonl'
            endpoint.write_text('\n'.join(json.dumps(raw_action(k)) for k in ('process.execution','file.transfer'))+'\n')
            result=endpoint_outcomes(root,operator)
            self.assertTrue(result['five_stage_chain_verified'],result)
            self.assertFalse(result['general_endpoint_audit_coverage'])
            self.assertFalse(endpoint_outcomes(root,{**operator,'complete':False})['five_stage_chain_verified'])
            changed={**operator,'transfer_server_evidence':{}}
            self.assertFalse(endpoint_outcomes(root,changed)['five_stage_chain_verified'])
            endpoint.write_text(json.dumps(raw_action())+'\n')
            self.assertFalse(endpoint_outcomes(root,operator)['five_stage_chain_verified'])


if __name__ == '__main__':unittest.main()
