import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from lab_correlation import DEFAULTS, build_cases, normalize_line
from lab_risk import case_assessment
from live_activity import Activities
from test_lab_correlation import sequence, auth, normalized, recon
from test_lab_live import flow
from wazuh_bridge import Publisher
from wazuh_scenarios import lab_scope, normal_http_commands, scan_command, ssh_command
from wazuh_trace import READ_ALERTS, auth_outcomes, manager_alerts, verify_index


class RealtimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.pub=Publisher(self.root/'outbox.sqlite','manager',lambda *_: None)
        self.addCleanup(self.pub.close)

    def payloads(self):
        return [json.loads(r[0]) for r in self.pub.db.execute('SELECT payload FROM delivery ORDER BY rowid')]

    def test_signature_is_published_before_any_completed_flow(self):
        acts=Activities(self.root,self.pub)
        event={**recon(),'alert':{'signature_id':9900001,'signature':'lab SYN indicator','severity':2}}
        with contextlib.redirect_stdout(io.StringIO()):
            acts.raw_event(event,'suricata-eve.jsonl','ubuntu-endpoint')
            acts.raw_event(event,'suricata-eve.jsonl','ubuntu-endpoint')
        rows=self.payloads()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['soc_ai_kind'],'sensor_alert')
        self.assertEqual(rows[0]['risk_score'],50)
        self.assertEqual(rows[0]['session_id'],self.root.name)
        self.assertFalse(rows[0]['confirmed_compromise'])

    def test_normal_observations_are_opt_in_and_not_attack_verdicts(self):
        acts=Activities(self.root,self.pub,publish_observations=True)
        e=normalized('ubuntu-auth.log',auth(10,'Accepted'))
        engine=SimpleNamespace(events={e['event_id']:e},cases=[],web_activity=[],snapshot=self.root/'cases.json')
        with contextlib.redirect_stdout(io.StringIO()):
            acts.correlation(engine);acts.correlation(engine)
            acts.prediction(flow(),{'decision':'below_alert_threshold','predicted_label':'BENIGN','attack_score':0})
            acts.flush(force=True)
        rows=self.payloads()
        self.assertEqual([r['soc_ai_kind'] for r in rows],['auth_observation','model_summary'])
        self.assertTrue(all(r['security_outcome']=='observation' and r['risk_score']==0 for r in rows))

    def test_chain_score_and_graph_follow_observed_same_entity_stages(self):
        case=build_cases(sequence(),DEFAULTS)[0]
        self.assertEqual(case['risk_score'],95)
        graph=case['attack_chain_graph']
        self.assertEqual(len(graph['nodes']),3);self.assertEqual(len(graph['edges']),2)
        self.assertTrue(all(n['evidence_ids'] for n in graph['nodes']))
        self.assertFalse(case['confirmed_compromise'])
        # A success on another account does not complete the chain or receive 95.
        other=build_cases(sequence(success_user='someone_else'),DEFAULTS)[0]
        self.assertEqual(other['status'],'possible_password_guessing')
        self.assertEqual(other['risk_score'],75)

    def test_wazuh_chain_has_string_graph_and_stable_case_revision(self):
        acts=Activities(self.root,self.pub)
        events=sequence();engine=SimpleNamespace(events={e['event_id']:e for e in events},
            cases=build_cases(events,DEFAULTS),web_activity=[],snapshot=self.root/'cases.json')
        with contextlib.redirect_stdout(io.StringIO()):
            acts.correlation(engine);acts.correlation(engine)
        row=self.payloads()[0]
        self.assertEqual(row['soc_ai_kind'],'correlation')
        self.assertIsInstance(row['attack_chain_json'],str)
        self.assertEqual(len(json.loads(row['attack_chain_json'])['nodes']),3)
        self.assertLess(len(json.dumps(row).encode()),6000)
        self.assertEqual(self.pub.pending,1)
        wrapper={'agent':{'id':'001','name':'ubuntu-endpoint'},'data':row,'full_log':auth(20).decode()}
        self.assertIsNone(normalize_line('wazuh-alerts.jsonl',json.dumps(wrapper).encode(),DEFAULTS))

    def test_sensor_health_uses_counter_deltas_not_old_cumulative_faults(self):
        acts=Activities(self.root,self.pub)
        def stats(n):
            return {'event_type':'stats','timestamp':str(n),'stats':{'decoder':{'event':{'ipv4':{'trunc_pkt':n}}},
                'tcp':{'reassembly_gap':n},'capture':{'kernel_drops':0}}}
        acts.raw_event(stats(100),'eve','sensor')
        self.assertEqual(self.pub.pending,0)
        acts.raw_event(stats(105),'eve','sensor')
        row=self.payloads()[0]
        self.assertEqual(row['ipv4_truncated_packets'],5)
        self.assertEqual(row['security_outcome'],'telemetry_warning')
        acts.raw_event(stats(0),'eve','sensor')
        self.assertEqual(self.pub.pending,1)

    def test_summary_interval_and_sensor_gap_annotation_preserve_model_decision(self):
        clock=[0]
        acts=Activities(self.root,self.pub,clock=lambda:clock[0],summary_seconds=1)
        acts.prediction({**flow(),'tcp':{'ts_gap':True}},
            {'decision':'possible_attack','predicted_label':'SSH-Patator','attack_score':.1})
        acts.flush();self.assertEqual(self.pub.pending,0)
        clock[0]=1
        with contextlib.redirect_stdout(io.StringIO()): acts.flush()
        row=self.payloads()[0]
        self.assertEqual(row['sensor_tcp_gap_flow_count'],1)
        self.assertEqual(row['decision'],'possible_attack')
        self.assertEqual(row['score_max'],.1)
        self.assertFalse(row['risk_is_probability'])

    def test_all_rules_have_unique_ids_and_low_severity_observations(self):
        rules=ET.fromstring(Path(__file__).with_name('soc_ai_bridge_rules.xml').read_text())
        ids=[r.attrib['id'] for r in rules]
        self.assertEqual(len(ids),len(set(ids)))
        for rule in rules:
            if rule.attrib['id'] in ('119207','119208','119210'):
                self.assertEqual(rule.attrib['level'],'3')
        self.assertEqual(set(map(int,ids)),set(range(119200,119212)))

    def test_public_target_and_wrong_network_rejected_before_traffic(self):
        with patch('subprocess.run') as runner:
            with self.assertRaises(ValueError): lab_scope('kali','ubuntu','8.8.8.8',runner)
            runner.assert_not_called()
        data=[{'NetworkSettings':{'Networks':{'lab':{'IPAddress':'172.20.0.4'}}}},
              {'NetworkSettings':{'Networks':{'lab':{'IPAddress':'172.20.0.3'}}}}]
        runner=lambda argv,**_: SimpleNamespace(returncode=0,stdout=json.dumps(
            [{'Driver':'host'}] if argv[1]=='network' else data).encode(),stderr=b'')
        with self.assertRaises(ValueError):lab_scope('kali','ubuntu','172.20.0.3',runner)

    def test_commands_are_bounded_and_plan_cannot_execute_docker(self):
        command=scan_command('kali','172.20.0.3')
        self.assertEqual(command[command.index('--max-rate')+1],'5')
        self.assertEqual(command[command.index('-p')+1],'1-32')
        self.assertEqual(len(normal_http_commands('kali','172.20.0.3')),12)
        wrong=ssh_command('kali','172.20.0.3','soctest',True)
        self.assertIn('NumberOfPasswordPrompts=1',wrong)
        import wazuh_scenarios
        with patch.object(sys,'argv',['wazuh_scenarios.py','plan','--scenario','chain']),patch('subprocess.run') as runner,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wazuh_scenarios.main(),0)
            runner.assert_not_called()

    def test_index_confirmation_requires_same_event_rule_and_alert_index(self):
        report={'event_id':'wanted','manager_alert_verified':True}
        def response(eid='wanted',rule='119201',index='wazuh-alerts-4.x-2026.10.19'):
            return {'hits':{'hits':[{'_index':index,'_id':'doc','_source':{'data':{'event_id':eid},'rule':{'id':rule}}}]}}
        self.assertTrue(verify_index(report,response())['indexer_verified'])
        for value in (response(eid='other'),response(rule='119202'),response(index='other-index')):
            self.assertFalse(verify_index(report,value)['indexer_verified'])

    def test_manager_reader_failure_is_not_reported_as_delivery_success(self):
        runner=lambda *_,**__:SimpleNamespace(returncode=1,stderr=b'not running',stdout=b'')
        with self.assertRaises(RuntimeError):manager_alerts('manager',{'event_id':'test'},runner)
        compile(READ_ALERTS,'<bounded-alert-reader>','exec')

    def test_raw_auth_verification_deduplicates_and_scopes_actor_and_time(self):
        from test_lab_correlation import time_at
        lines=[auth(t) for t in range(10,18)]
        lines += [lines[0],auth(20,'Accepted'),auth(21,'Accepted',user='other'),
                  auth(21,'Accepted',host='other-host'),auth(100,'Accepted')]
        (self.root/'ubuntu-auth.log').write_bytes(b'\n'.join(lines)+b'\n')
        operator={'started_at':time_at(0),'ended_at':time_at(30),
                  'username':'labuser','scope':{'source_ip':'172.20.0.4'}}
        result=auth_outcomes(self.root,operator)
        self.assertEqual(result['password_failures'],8)
        self.assertEqual(result['successes'],1)
        self.assertEqual(result['maximum_failures_in_60_seconds'],8)
        self.assertTrue(result['success_within_300_seconds_after_last_failure'])


if __name__=='__main__':unittest.main()
