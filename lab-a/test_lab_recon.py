import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lab_correlation import Correlator, DEFAULTS, build_cases, normalize_line
from lab_recon import scan_evidence, instant
from live_activity import Activities
from test_lab_correlation import syn, recon, normalized, scan, sequence
from setup_recon import LEGACY, merge_rules, remote_install, remote_script, test_pcap as recon_pcap
from wazuh_bridge import Publisher
from wazuh_trace import recon_coverage
from test_lab_correlation import time_at


class ReconTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def probes(self,ports,*,start=0,spacing=.2,sensor=None,src=None,dst=None):
        result=[]
        for i,port in enumerate(ports):
            raw=syn(start+i*spacing,port,fid=1000+i,dst=dst or '172.20.0.3')
            if src:raw['src_ip']=src
            event=normalized('suricata-eve.jsonl',json.dumps(raw).encode())
            if sensor:event['sensor_id']=sensor
            result.append(event)
        return result

    def test_http_burst_and_single_service_never_create_port_sweep(self):
        for port,count in ((80,33),(443,200),(22,24)):
            with self.subTest(port=port):
                events=self.probes([port]*count,spacing=.01)
                self.assertEqual(scan_evidence(events,DEFAULTS),[])
                self.assertEqual(build_cases(events,DEFAULTS),[])

    def test_scan_is_detected_before_completed_flow_with_real_evidence_ids(self):
        events=self.probes(range(1,33))
        self.assertEqual(build_cases(events[:19],DEFAULTS),[])
        cases=build_cases(events,DEFAULTS)
        self.assertEqual(len(cases),1)
        case=cases[0];stage=case['stages'][0]
        self.assertEqual(case['status'],'possible_recon')
        self.assertEqual(stage['distinct_destination_ports'],20)
        self.assertEqual(stage['port_window_seconds'],10)
        self.assertEqual(len(stage['evidence_ids']),20)
        self.assertTrue(set(stage['evidence_ids'])<={e['event_id'] for e in events})
        self.assertEqual(case['risk_score'],40)
        self.assertFalse(case['confirmed_compromise'])
        self.assertEqual(cases,build_cases(list(reversed(events)),DEFAULTS))

    def test_sliding_window_across_clock_boundary_and_slow_scan(self):
        self.assertEqual(len(build_cases(self.probes(range(1,33),start=8),DEFAULTS)),1)
        self.assertEqual(build_cases(self.probes(range(1,21),spacing=1),DEFAULTS),[])

    def test_distinct_ports_are_not_pooled_between_sources_targets_or_sensors(self):
        first=self.probes(range(1,11))
        for kwargs in ({'src':'172.20.0.99'},{'dst':'172.20.0.99'},{'sensor':'other-sensor'}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(build_cases(first+self.probes(range(11,21),**kwargs),DEFAULTS),[])

    def test_legacy_syn_count_alert_alone_is_no_longer_recon_evidence(self):
        event=normalized('suricata-eve.jsonl',json.dumps(recon()).encode())
        self.assertEqual(event['kind'],'network.syn_rate_indicator')
        self.assertEqual(build_cases([event],DEFAULTS),[])

    def test_decoded_wazuh_syn_views_do_not_double_count_and_keep_provenance(self):
        for source in ('suricata-eve.jsonl','wazuh-alerts.jsonl','ubuntu-auth.log'):
            (self.root/source).touch()
        engine=Correlator(self.root,self.root/'out')
        for port in range(1,21):
            raw=syn(port=port)
            engine.process('suricata-eve.jsonl',json.dumps(raw).encode())
            for field in ('flow_id','src_port','dest_port'):raw[field]=str(raw[field])
            raw['alert']['signature_id']='9900003'
            wrapper={'agent':{'id':'001','name':'ubuntu-endpoint'},'data':raw}
            engine.process('wazuh-alerts.jsonl',json.dumps(wrapper).encode())
        self.assertEqual(len(engine.events),20)
        self.assertEqual(engine.counts['duplicate_views'],20)
        self.assertTrue(all(len(e['source_refs'])==2 for e in engine.events.values()))
        case=build_cases(list(engine.events.values()),engine.config)[0]
        self.assertEqual(len(case['stages'][0]['evidence_ids']),20)

    def test_syn_observations_do_not_publish_attack_signatures_but_sweep_publishes_case(self):
        publisher=Publisher(self.root/'outbox.sqlite','manager',lambda *_:None)
        self.addCleanup(publisher.close)
        activities=Activities(self.root,publisher)
        for port in range(1,33):activities.raw_event(syn(port=port),'eve','ubuntu-endpoint')
        activities.raw_event(recon(),'eve','ubuntu-endpoint')
        self.assertEqual(publisher.pending,0)
        events=scan()
        engine=SimpleNamespace(events={e['event_id']:e for e in events},
            cases=build_cases(events,DEFAULTS),snapshot=self.root/'cases.json',web_activity=[])
        with contextlib.redirect_stdout(io.StringIO()):
            activities.correlation(engine);activities.correlation(engine)
        self.assertEqual(publisher.pending,1)
        row=json.loads(publisher.db.execute('SELECT payload FROM delivery').fetchone()[0])
        self.assertEqual(row['soc_ai_kind'],'correlation')
        self.assertEqual(row['distinct_destination_ports'],20)
        self.assertEqual(row['recon_detection_method'],'distinct_tcp_destination_ports')

    def test_dense_scans_have_bounded_proof_output_per_window(self):
        scans=scan_evidence(self.probes(range(1,3001),spacing=.001),DEFAULTS)
        self.assertEqual(len(scans),1)
        self.assertEqual(len(scans[0]['recon_evidence_ids']),20)

    def test_invalid_observation_and_thresholds_are_rejected(self):
        for key,value in (('proto','UDP'),('dest_port',None),('dest_port',True),('flow_id',1.0)):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                normalize_line('suricata-eve.jsonl',json.dumps({**syn(),key:value}).encode(),DEFAULTS)
        for settings in ({'recon_port_threshold':True},{'recon_port_threshold':1},
                         {'recon_port_window_seconds':0}):
            with self.subTest(settings=settings),self.assertRaises(ValueError):
                scan_evidence([],settings)

    def test_sensor_compact_timezone_offsets_are_canonical(self):
        self.assertEqual(instant('2026-10-14T23:20:00.000000+0000'),
                         instant('2026-10-14T19:20:00.000000-0400'))
        self.assertEqual(instant('2026-10-14T23:20:00Z'),
                         instant('2026-10-14T23:20:00+00:00'))
        with self.assertRaises(ValueError):instant('2026-10-14T23:20:00')

    def test_chain_uses_verified_port_spread_and_keeps_risk_policy(self):
        case=build_cases(sequence(),DEFAULTS)[0]
        self.assertEqual(case['risk_score'],95)
        self.assertEqual(case['stages'][0]['detection_method'],'distinct_tcp_destination_ports')
        self.assertEqual(case['stages'][1]['failure_count'],8)

    def test_negative_coverage_requires_observed_connections_not_only_a_closed_session(self):
        events=self.probes([80]*33)
        path=self.root/'correlation-events.jsonl'
        # A later provenance update for an event must not increase coverage.
        path.write_text(''.join(json.dumps(e)+'\n' for e in events+[events[0]]))
        operator={'scenario':'http-burst','http_requests':33,'complete':True,
            'started_at':time_at(-1),'ended_at':time_at(20),
            'scope':{'source_ip':'172.20.0.4','target_ip':'172.20.0.3'}}
        coverage=recon_coverage(self.root,operator)
        self.assertTrue(coverage['coverage_sufficient'])
        self.assertEqual(coverage['observed_connections'],33)
        self.assertEqual(coverage['distinct_destination_ports'],1)
        self.assertEqual(coverage['qualifying_port_sweep_windows'],0)
        self.assertFalse(recon_coverage(self.root,{**operator,'http_requests':34})['coverage_sufficient'])
        path.unlink()
        self.assertFalse(recon_coverage(self.root,operator)['coverage_sufficient'])


class ReconInstallerTests(unittest.TestCase):
    def setUp(self):
        self.rule=Path(__file__).with_name('soc-recon.rules').read_text()

    def test_merge_preserves_sql_and_custom_rules_and_is_idempotent(self):
        other='alert udp any any -> any any (msg:"custom"; sid:9912345;)\n'
        web=Path(__file__).with_name('soc-web.rules').read_text()
        merged=merge_rules(LEGACY+'\n'+other+web,self.rule)
        self.assertNotIn('sid:9900001;',merged)
        self.assertIn(other,merged);self.assertIn(web.strip(),merged)
        self.assertIn('sid:9900003;',merged)
        self.assertEqual(merge_rules(merged,self.rule),merged)

    def test_unknown_rule_and_colliding_id_are_preserved_by_refusing_merge(self):
        for old in (LEGACY.replace('count 20','count 30'),
                    LEGACY+'\nalert tcp any any -> any any (sid:9900003;)\n',
                    LEGACY+'\n'+LEGACY,'# no reviewed rule\n'):
            with self.subTest(old=old),self.assertRaises(ValueError):merge_rules(old,self.rule)

    def test_control_pcap_has_exact_generated_attempts_and_http_requests(self):
        data=recon_pcap();position=24;ports={};http=0
        while position<len(data):
            _,micro,length,original=struct.unpack_from('<IIII',data,position);position+=16
            self.assertEqual(length,original);self.assertLess(micro,1000000)
            frame=data[position:position+length];position+=length
            if frame[47]==2:
                source=socket.inet_ntoa(frame[26:30]);dest=struct.unpack('!H',frame[36:38])[0]
                ports.setdefault(source,[]).append(dest)
            http+=int(b'GET /soc-lab-health HTTP/1.1' in frame)
        self.assertEqual(position,len(data));self.assertEqual(http,33)
        self.assertEqual(ports['198.51.100.30'],[80]*33)
        self.assertEqual(ports['198.51.100.20'],list(range(1,33)))
        self.assertEqual(ports['198.51.100.40'],[22]*24)
        compile(remote_script(),'<remote-recon>','exec')
        self.assertLess(len(subprocess.list2cmdline(['docker','exec','sensor','python3','-c',remote_script()])),32767)

    def test_validation_failure_cannot_change_live_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);rules=root/'live.rules';rules.write_text(LEGACY+'\n')
            original=rules.read_bytes()
            class Process:
                name='777'
                def __truediv__(self,key):
                    return SimpleNamespace(read_bytes=lambda:b'\0'.join(
                        x.encode() for x in ['suricata','-c',str(root/'suri.yaml'),'-S',str(rules)]))
            with patch('setup_recon.os.geteuid',return_value=0,create=True), \
                    patch.object(Path,'iterdir',return_value=iter([Process()])), \
                    patch('setup_recon.subprocess.run',side_effect=subprocess.CalledProcessError(1,['suricata','-T'])), \
                    patch('setup_recon.os.kill') as kill:
                with self.assertRaises(subprocess.CalledProcessError):
                    remote_install({'rules':self.rule,'algorithm':Path(__file__).with_name('lab_recon.py').read_text()})
            self.assertEqual(rules.read_bytes(),original)
            self.assertEqual(list(root.glob('*.before-recon-*')),[])
            kill.assert_not_called()


if __name__=='__main__':unittest.main()
