import unittest,tempfile,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
from syn_load_detection import syn_cases
from lab_campaign import validate,build_chains,wire_events
from live_activity import Activities

def events(n=120,port=80,offset=0):
 t=datetime(2026,10,21,tzinfo=timezone.utc)
 return [dict(kind='network.tcp_syn',signature_id='9900003',sensor_id='sensor',source_ip='172.20.0.4',target_ip='172.20.0.3',target_host='ubuntu-endpoint',destination_port=port,source_port=10000+i,flow_id=str(i+1),event_id='e'+str(offset+i),event_time=(t+timedelta(seconds=offset+i*.02)).isoformat()) for i in range(n)]
C=validate(dict(attack_chain_enabled=True,syn_load_alerts_enabled=True,recon_window_seconds=120,recon_port_threshold=20,recon_port_window_seconds=10,failure_threshold=5,failure_window_seconds=60))
class SynTest(unittest.TestCase):
 def test_eve_validation_duplicate_outputs(self):
  from setup_suricata_web import unique_alerts
  from copy import deepcopy
  e=dict(timestamp='2026-10-14T19:20:02.596000-0400',flow_id=563707903473785,
         src_ip='198.51.100.11',src_port=31059,dest_ip='192.0.2.10',dest_port=80,proto='TCP',
         alert={'signature_id':9900104,'rev':1})
  self.assertEqual(len(unique_alerts([e,deepcopy(e)])),1)
  for changes in ({'src_ip':'198.51.100.12'},{'tx_id':2},{'timestamp':'2026-10-14T19:20:03.596000-0400'},
                  {'flow_id':2},{'alert':{'signature_id':9900101,'rev':1}}):
   self.assertEqual(len(unique_alerts([e,{**e,**changes}])),2)
 def test_threshold_disabled_and_scan(self):
  self.assertFalse(syn_cases(events(99),C));self.assertFalse(syn_cases(events(),{}))
  scan=events(32)
  for i,e in enumerate(scan):e['destination_port']=i+1
  self.assertFalse(syn_cases(scan,C))
 def test_retransmit_sources_ports_sensors(self):
  es=events();self.assertEqual(syn_cases(es,C),syn_cases(list(reversed(es+es)),C))
  for field in ('source_ip','destination_port','sensor_id'):
   es=events()
   for i,e in enumerate(es):e[field]=('other' if field!='destination_port' else 81) if i>=60 else e[field]
   self.assertFalse(syn_cases(es,C))
 def test_gap_and_unknown_impact(self):
  self.assertFalse(syn_cases(events(60)+events(60,offset=95),C))
  s=syn_cases(events(),C)[0]['stages'][0]
  self.assertEqual(s['syn_connection_count'],120);self.assertFalse(s['service_degradation_observed']);self.assertFalse(s['handshake_completion_verified'])
 def test_raw_eve_normalization(self):
  from lab_correlation import recon_event
  cfg={'assets':[{'host':'ubuntu-endpoint','ips':['172.20.0.3']}],'protected_host':'ubuntu-endpoint'}
  from lab_recon import observation
  raw=dict(event_type='alert',proto='TCP',alert={'signature_id':9900003},timestamp='2026-10-21T00:00:00+0000',src_ip='172.20.0.4',dest_ip='172.20.0.3',src_port=12345,dest_port=80,flow_id=123)
  e=observation(raw,'sensor','ubuntu-endpoint')
  self.assertEqual(e['kind'],'network.tcp_syn');self.assertEqual(e['destination_port'],80)
  es=[]
  for i in range(120):
   raw.update(flow_id=1000+i,src_port=12000+i,timestamp=(datetime(2026,10,21,tzinfo=timezone.utc)+timedelta(milliseconds=20*i)).isoformat())
   e=observation(raw,'sensor','ubuntu-endpoint');e['event_id']=str(i);es.append(e)
  self.assertEqual(syn_cases(es,C)[0]['stages'][0]['syn_connection_count'],120)
 def test_chain_wire_publication(self):
  scan=events(32)
  for i,e in enumerate(scan):e['destination_port']=i+1;e['flow_id']='scan'+str(i)
  es=scan+events(120,offset=8)
  chains=build_chains(es,[],C)
  c=next(c for c in chains if len(c['stages'])==2);self.assertEqual(c['stages'][1]['name'],'syn_connection_pressure');self.assertEqual(c['risk_score'],60)
  self.assertTrue(wire_events(c,'session','evidence'))
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),None);engine=SimpleNamespace(config=C,events={e['event_id']:e for e in es},snapshot=Path(d)/'cases.json')
   a.publish_syn_load(engine);a.publish_syn_load(engine)
   rows=[json.loads(x) for x in a.path.read_text().splitlines()]
   self.assertEqual(len(rows),1);self.assertEqual(rows[0]['soc_ai_kind'],'syn_load')
if __name__=='__main__':unittest.main()
