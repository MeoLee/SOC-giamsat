import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from test_lab_correlation import DEFAULTS,normalized,syn,auth,time_at
from lab_campaign import validate,build_chains
from lab_correlation import build_cases,instant
from lab_chain_episode import lifecycle
from ssh_contact_detection import contact_cases
from live_activity import Activities
from test_lab_live import flow
C=validate({**DEFAULTS,'attack_chain_enabled':True,'ssh_contact_observations_enabled':True})
def contact(t=0,port=22,fid=1):return normalized('suricata-eve.jsonl',json.dumps(syn(t,port,fid=fid)).encode())
def chains(es):return build_chains(es,build_cases(es,C),C)
class ContactTests(unittest.TestCase):
 def test_one_syn_early_without_flow(self):
  es=[contact()];cs=chains(es);self.assertEqual(len(cs),1);c=cs[0]
  self.assertEqual([s['name'] for s in c['stages']],['ssh_service_contact']);self.assertEqual(c['risk_score'],0);self.assertFalse(c['recon_observed'])
  self.assertFalse(c['stages'][0]['reconnaissance_proven']);self.assertFalse(contact_cases(es,{**C,'ssh_contact_observations_enabled':False}))
 def test_retransmits_and_duplicate_views_do_not_extend_idle(self):
  e=contact();later={**e,'event_time':time_at(30),'event_id':'retransmit'}
  c=chains([e,e,later])[0];self.assertEqual(c['stages'][0]['connection_count'],1);self.assertEqual(c['last_seen'],e['event_time'])
  self.assertEqual(lifecycle(c,C,instant(time_at(95)))['chain_status'],'expired_singleton')
 def test_auth_connection_retracted_and_normal_login_not_formed(self):
  e=contact();a=normalized('ubuntu-auth.log',auth(2,'Accepted'))
  e['source_port']=a['source_port'];self.assertEqual(chains([e,a]),[])
 def test_old_auth_does_not_mask_reused_port_and_retransmit_stays_retracted(self):
  a=normalized('ubuntu-auth.log',auth(2,'Accepted'));e=contact();e['source_port']=a['source_port']
  late={**e,'event_time':time_at(10),'event_id':'later-retransmission'}
  self.assertEqual(chains([e,a,late]),[])
  fresh=contact(100,fid=2);fresh['source_port']=a['source_port']
  self.assertEqual(chains([a,fresh])[0]['stages'][0]['name'],'ssh_service_contact')
 def test_unrelated_ports_hosts_and_directions_excluded(self):
  for e in (contact(port=80),{**contact(),'target_host':'ip:172.20.0.4'},{**contact(),'sensor_id':'other'}):self.assertEqual(chains([e]),[])
 def test_candidate_promotes_to_auth_chain_with_stable_id(self):
  es=[contact()];before=chains(es)[0]
  es += [normalized('ubuntu-auth.log',auth(t)) for t in range(10,18)]
  es += [normalized('ubuntu-auth.log',auth(20,'Accepted'))]
  cs=chains(es);self.assertEqual(len(cs),1);after=cs[0];self.assertEqual(before['chain_id'],after['chain_id'])
  self.assertEqual([s['name'] for s in after['stages']],['ssh_service_contact','repeated_auth_failures','auth_success_after_failures'])
  self.assertFalse(after['recon_observed']);self.assertEqual(after['risk_score'],85)
 def test_gap95_splits_even_same_target(self):
  self.assertEqual(len(chains([contact(),contact(95,fid=2)])),2)
 def test_broad_scan_uses_recon_without_extra_contact_candidate(self):
  es=[contact(port=p,fid=p) for p in range(1,33)]
  cs=chains(es);self.assertEqual(len(cs),1);self.assertEqual(cs[0]['stages'][0]['name'],'possible_recon')
 def test_neutral_event_once_no_completed_flow(self):
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),None);e=contact();engine=SimpleNamespace(events={e['event_id']:e},config=C,snapshot=Path(d)/'cases.json')
   out=io.StringIO()
   with contextlib.redirect_stdout(out):a.publish_ssh_contacts(engine);a.publish_ssh_contacts(engine)
   row=json.loads(a.path.read_text().splitlines()[0]);self.assertEqual(row['soc_ai_kind'],'ssh_contact');self.assertEqual(row['risk_score'],0);self.assertFalse(row['waited_for_completed_flow']);self.assertIn('[SSH-CONTACT]',out.getvalue())
 def test_poll_publishes_contact_before_flow_prediction(self):
  from lab_live import LiveCollector
  from test_lab_live import FakePredictor
  import sys
  class MockLive(LiveCollector):
   remote=b''
   def container_id(self,c):return c+':id'
   def read(self,c,p,offset,count):return '1:1',len(self.remote),self.remote[offset:offset+count]
  runtime={'sources':[{'kind':'eve','container':'ubuntu-endpoint','path':'/eve','output':'eve.jsonl'}],
           'correlation':{**C,'source_kinds':{'eve.jsonl':'eve'},'source_origins':{'eve.jsonl':{'source_container':'ubuntu-endpoint'}}}}
  with tempfile.TemporaryDirectory() as d:
   args=SimpleNamespace(output_dir=d,scenario_id='live-observe',interval=.1,grace=0,from_start=False,resume=None,docker_command=sys.executable,all_flows=False,endpoints=None,runtime=runtime,sources=[('eve','ubuntu-endpoint','/eve','eve.jsonl')])
   live=MockLive(args,FakePredictor());order=[]
   class Pub:
    pending=0;last_error=None
    def enqueue(self,row):order.append('enqueue:'+row['soc_ai_kind'])
    def flush(self):order.append('deliver')
   pub=Pub();live.publisher=pub;live.activities.publisher=pub
   consume=live.observer.consume
   def prediction(*args):
    order.append('flow_inference');return consume(*args)
   live.observer.consume=prediction
   live.remote=(json.dumps(syn(0,22))+'\n').encode()
   try:
    with contextlib.redirect_stdout(io.StringIO()):live.poll()
    self.assertLess(order.index('enqueue:ssh_contact'),order.index('flow_inference'));self.assertLess(order.index('deliver'),order.index('flow_inference'))
    self.assertEqual(live.observer.counts['written_predictions'],0);self.assertEqual(live.correlator.chains[0]['stages'][0]['name'],'ssh_service_contact')
   finally:live.lock_file.close()
 def test_benign_top_class_explains_binary_decision(self):
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),None);out=io.StringIO()
   with contextlib.redirect_stdout(out):
    a.prediction(flow(),{'predicted_label':'BENIGN','decision':'possible_attack','attack_score':.6,'attack_score_threshold':.5});a.flush(force=True)
   row=json.loads(a.path.read_text().splitlines()[0]);self.assertEqual(row['predicted_label'],'BENIGN');self.assertIn('Chưa xác định loại tấn công',row['model_interpretation']);self.assertEqual(row['score_max'],.6);self.assertEqual(row['attack_score_threshold'],.5);self.assertIn('top_class=BENIGN',out.getvalue());self.assertNotIn('prediction=BENIGN',out.getvalue())
if __name__=='__main__':unittest.main()
