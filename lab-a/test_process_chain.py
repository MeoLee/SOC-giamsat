import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from test_lab_correlation import scan,time_at,auth
from lab_correlation import DEFAULTS,normalize_line,digest,build_cases
from lab_campaign import build_chains,wire_events,validate
from process_observer import SCHEMA,identity,observe
BOOT='12345678-1234-1234-1234-123456789abc'
CONFIG=validate({**DEFAULTS,'attack_chain_enabled':True,'source_kinds':{'proc.jsonl':'process','auth.log':'auth'},'source_origins':{'proc.jsonl':{'source_container':'ubuntu-endpoint','source_path':'/var/log/soc-lab/process-observer/events.jsonl'}}})
def raw(**changes):
 e=dict(schema_version=SCHEMA,kind='process.shell_socket',observer_uid=0,kernel_process_observation=True,source_ip='172.20.0.4',target_ip='172.20.0.3',source_port=40000,target_port=22,username='labuser',session_uid=1003,pid=300,start_ticks=30,process_id=identity(BOOT,300,30),boot_id=BOOT,executable='/usr/bin/bash',real_uid=1003,effective_uid=1003,sshd_pids=[123],sshd_process_ids=[identity(BOOT,123,12)],ancestry_pids=[200,123],ancestry_process_ids=[identity(BOOT,200,20),identity(BOOT,123,12)],event_time=time_at(25),stdin_stdout_same_socket=True,socket_inode='123456',peer_ip='172.20.0.4',peer_port=4444,local_ip='172.20.0.3',local_port=45000)
 e.update(changes);return e
def event(row,source='proc.jsonl'):
 e=normalize_line(source,row if isinstance(row,bytes) else json.dumps(row).encode(),CONFIG)
 return {**e,'event_id':'event:'+digest(e),'source_refs':[]}
def accepted():return event(auth(20,'Accepted'),'auth.log')
def callback():return dict(kind='network.tcp_syn',event_time=time_at(24.9),event_id='callback-syn',signature_id='9900003',sensor_id='ubuntu-endpoint',source_ip='172.20.0.3',target_ip='172.20.0.4',target_host='ip:172.20.0.4',source_port=45000,destination_port=4444,flow_id='99999')
def rows():return scan()+[event(auth(i),'auth.log') for i in range(10,18)]+[accepted(),callback(),event(raw())]
def chains(es):return build_chains(es,build_cases(es,CONFIG),CONFIG)
class ProcessChainTests(unittest.TestCase):
 def test_four_steps_same_branch_deterministic(self):
  cs=chains(rows());self.assertEqual(len(cs),1);c=cs[0]
  self.assertEqual([s['name'] for s in c['stages']],['possible_recon','repeated_auth_failures','auth_success_after_failures','observed_reverse_shell'])
  self.assertEqual(c['stages'][-1]['parent_stage_ids'],[c['stages'][-2]['stage_id']]);self.assertEqual(c['risk_level'],'high');self.assertFalse(c['confirmed_compromise'])
  self.assertEqual(chains(list(reversed(rows()))),chains(rows()+rows()))
  docs=wire_events(c,'session','cases.json');self.assertTrue(docs[-2]['outgoing_syn_verified']);self.assertLess(max(len(json.dumps(d).encode()) for d in docs),6000)
 def test_no_process_or_syn_never_reverse(self):
  for es in (rows()[:-1],[e for e in rows() if e['event_id']!='callback-syn']):self.assertFalse(any(s['name']=='observed_reverse_shell' for c in chains(es) for s in c['stages']))
 def test_identity_and_direction_gates(self):
  for change in ({'username':'other'},{'source_port':40001},{'source_ip':'172.20.0.9'},{'sshd_pids':[124]},{'event_time':time_at(19)},{'event_time':time_at(37)}):
   e=event(raw());e.update(change);self.assertFalse(any(s['name']=='observed_reverse_shell' for c in chains(rows()[:-1]+[e]) for s in c['stages']),change)
  for change in ({'source_ip':'172.20.0.9'},{'destination_port':4445},{'source_port':45001},{'sensor_id':'other'}):
   es=[e for e in rows() if e['event_id']!='callback-syn']+[{**callback(),**change}];self.assertFalse(any(s['name']=='observed_reverse_shell' for c in chains(es) for s in c['stages']),change)
 def test_normal_login_never_callback(self):self.assertEqual(chains([accepted()]),[])
 def test_single_port_is_context_no_recon_or_bruteforce(self):
  contact=dict(kind='network.tcp_syn',event_time=time_at(0),event_id='contact',signature_id='9900003',sensor_id='ubuntu-endpoint',source_ip='172.20.0.4',target_ip='172.20.0.3',target_host='ubuntu-endpoint',source_port=49000,destination_port=22,flow_id='900')
  c=chains([contact,accepted(),callback(),event(raw())])[0];self.assertEqual([s['name'] for s in c['stages']],['ssh_service_contact','observed_ssh_session','observed_reverse_shell']);self.assertEqual(c['risk_score'],85);self.assertFalse(c['recon_observed'])
 def test_below_threshold_stays_context(self):
  c=chains([event(auth(10),'auth.log'),accepted(),callback(),event(raw())])[0];self.assertEqual(c['stages'][0]['name'],'observed_auth_failures')
 def test_invalid_evidence_rejected(self):
  with self.assertRaises(ValueError):normalize_line('proc.jsonl',json.dumps(raw()).encode(),{**CONFIG,'source_origins':{}})
  for changes in ({'observer_uid':False},{'observer_uid':1003},{'stdin_stdout_same_socket':False},{'process_id':'0'*64},{'executable':'/tmp/bash'},{'session_uid':0},{'peer_ip':'172.20.0.9'},{'sshd_pids':[124]},{'source_port':True}):
   with self.subTest(changes=changes),self.assertRaises(ValueError):event(raw(**changes))
 def test_idle_and_ambiguous_auth(self):
  e=event(raw(event_time=time_at(120)));s={**callback(),'event_time':time_at(119.9)}
  self.assertFalse(any(t['name']=='observed_reverse_shell' for c in chains(rows()[:-2]+[s,e]) for t in c['stages']))
  a={**accepted(),'event_id':'second-auth','event_time':time_at(20.1)};self.assertFalse(any(t['name']=='observed_reverse_shell' for c in chains(rows()+[a]) for t in c['stages']))
 def test_publisher_once(self):
  from live_activity import Activities
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),None);engine=SimpleNamespace(config=CONFIG,cases=build_cases(rows(),CONFIG),snapshot=Path(d)/'cases.json')
   with contextlib.redirect_stdout(io.StringIO()):a.publish_process_evidence(engine);a.publish_process_evidence(engine)
   es=[json.loads(x) for x in a.path.read_text().splitlines()];self.assertEqual(len(es),1);self.assertTrue(es[0]['outgoing_syn_verified']);self.assertFalse(es[0]['confirmed_compromise'])
 def test_observer_fd_requirements(self):
  r=dict(pid=300,process_id='p',executable='/usr/bin/bash',real_uid=1003,effective_uid=1003);conn=dict(source_ip='172.20.0.4',target_ip='172.20.0.3',session_uid=1003);net={'10':dict(local_ip='172.20.0.3',local_port=45000,peer_ip='172.20.0.4',peer_port=4444)}
  for fd in ({},{0:'10'},{0:'10',1:'11'}):self.assertEqual(observe(r,[],conn,net,fd,BOOT,time_at(25)),[])
  self.assertEqual(len(observe(r,[],conn,net,{0:'10',1:'10'},BOOT,time_at(25))),1);self.assertEqual(observe({**r,'executable':'/usr/bin/curl'},[],conn,net,{0:'10',1:'10'},BOOT,time_at(25)),[])
 def test_publickey_native_format_retains_pid(self):
  a=event(auth(20,'Accepted').replace(b'password',b'publickey').replace(b'ssh2',b'ssh2: ED25519 SHA256:fixture'),'auth.log')
  self.assertEqual(a['sshd_pid'],123);self.assertEqual(a['auth_method'],'publickey')
 def test_concurrent_sessions_keep_separate_branch(self):
  a=event(auth(21,'Accepted').replace(b'[123]',b'[124]').replace(b'40000',b'40001'),'auth.log')
  e=event(raw(pid=301,start_ticks=31,process_id=identity(BOOT,301,31),sshd_pids=[124],sshd_process_ids=[identity(BOOT,124,12)],ancestry_pids=[200,124],ancestry_process_ids=[identity(BOOT,200,20),identity(BOOT,124,12)],source_port=40001,local_port=45001,event_time=time_at(26)))
  net={**callback(),'event_id':'callback-2','source_port':45001,'event_time':time_at(25.9)}
  c=chains(rows()+[a,e,net])[0];steps=[s for s in c['stages'] if s['name']=='observed_reverse_shell'];self.assertEqual(len(steps),2)
  self.assertEqual(len({s['branch_id'] for s in steps}),2)
  for s in steps:
   parent=next(x for x in c['stages'] if x['stage_id']==s['parent_stage_ids'][0]);self.assertEqual(parent['branch_id'],s['branch_id'])
 def test_same_host_distinct_target_ips_do_not_share_failures(self):
  es=[event(auth(i),'auth.log') for i in range(10,14)]+[event(auth(i),'auth.log') for i in range(14,18)]
  for e in es[4:]:e['target_ip']='172.20.0.9'
  self.assertEqual(build_cases(es,CONFIG),[])
 def test_raw_collector_out_of_order_arrival(self):
  from lab_correlation import Correlator
  from test_lab_correlation import syn
  cfg={**CONFIG,'source_kinds':{**CONFIG['source_kinds'],'eve.jsonl':'eve'},'source_origins':{**CONFIG['source_origins'],'eve.jsonl':{'source_container':'ubuntu-endpoint'}}}
  with tempfile.TemporaryDirectory() as d:
   folder=Path(d);rawdir=folder/'raw';rawdir.mkdir()
   for n in cfg['source_kinds']:(rawdir/n).touch()
   engine=Correlator(rawdir,folder/'out',cfg)
   (rawdir/'proc.jsonl').write_text(json.dumps(raw())+'\n');engine.consume();self.assertEqual(engine.cases,[])
   (rawdir/'auth.log').write_bytes(b'\n'.join([auth(i) for i in range(10,18)]+[auth(20,'Accepted')])+b'\n');engine.consume()
   payload=[syn(0,port) for port in range(1,21)]+[{**syn(24.9,4444,fid=99999,dst='172.20.0.4'),'src_ip':'172.20.0.3','src_port':45000}]
   (rawdir/'eve.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in payload));engine.consume()
   self.assertEqual(engine.counts['invalid_source_records'],0);self.assertEqual(len(engine.chains),1)
   self.assertEqual(engine.chains[0]['stages'][-1]['name'],'observed_reverse_shell');self.assertEqual(len(engine.chains[0]['stages']),4)
   before=engine.chains;engine.consume();self.assertEqual(engine.chains,before)
 def test_installer_defensive_only(self):
  from setup_process_observer import INSTALL,candidate_config
  c=candidate_config({'assets':[{'host':'ubuntu-endpoint'}],'sources':[]},'ubuntu-endpoint');self.assertEqual(candidate_config(c,'ubuntu-endpoint'),c);self.assertNotIn('NOPASSWD',INSTALL);self.assertNotIn('root_proof',INSTALL)
if __name__=='__main__':unittest.main()
