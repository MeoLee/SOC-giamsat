"""Defensive fixtures only: no executable payloads or attack command generation."""
import json,unittest,tempfile,os,hashlib
from pathlib import Path
from unittest.mock import patch
from test_process_chain import CONFIG,raw,event,accepted,callback
from test_lab_correlation import scan,auth,time_at
from lab_correlation import build_cases,digest
from lab_campaign import build_chains,wire_events
from process_observer import SCHEMA
C={**CONFIG,'ssh_extended_chains_enabled':True,'artifact_observation_enabled':True,'ssh_contact_observations_enabled':True}
def file_event(kind='file.artifact_closed',t=22,**kw):
 r=dict(schema_version=SCHEMA,kind=kind,observer_uid=0,kernel_file_observation=True,event_time=time_at(t),artifact_path='/tmp/fixture.sh',artifact_sha256='a'*64,artifact_hash_complete=True,artifact_bytes=20,artifact_uid=1003,artifact_owner='labuser',artifact_device=1,artifact_inode=2,artifact_mtime_ns=3)
 if kind=='process.script_execution':r={**raw(event_time=time_at(t)),**r,'kernel_process_observation':True,'ssh_context_method':'live_ssh_ancestry'}
 r.update(kw)
 from lab_process_chain import normalize
 n=normalize(json.dumps(r).encode(),C,'proc.jsonl');return {**n,'event_id':digest(n),'source_refs':[]}
def chain(es):return build_chains(es,build_cases(es,C),C)
class ExtendedTests(unittest.TestCase):
 def test_small_failure_context_script_and_detached_callback(self):
  es=scan()+[event(auth(i),'auth.log') for i in (10,11,12)]+[accepted(),file_event(),file_event('process.script_execution',23),callback(),event(raw(ssh_context_method='environment_hint',sshd_pids=[],sshd_process_ids=[],ancestry_pids=[],ancestry_process_ids=[]))]
  c=chain(es)[0];names=[s['name'] for s in c['stages']]
  self.assertIn('observed_auth_failures',names);self.assertNotIn('repeated_auth_failures',names)
  for n in ('observed_script_file','observed_script_execution','observed_reverse_shell'):self.assertIn(n,names)
  self.assertEqual(c['risk_level'],'critical');self.assertTrue(c['reverse_shell_behavior_verified'])
  reverse=next(s for s in c['stages'] if s['name']=='observed_reverse_shell');self.assertFalse(reverse['native_ssh_session_verified'])
  self.assertIn('hypothesis',reverse['ssh_session_link_method'])
  self.assertFalse(next(s for s in c['stages'] if s['name']=='observed_script_file')['file_transport_verified'])
  self.assertEqual(chain(es),chain(list(reversed(es))+es))
  self.assertTrue(wire_events(c,'s','cases.json')[-1]['reverse_shell_behavior_verified'])
 def test_standalone_detached_behavior_not_lost_on_ambiguous_auth(self):
  e=event(raw(ssh_context_method='unavailable',source_port=0,sshd_pids=[],sshd_process_ids=[],ancestry_pids=[],ancestry_process_ids=[]))
  a={**accepted(),'event_id':'second','source_port':40001}
  cs=chain([accepted(),a,callback(),e]);self.assertTrue(any(c['risk_level']=='critical' for c in cs))
  for c in cs:
   for s in c['stages']:
    if s['name']=='observed_reverse_shell':self.assertFalse(s['native_ssh_session_verified'])
 def test_file_alone_never_actor_or_critical(self):self.assertEqual(chain([file_event()]),[])
 def test_different_user_or_idle_not_attributed(self):
  for f in (file_event(artifact_owner='other'),file_event(t=116)):
   self.assertFalse(any(s['name']=='observed_script_file' for c in chain([accepted(),f]) for s in c['stages']))
 def test_missing_syn_never_critical(self):
  cs=chain(scan()+[accepted(),event(raw())]);self.assertFalse(any(c['risk_level']=='critical' for c in cs))
 def test_malformed_script_ancestry_rejected(self):
  with self.assertRaises(ValueError):file_event('process.script_execution',ancestry_pids=[True])
 def test_metadata_never_content_and_refuses_symlink_fifo(self):
  import artifact_observer as a
  with tempfile.TemporaryDirectory() as d,patch.object(a,'WATCH_ROOTS',(d,)):
   p=Path(d)/'fixture.sh';p.write_text('benign fixture\n');m=a.metadata(p)
   self.assertEqual(m['artifact_sha256'],hashlib.sha256(p.read_bytes()).hexdigest());self.assertNotIn('content',m)
   link=Path(d)/'link.sh';link.symlink_to(p)
   with self.assertRaises(ValueError):a.metadata(link)
   fifo=Path(d)/'fifo.sh';os.mkfifo(fifo)
   with self.assertRaises(ValueError):a.metadata(fifo)
 def test_managed_rule_descriptions_english_and_critical_gate(self):
  import xml.etree.ElementTree as ET
  root=ET.fromstring(Path(__file__).with_name('soc_ai_bridge_rules.xml').read_text())
  rules={r.attrib['id']:r for r in root.findall('rule')}
  for r in rules.values():self.assertTrue(r.findtext('description').isascii())
  self.assertEqual(rules['119220'].attrib['level'],'15')
  gates={f.attrib['name'] for f in rules['119220'].findall('field')}
  self.assertTrue({'reverse_shell_behavior_verified','kernel_process_observation','stdin_stdout_same_socket','outgoing_syn_verified'}<=gates)
