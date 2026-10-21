import unittest,json,tempfile,contextlib,io
from pathlib import Path
from types import SimpleNamespace
from correlation_delivery import compact,LIMIT
from wazuh_bridge import encoded,make_event
class DeliveryTests(unittest.TestCase):
 def test_small_event_unchanged(self):
  r=make_event('correlation',['small'],case_status='observed_reverse_shell');self.assertEqual(compact(r,'local'),r)
 def test_unicode_and_oversized_metadata_bounded_without_mutating_full_event(self):
  r=make_event('correlation',['large'],case_status='observed_reverse_shell',attack_chain_json='x'*7000,chain_stage_details='á'*9000,activity='x'*9000,risk_level='critical',risk_score=95,confirmed_compromise=False)
  c=compact(r,'E:/session/live-activities.jsonl');self.assertLessEqual(len(encoded(c).encode()),LIMIT)
  self.assertEqual(c['event_id'],r['event_id']);self.assertEqual(c['risk_score'],95);self.assertEqual(len(r['chain_stage_details']),9000);self.assertTrue(c['delivery_compacted'])
 def test_optional_huge_field_uses_minimal_summary(self):
  r=make_event('correlation',['minimal'],unexpected='x'*100000,risk_score=95)
  c=compact(r,'local');self.assertLessEqual(len(encoded(c).encode()),LIMIT);self.assertTrue(c['delivery_minimal_summary'])
 def test_six_stage_long_path_publisher_keeps_running_and_local_full_event(self):
  from test_extended_chain import chain,file_event
  from test_process_chain import event,raw,accepted,callback,CONFIG
  from test_lab_correlation import scan,auth
  from live_activity import Activities
  from lab_correlation import build_cases
  es=scan()+[event(auth(t),'auth.log') for t in (10,11,12)]+[accepted(),file_event(),file_event('process.script_execution',23),callback(),event(raw())]
  cfg={**CONFIG,'ssh_extended_chains_enabled':True,'artifact_observation_enabled':True}
  rows=[];pub=SimpleNamespace(enqueue=rows.append,pending=0)
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),pub);engine=SimpleNamespace(config=cfg,cases=build_cases(es,cfg),events={},chains=[],snapshot=Path(d)/('long-path-'*350+'cases.json'))
   with contextlib.redirect_stdout(io.StringIO()):a.correlation(engine)
   local=[json.loads(x) for x in a.path.read_text().splitlines()]
   self.assertTrue(rows);self.assertTrue(local)
   self.assertTrue(any(r.get('delivery_compacted') for r in rows))
   self.assertTrue(all(len(encoded(r).encode())<=LIMIT for r in rows));self.assertIn('attack_chain_json',local[-1])
