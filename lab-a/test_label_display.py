import contextlib,io,json,tempfile,unittest
from pathlib import Path
from soc_ai.common import CLASSES,DISPLAY_CLASSES,display_label
from live_activity import Activities
from test_lab_live import flow

class DisplayTests(unittest.TestCase):
 def test_alias_does_not_change_model_contract(self):
  self.assertEqual(CLASSES[-1],'DDoS');self.assertEqual(DISPLAY_CLASSES[-1],'DoS')
  for label in CLASSES[:-1]:self.assertEqual(display_label(label),label)
 def test_threat_hunting_and_console(self):
  with tempfile.TemporaryDirectory() as d:
   a=Activities(Path(d),None);p={'predicted_label':'DDoS','decision':'possible_attack','attack_score':.9}
   out=io.StringIO()
   with contextlib.redirect_stdout(out):a.prediction(flow(),p);a.flush(force=True)
   row=json.loads(a.path.read_text().splitlines()[-1])
   self.assertEqual(row['predicted_label'],'DoS');self.assertEqual(row['model_predicted_label'],'DDoS')
   self.assertEqual(p['predicted_label'],'DDoS');self.assertIn('prediction=DoS',out.getvalue());self.assertNotIn('prediction=DDoS',out.getvalue())
 def test_generated_dashboard_no_distributed_description(self):
  from chain_unified import objects
  from chain_profile import STEPS,FOLLOW_UP
  self.assertNotIn('DDoS',json.dumps(objects(),ensure_ascii=False))
  self.assertNotIn('DDoS',json.dumps(STEPS+FOLLOW_UP,ensure_ascii=False))
if __name__=='__main__':unittest.main()
