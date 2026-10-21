from datetime import timedelta
from types import SimpleNamespace
from pathlib import Path
import contextlib,io,json,tempfile,unittest
from test_lab_campaign import chains,mixed,http,CONFIG
from lab_correlation import instant,stamp,digest
from lab_campaign import wire_events
from lab_chain_episode import lifecycle


def shift(events,seconds,source=None):
    output=[]
    for original in events:
        e=dict(original)
        for k in ('event_time','available_time','started_at'):
            if k in e:e[k]=stamp(instant(e[k])+timedelta(seconds=seconds))
        if source:e['source_ip']=source
        if 'http_record_id' in e:e['http_record_id']+=':'+str(seconds)
        e['event_id']='shift:'+digest(e);output.append(e)
    return output

class EpisodeTests(unittest.TestCase):
    def test_fresh_scan_separates_two_chains_inside_old_600_second_window(self):
        events=mixed()+shift(mixed(),75)
        result=chains(events)
        self.assertEqual(len(result),2)
        sets=[{eid for s in c['stages'] for eid in s['evidence_ids']} for c in result]
        self.assertFalse(sets[0]&sets[1]);self.assertEqual([c['risk_score'] for c in result],[80,80])
        self.assertEqual(chains(list(reversed(events))),result)
    def test_idle_gap_without_new_scan_does_not_reuse_previous_chain(self):
        events=mixed()+[http(200,sql=True)]
        result=chains(events)
        self.assertEqual(len(result),2);self.assertFalse(result[1]['recon_observed'])
        self.assertEqual(result[1]['risk_score'],60)
    def test_source_scope_and_account_branch_ownership(self):
        result=chains(mixed()+shift(mixed(),0,source='172.20.0.9'))
        self.assertEqual(len(result),2)
        for c in result:
            docs=wire_events(c,'session','cases.json')
            self.assertTrue(all(d['source_ip']==c['source_ip'] for d in docs))
            parents={s['stage_id'] for s in c['stages']}
            self.assertTrue(all(set(s['parent_stage_ids'])<=parents for s in c['stages']))
    def test_five_stage_probe_remains_bound_to_auth_session_and_has_positions(self):
        from test_lab_endpoint import action
        from test_lab_correlation import sequence
        result=chains(sequence()+[action(),action('file.transfer')])
        self.assertEqual(len(result),1)
        self.assertEqual([s['stage_position'] for s in result[0]['stages']],[0,1,2,3,4])
        self.assertEqual(result[0]['risk_score'],95)
        self.assertEqual(len({s['stage_id'] for s in result[0]['stages']}),5)

    def test_runtime_quiescence_is_not_proof_of_attack_end_or_a_probability(self):
        c=chains(mixed())[0];last=instant(c['last_seen'])
        from lab_campaign import validate
        cfg=validate(CONFIG)
        for seconds,status in ((0,'active'),(20,'waiting'),(90,'quiescent')):
            state=lifecycle(c,cfg,last+timedelta(seconds=seconds))
            self.assertEqual(state['chain_status'],status)
            self.assertEqual(state['next_step_ready'],seconds==90)
            self.assertFalse(state['chain_end_proven']);self.assertFalse(state['next_step_probability_calibrated'])
    def test_lifecycle_republishes_summary_once_per_state_without_stage_duplication(self):
        from live_activity import Activities
        c=chains(mixed())[0];last=instant(c['last_seen'])
        with tempfile.TemporaryDirectory() as folder:
            a=Activities(Path(folder));engine=SimpleNamespace(chains=[c],snapshot=Path(folder)/'cases.json',config=CONFIG,evaluated_at=last)
            with contextlib.redirect_stdout(io.StringIO()):
                for delay in (0,1,20,21,90,100):
                    engine.evaluated_at=last+timedelta(seconds=delay);a.publish_chains(engine)
            rows=[json.loads(l) for l in a.path.read_text().splitlines()]
            summaries=[r for r in rows if r['soc_ai_kind']=='attack_chain']
            self.assertEqual([r['chain_status'] for r in summaries],['active','waiting','quiescent'])
            self.assertEqual(len({r['chain_revision_id'] for r in summaries}),1)
            self.assertEqual(len({r['event_id'] for r in summaries}),3)
            self.assertEqual(len({r['event_id'] for r in rows if r['soc_ai_kind']=='chain_stage'}),4)

if __name__=='__main__':unittest.main()
