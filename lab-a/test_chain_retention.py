"""Observed singleton expiry never erases evidence or expires formed chains."""
import contextlib
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from chain_unified import objects, workspace, reader, listing, HISTORY_QUERY, VISIBLE_EXPR
from lab_campaign import validate, wire_events
from lab_chain_episode import lifecycle
from lab_correlation import instant
from live_activity import Activities
from test_lab_campaign import chains, http, mixed
from test_lab_correlation import scan


class RetentionTests(unittest.TestCase):
    def test_singleton_pending_then_expires_at_idle_boundary(self):
        chain = chains(scan())[0]; last = instant(chain['last_seen'])
        config = validate({})
        for seconds, expected in ((0,'active'), (20,'waiting'), (89.999,'waiting'),
                                  (90,'expired_singleton'), (95,'expired_singleton')):
            state = lifecycle(chain, config, last+timedelta(seconds=seconds))
            self.assertEqual(state['chain_status'], expected)
            self.assertEqual(state['chain_active'], seconds<90)
            self.assertFalse(state['next_step_ready'])
            self.assertFalse(state['chain_end_proven'])

    def test_two_observed_stages_retained_after_long_idle(self):
        chain = chains(scan()+[http(55,sql=True)])[0]
        self.assertEqual(len(chain['stages']),2)
        for delay in (95,3600,86400):
            state = lifecycle(chain,validate({}),instant(chain['last_seen'])+timedelta(seconds=delay))
            self.assertEqual(state['chain_status'],'quiescent')
            self.assertEqual(state['chain_display_state'],'formed')
            self.assertTrue(state['chain_active']); self.assertTrue(state['next_step_ready'])
            self.assertFalse(state['chain_end_proven'])

    def test_configured_idle_threshold_is_respected(self):
        chain=chains(scan())[0]; last=instant(chain['last_seen'])
        config=validate({'chain_idle_seconds':120})
        self.assertTrue(lifecycle(chain,config,last+timedelta(seconds=95))['chain_active'])
        self.assertFalse(lifecycle(chain,config,last+timedelta(seconds=120))['chain_active'])

    def test_singleton_expiry_is_published_once_without_removing_raw_or_case(self):
        chain=chains(scan())[0]; last=instant(chain['last_seen'])
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); raw=root/'suricata-eve.jsonl'; raw.write_bytes(b'preserved raw evidence\n')
            snapshot=root/'correlation-cases.json'; snapshot.write_text(json.dumps({'chains':[chain]}))
            before={p:p.read_bytes() for p in (raw,snapshot)}
            activities=Activities(root); engine=SimpleNamespace(chains=[chain],snapshot=snapshot,config={})
            with contextlib.redirect_stdout(io.StringIO()):
                for delay in (0,20,90,95,200):
                    engine.evaluated_at=last+timedelta(seconds=delay);activities.publish_chains(engine)
            rows=[json.loads(line) for line in activities.path.read_text().splitlines()]
            summaries=[r for r in rows if r.get('soc_ai_kind')=='attack_chain']
            expired=[r for r in summaries if r['chain_status']=='expired_singleton']
            self.assertEqual(len(expired),1); self.assertFalse(expired[0]['chain_active'])
            self.assertEqual(expired[0]['chain_expiration_reason'],'single_observed_stage_idle_timeout')
            self.assertEqual(len({r['event_id'] for r in summaries}),3)
            self.assertEqual(len({r['event_id'] for r in rows if r.get('soc_ai_kind')=='chain_stage'}),1)
            for path,data in before.items(): self.assertEqual(path.read_bytes(),data)

    def test_second_action_inside_idle_promotes_same_chain(self):
        singleton=chains(scan())[0]
        formed=chains(scan()+[http(55,sql=True)])[0]
        self.assertEqual(singleton['chain_id'],formed['chain_id'])
        for doc in wire_events(formed,'session','cases.json'):
            self.assertTrue(doc['chain_formed']); self.assertEqual(doc['attack_chain_stage_count'],2)
        state=lifecycle(formed,validate({}),instant(formed['last_seen'])+timedelta(seconds=95))
        self.assertTrue(state['chain_active'])

    def test_new_action_after_gap_cannot_form_chain_with_expired_singleton(self):
        result=chains(scan()+[http(200,sql=True)])
        self.assertEqual(len(result),2)
        self.assertTrue(all(len(c['stages'])==1 for c in result))
        self.assertNotEqual(result[0]['chain_id'],result[1]['chain_id'])
        old_ids={e for s in result[0]['stages'] for e in s['evidence_ids']}
        new_ids={e for s in result[1]['stages'] for e in s['evidence_ids']}
        self.assertFalse(old_ids&new_ids)
        self.assertTrue(all(not lifecycle(c,validate({}),instant(c['last_seen'])+timedelta(seconds=95))['chain_active'] for c in result))

    def test_late_evidence_within_original_episode_can_correct_expired_candidate(self):
        # Arrival time is not event time. A real earlier action delivered late
        # can establish a previously unobserved multi-step episode.
        root=chains(scan())[0]; full=chains(scan()+[http(55,sql=True)])[0]
        now=instant(root['last_seen'])+timedelta(seconds=200)
        self.assertFalse(lifecycle(root,validate({}),now)['chain_active'])
        self.assertEqual(full['chain_id'],root['chain_id'])
        self.assertTrue(lifecycle(full,validate({}),now)['chain_active'])

    def test_many_requests_are_not_many_distinct_observed_steps(self):
        chain=chains([http(55+i/10,sql=True) for i in range(20)])[0]
        self.assertEqual(len(chain['stages']),1)
        state=lifecycle(chain,validate({}),instant(chain['last_seen'])+timedelta(seconds=95))
        self.assertFalse(state['chain_active'])

    def test_dashboard_filters_after_latest_and_has_one_live_visibility_clock(self):
        view=workspace(); data={r['name']:r for r in view['data']}
        self.assertEqual(data['records']['transform'][-1],{'type':'filter','expr':VISIBLE_EXPR})
        self.assertEqual(data['records']['transform'][0]['type'],'flatten')
        self.assertEqual(len([s for s in view['signals'] if s['name']=='visibilityNow']),1)
        self.assertIn('visibilityNow',VISIBLE_EXPR)
        self.assertIn('chain_last_seen_at',VISIBLE_EXPR)
        self.assertIn('>=2',VISIBLE_EXPR)
        self.assertIn('unmapped_type',json.dumps(data['records']['url']))
        self.assertIn('"0" or "1"',HISTORY_QUERY)
        search=next(o for o in objects() if o['type']=='search')
        self.assertEqual(json.loads(search['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])['query']['query'],HISTORY_QUERY)
        self.assertEqual(len(objects()),5)


if __name__=='__main__': unittest.main()
