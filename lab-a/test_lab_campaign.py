import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from lab_campaign import build_chains,http_cases,wire_events,validate
from lab_correlation import DEFAULTS,build_cases,digest
from test_lab_correlation import sequence,scan,time_at
CONFIG={**DEFAULTS,'attack_chain_enabled':True}
def http(t,i=0,status=200,duration=2000,sql=False,**changes):
    r={'kind':'web.sqli_indicator' if sql else 'web.request','event_time':time_at(t),
       'available_time':time_at(t+duration/1000000),'target_host':'ubuntu-endpoint',
       'source_ip':'172.20.0.4','target_ip':'172.20.0.3','destination_port':80,
       'evidence_provider':'apache_tsv','http_origin':'ubuntu-endpoint|apache.tsv',
       'http_record_id':f'request:{t}:{i}','http_status':status,'duration_us':duration,
       'request_target':'/?x=UNION%20SELECT' if sql else '/','success_proven':False}
    r.update(changes);r['event_id']='event:'+digest(r);r['source_refs']=[];return r
def mixed(degraded=False):
    return sequence()[:-1]+[http(22+i) for i in range(15)]+[http(40+i/20,i,status=503 if degraded else 200) for i in range(100)]+[http(55,sql=True)]
def chains(events,config=CONFIG):return build_chains(events,build_cases(events,config),config)
class CampaignTests(unittest.TestCase):
    def test_stable_scan_id_and_separate_branches(self):
        e=mixed();root=chains(e[:20])[0];partial=chains(e[:27])[0];full=chains(e)[0]
        self.assertEqual({c['chain_id'] for c in (root,partial,full)},{root['chain_id']})
        self.assertEqual([s['name'] for s in partial['stages']],['possible_recon','observed_auth_failures'])
        self.assertEqual(partial['risk_score'],40);self.assertEqual(full['risk_score'],80)
        self.assertEqual(len(full['branches']),3)
        self.assertEqual({s['name'] for s in full['stages']},{'possible_recon','repeated_auth_failures','http_request_pressure','possible_web_sqli'})
        for s in full['stages'][1:]:self.assertEqual(s['parent_stage_ids'],[full['stages'][0]['stage_id']])
        self.assertEqual(chains(list(reversed(e))),chains(e));self.assertFalse(full['confirmed_compromise'])
        self.assertIsNone(full['training_label'])
    def test_pressure_needs_healthy_baseline_and_degradation_for_possible_dos(self):
        self.assertNotIn('possible_http_dos',[s['name'] for c in http_cases(mixed(),CONFIG) for s in c['stages']])
        full=chains(mixed(True))[0];self.assertEqual(full['risk_score'],90)
        dos=next(s for s in full['stages'] if s['name']=='possible_http_dos')
        self.assertTrue(dos['healthy_baseline_observed']);self.assertFalse(dos['dos_causality_proven'])
        no_baseline=[http(40+i/20,i,status=503) for i in range(100)]
        self.assertEqual(http_cases(no_baseline,CONFIG)[0]['stages'][0]['name'],'http_request_pressure')
        self.assertEqual(http_cases([http(40+i/5,i) for i in range(33)],CONFIG),[])
        self.assertEqual(http_cases(no_baseline*2,CONFIG),http_cases(no_baseline,CONFIG))
    def test_missing_recon_other_entities_and_mlp_do_not_join_wrongly(self):
        self.assertFalse(chains([http(55,sql=True)])[0]['recon_observed'])
        for change in ({'source_ip':'172.20.0.9'},{'target_ip':'172.20.0.9'},{'target_host':'other'}):
            self.assertEqual(len(chains(scan()+[http(55,sql=True,**change)])),2)
        self.assertEqual(len(chains(scan()+[http(901,sql=True)])),2)
        self.assertEqual(chains([{'kind':'model_summary','predicted_label':'DoS','event_id':'model','event_time':time_at(10)}]),[])
    def test_wire_limits_revision_and_wazuh_json_types(self):
        docs=wire_events(chains(mixed(True))[0],'session','E:/SOC/cases.json')
        self.assertEqual(len({d['chain_revision_id'] for d in docs}),1)
        self.assertEqual(docs[-1]['stage_revision_count'],len(docs)-1)
        for d in docs:
            self.assertLess(len(json.dumps(d,ensure_ascii=False).encode()),6000)
            self.assertFalse(any(isinstance(x,dict) for v in d.values() if isinstance(v,list) for x in v))
    def test_delayed_recon_retires_standalone_instead_of_double_counting(self):
        from live_activity import Activities
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);a=Activities(root,None);before=chains([http(55,sql=True)]);after=chains(scan()+[http(55,sql=True)])
            with contextlib.redirect_stdout(io.StringIO()):
                a.publish_chains(SimpleNamespace(chains=before,snapshot=root/'cases.json'))
                a.publish_chains(SimpleNamespace(chains=after,snapshot=root/'cases.json'))
            rows=[json.loads(line) for line in a.path.read_text().splitlines()]
            retired=[r for r in rows if r.get('chain_active') is False]
            self.assertEqual(len(retired),1);self.assertEqual(retired[0]['superseded_by'],[after[0]['chain_id']])
    def test_config_and_legacy_mode(self):
        self.assertEqual(build_chains(sequence(),build_cases(sequence(),DEFAULTS),DEFAULTS),[])
        for setting in ({'attack_chain_enabled':1},{'http_pressure_threshold':True},{'chain_max_seconds':0}):
            with self.assertRaises(ValueError):validate(setting)
    def test_raw_http_live_capture_matches_independent_closed_replay(self):
        from lab_correlation import Correlator,instant
        from test_lab_correlation import syn,auth
        from chain_trace import verify
        config={**CONFIG,'source_kinds':{'a.log':'auth','e.json':'eve','web.tsv':'web'},
            'source_origins':{'e.json':{'source_container':'ubuntu-endpoint'},'web.tsv':{'source_container':'ubuntu-endpoint'}}}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);raw=root/'raw';raw.mkdir()
            (raw/'e.json').write_text('\n'.join(json.dumps(syn(0,p)) for p in range(1,21))+'\n')
            (raw/'a.log').write_bytes(b'\n'.join(auth(t) for t in range(10,18))+b'\n')
            lines=[]
            for e in mixed()[28:]:
                begin=int(instant(e['event_time']).timestamp()*1000000)
                target='/?x=UNION%20SELECT' if e['kind']=='web.sqli_indicator' else '/soc-lab-health'
                lines.append('\t'.join(map(str,[begin,begin+2000,e['source_ip'],41000,e['target_ip'],80,'GET',target,e['http_status'],33,2000,'test'])))
            (raw/'web.tsv').write_text('\n'.join(lines)+'\n')
            engine=Correlator(raw,raw,config)
            while engine.consume():pass
            engine.write('completed')
            self.assertEqual(len(engine.chains),1)
            self.assertEqual(engine.chains[0]['risk_score'],80)
            (raw/'session.json').write_text(json.dumps({'closed':True,'status':'completed','session_id':'test','sha256':{name:__import__('hashlib').sha256((raw/name).read_bytes()).hexdigest() for name in config['source_kinds']}}))
            operator={'complete':True,'capture_session_id':'test','required_stages':['possible_recon','repeated_auth_failures','http_pressure_or_degradation','possible_web_sqli']}
            result=verify(raw,operator);self.assertTrue(result['checks_passed'],result)
            self.assertFalse(result['manager_delivery_verified_by_this_check'])
            from manual_chain_review import review
            manual=review(raw)
            self.assertTrue(manual['checks_passed'],manual)
            self.assertFalse(manual['operator_intent_or_attack_success_verified'])

if __name__=='__main__':unittest.main()
