"""Fail closed across actors, files, episodes and delayed VT responses."""
import base64,contextlib,copy,io,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from endpoint_probe import SCHEMA
from lab_correlation import DEFAULTS,normalize_line,digest,build_cases,instant,Correlator
from lab_campaign import build_chains,wire_events,validate
from lab_chain_episode import lifecycle
from test_lab_correlation import time_at,auth,scan,syn
from vt_lab_artifact import EICAR_SHA256,EICAR_MD5,EICAR_B64
TOKEN='a'*32
PATH='/var/lib/soc-lab/fim/vt-eicar-'+TOKEN+'.txt'
CONFIG={**DEFAULTS,'attack_chain_enabled':True,'source_kinds':{
    'endpoint.jsonl':'endpoint','auth.log':'auth','eve.jsonl':'eve','wazuh.jsonl':'wazuh'},
    'source_origins':{'endpoint.jsonl':{'source_container':'ubuntu-endpoint'},'eve.jsonl':{'source_container':'ubuntu-endpoint'}}}
def receiver(**changes):
    e=dict(schema_version=SCHEMA,lab_probe=True,kind='file.eicar_received',probe_id=TOKEN,
        source_ip='172.20.0.4',source_port=40000,target_ip='172.20.0.3',target_port=22,
        username='labuser',uid=1003,returncode=0,started_at=time_at(11),event_time=time_at(12),
        artifact_path=PATH,artifact_bytes=68,artifact_sha256=EICAR_SHA256,artifact_md5=EICAR_MD5,
        payload_verified=True,test_artifact=True,executed=False,transfer_method='ssh_stdin_fixed_eicar_receiver')
    e.update(changes);return e
def fim(**changes):
    e={'timestamp':time_at(12.1),'id':'fim.1','agent':{'id':'001','name':'ubuntu-endpoint'},
       'rule':{'id':'119253'},'syscheck':{'event':'added','path':PATH,'sha256_after':EICAR_SHA256,'md5_after':EICAR_MD5}}
    e.update(changes);return e
def vt(**changes):
    e={'timestamp':time_at(180),'id':'vt.1','agent':{'id':'001','name':'ubuntu-endpoint'},
       'rule':{'id':'87105'},'data':{'integration':'virustotal','virustotal':{
           'found':'1','malicious':'1','positives':'66','source':{'file':PATH,'alert_id':'fim.1','md5':EICAR_MD5}}}}
    e.update(changes);return e
def normalized(source,row):
    e=normalize_line(source,row if isinstance(row,bytes) else json.dumps(row).encode(),CONFIG)
    return None if e is None else {**e,'event_id':'event:'+digest(e),'source_refs':[]}
def evidence():
    return scan()+[normalized('auth.log',auth(10,'Accepted')),normalized('endpoint.jsonl',receiver()),
                   normalized('wazuh.jsonl',fim()),normalized('wazuh.jsonl',vt())]
def chains(events):return build_chains(events,build_cases(events,CONFIG),CONFIG)
class FileChainTests(unittest.TestCase):
    def test_two_stages_stable_chain_delayed_vt_updates_score_not_time(self):
        e=evidence();initial=chains(e[:-3])[0];received=chains(e[:-2])[0];full=chains(e)[0]
        self.assertEqual({c['chain_id'] for c in (initial,received,full)},{full['chain_id']})
        self.assertEqual([s['name'] for s in full['stages']],['possible_recon','observed_eicar_transfer'])
        self.assertEqual([c['risk_score'] for c in (received,full)],[50,85])
        self.assertEqual(full['stages'][-1]['vt_status'],'detected_test_file')
        self.assertEqual(len(full['stages'][-1]['evidence_ids']),4)
        self.assertEqual(full['last_seen'],received['last_seen']);self.assertFalse(full['confirmed_compromise'])
        self.assertEqual(chains(list(reversed(e))),chains(e+e))
        docs=wire_events(full,'session','cases.json',lifecycle(full,validate(CONFIG),instant(time_at(181))))
        self.assertTrue(docs[-1]['next_step_ready']);self.assertEqual(docs[-1]['attack_chain_stage_count'],2)
        self.assertEqual(docs[1]['vt_positives'],66);self.assertLess(max(len(json.dumps(d).encode()) for d in docs),6000)
    def test_no_receiver_or_auth_never_creates_transfer_stage(self):
        e=evidence();self.assertEqual(chains(e[-2:]),[])
        self.assertEqual(len(chains(e[:21]+e[-2:])[0]['stages']),1)
        self.assertEqual(chains([e[21]]),[])
    def test_exact_ssh_identity_and_time(self):
        for change in ({'source_ip':'172.20.0.9'},{'source_port':40001},{'username':'other'},
                       {'target_ip':'172.20.0.9'},{'target_host':'other'},
                       {'started_at':time_at(9)},{'started_at':time_at(71),'event_time':time_at(72)}):
            e=evidence();e[21]={**e[21],**change}
            with self.subTest(change=change):self.assertFalse(any(s['name']=='observed_eicar_transfer' for c in chains(e) for s in c['stages']))
    def test_unverified_receiver_rejected(self):
        for change in ({'artifact_sha256':'0'*64},{'artifact_md5':'0'*32},{'artifact_bytes':69},
                       {'artifact_path':'/tmp/eicar.txt'},{'probe_id':'b'*32},{'executed':True},
                       {'test_artifact':False},{'payload_verified':False},{'transfer_method':'scp'},
                       {'uid':0},{'source_port':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):normalized('endpoint.jsonl',receiver(**change))
        self.assertIsNone(normalized('endpoint.jsonl',receiver(returncode=1)))
        with self.assertRaises(ValueError):normalize_line('endpoint.jsonl',json.dumps(receiver()).encode(),{**CONFIG,'source_origins':{}})
    def test_vt_exact_fim_id_agent_path_hash_and_time(self):
        variants=[]
        for key,value in [('alert_id','other'),('file',PATH.replace(TOKEN,'b'*32)),('md5','0'*32)]:
            r=vt();r['data']['virustotal']['source'][key]=value;variants.append(r)
        variants += [vt(agent={'id':'999','name':'ubuntu-endpoint'}),vt(timestamp=time_at(4000)),
                     vt(timestamp=time_at(11)),vt(agent={'id':'001','name':'other'})]
        for raw in variants:
            e=evidence()[:-1];r=normalized('wazuh.jsonl',raw)
            if r:e.append(r)
            with self.subTest(raw=raw):self.assertEqual(chains(e)[0]['risk_score'],50)
    def test_fim_exact_hash_path_event_and_time(self):
        for change in ({'path':PATH.replace(TOKEN,'b'*32)},{'sha256_after':'0'*64},{'md5_after':'0'*32},{'event':'modified'}):
            raw=fim();raw['syscheck'].update(change);e=evidence();e.pop(-2);r=normalized('wazuh.jsonl',raw)
            if r:e.append(r)
            with self.subTest(change=change):self.assertEqual(chains(e)[0]['risk_score'],50)
        e=evidence();e[-2]['event_time']=time_at(90);self.assertEqual(chains(e)[0]['risk_score'],50)
    def test_no_positive_and_conflicting_reports_not_malware_verdict(self):
        raw=vt(rule={'id':'87104'});raw['data']['virustotal'].update(positives='0',malicious='0')
        c=chains(evidence()[:-1]+[normalized('wazuh.jsonl',raw)])[0]
        self.assertEqual(c['stages'][-1]['vt_status'],'no_positive_verdict');self.assertEqual(c['risk_score'],50)
        raw['id']='vt.2';c=chains(evidence()+[normalized('wazuh.jsonl',raw)])[0]
        self.assertEqual(c['stages'][-1]['vt_status'],'ambiguous_reports');self.assertEqual(c['risk_score'],50)
        self.assertEqual(chains(evidence()+[normalized('wazuh.jsonl',fim(id='fim.2'))])[0]['risk_score'],50)
    def test_idle_95_and_late_vt_never_resurrects_singleton(self):
        e=evidence()
        e[20]['event_time']=time_at(110);e[21].update(started_at=time_at(111),event_time=time_at(112));e[-2]['event_time']=time_at(112.1)
        result=chains(e);self.assertEqual(len(result),2);self.assertEqual([len(c['stages']) for c in result],[1,1])
        self.assertTrue(all(not lifecycle(c,validate(CONFIG),instant(time_at(300)))['chain_active'] for c in result))
        self.assertFalse(result[1]['recon_observed'])
    def test_different_tokens_and_accounts_separate_branches_and_verdicts(self):
        second=receiver(probe_id='b'*32,artifact_path=PATH.replace(TOKEN,'b'*32),username='other',source_port=40001,started_at=time_at(15),event_time=time_at(16))
        accepted=auth(14,'Accepted',user='other').replace(b'40000',b'40001')
        c=chains(evidence()+[normalized('endpoint.jsonl',second),normalized('auth.log',accepted)])[0]
        self.assertEqual(len(c['branches']),2);stages=c['stages'][1:]
        self.assertEqual([s['vt_status'] for s in stages],['detected_test_file','awaiting_fim_and_vt'])
        self.assertNotEqual(stages[0]['branch_id'],stages[1]['branch_id'])
    def test_raw_incremental_live_and_full_replay_match(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);raw=root/'raw';raw.mkdir()
            for name in CONFIG['source_kinds']:(raw/name).touch()
            engine=Correlator(raw,root/'out',CONFIG)
            inputs=[('wazuh.jsonl',json.dumps(vt())),('endpoint.jsonl',json.dumps(receiver())),('wazuh.jsonl',json.dumps(fim())),('auth.log',auth(10,'Accepted').decode())]
            for name,line in inputs:
                with (raw/name).open('a') as f:f.write(line+'\n')
                while engine.consume():pass
            (raw/'eve.jsonl').write_text('\n'.join(json.dumps(syn(0,p)) for p in range(1,21))+'\n')
            while engine.consume():pass
            replay=Correlator(raw,root/'replay',CONFIG)
            while replay.consume():pass
            self.assertEqual(engine.chains,replay.chains);self.assertEqual(engine.counts['invalid_source_records'],0)
            self.assertEqual(engine.chains[0]['risk_score'],85)
    @unittest.skipUnless(os.name=='posix','POSIX directory FDs')
    def test_actual_receiver_bytes_log_exclusive_write_no_execution(self):
        from eicar_receiver import receive
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);log=root/'endpoint.jsonl';log.touch();payload=base64.b64decode(EICAR_B64);original=os.fstat
            def owned(fd):return SimpleNamespace(st_uid=0,st_mode=original(fd).st_mode)
            with patch('eicar_receiver.ssh_context',return_value=receiver()),patch('eicar_receiver.os.fstat',side_effect=owned),contextlib.redirect_stdout(io.StringIO()):
                event=receive(TOKEN,io.BytesIO(payload),str(log),str(root))
                self.assertEqual(Path(event['artifact_path']).read_bytes(),payload);self.assertFalse(event['executed'])
                self.assertEqual(json.loads(log.read_text())['source_port'],40000)
                with self.assertRaises(FileExistsError):receive(TOKEN,io.BytesIO(payload),str(log),str(root))
                for bad in (b'bad',payload+b'x',payload[:-1]):
                    with self.assertRaises(ValueError):receive('b'*32,io.BytesIO(bad),str(log),str(root))
                self.assertFalse((root/('vt-eicar-'+'b'*32+'.txt')).exists())
    def test_one_dashboard_renamed_and_forecast_separate(self):
        from chain_unified import objects,DASHBOARD_ID
        from chain_profile import FOLLOW_UP
        rows=[r for r in objects() if r['type']=='dashboard']
        self.assertEqual([(r['id'],r['attributes']['title']) for r in rows],[(DASHBOARD_ID,'Attack Chain')])
        self.assertTrue(any(r['after']=='observed_eicar_transfer' for r in FOLLOW_UP))
if __name__=='__main__':unittest.main()
