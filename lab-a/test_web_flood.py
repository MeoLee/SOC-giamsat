"""DVWA rate/degradation evidence and bounded load-client contracts."""
import contextlib,io,json,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import http.server
import http.client
from test_lab_campaign import http as http_event,CONFIG as BASE_CONFIG,chains
from test_lab_correlation import scan,time_at,syn
from lab_campaign import http_cases,wire_events,validate
from lab_correlation import digest,Correlator,instant
from live_activity import Activities
import dvwa_web_flood as client

ROUTE='/dvwa/login.php'
CONFIG={**BASE_CONFIG,'http_load_alerts_enabled':True}
def row(t,i=0,**changes):
    e=http_event(t,i,http_method='GET',url_path=ROUTE,request_target=ROUTE,**changes)
    e['event_id']='event:'+digest(e);return e
def baseline(**changes):return [row(i,i,**changes) for i in range(20)]
def burst(**changes):return [row(30+i/40,i,**changes) for i in range(100)]
def detection(events):return http_cases(events,CONFIG)[0]['stages'][0]

class WebFloodTests(unittest.TestCase):
    def test_volume_only_pressure_and_same_route_slowdown_dos(self):
        healthy=detection(baseline()+burst());self.assertEqual(healthy['name'],'http_request_pressure')
        self.assertTrue(healthy['healthy_baseline_observed']);self.assertEqual(healthy['baseline_request_count'],20)
        degraded=detection(baseline()+burst(duration=1500000))
        self.assertEqual(degraded['name'],'possible_http_dos');self.assertEqual(degraded['http_route'],ROUTE)
        self.assertEqual(degraded['window_rate_rps'],10);self.assertEqual(degraded['burst_p95_us'],1500000)
        self.assertFalse(degraded['dos_causality_proven'])
    def test_route_method_origin_and_service_baselines_do_not_mix(self):
        for change in ({'url_path':'/soc-lab-health'},{'http_method':'POST'},
                       {'target_ip':'172.20.0.9'},{'http_origin':'other|web.tsv'},{'destination_port':8080}):
            b=baseline()
            for e in b:e.update(change)
            with self.subTest(change=change):
                s=detection(b+burst(duration=2000000));self.assertFalse(s['healthy_baseline_observed']);self.assertEqual(s['name'],'http_request_pressure')
    def test_relative_latency_not_just_one_second_and_redirect_baseline_valid(self):
        s=detection(baseline(duration=400000)+burst(duration=1500000))
        self.assertEqual(s['name'],'http_request_pressure');self.assertEqual(s['slow_us'],2000000)
        self.assertEqual(detection(baseline(duration=400000)+burst(duration=2500000))['name'],'possible_http_dos')
        self.assertEqual(detection(baseline(status=302)+burst(status=503))['name'],'possible_http_dos')
    def test_missing_unhealthy_or_not_yet_available_baseline_never_dos(self):
        b=baseline()
        for e in b:e['available_time']=time_at(50)
        for prior in ([],baseline()[:9],baseline(status=503),b):
            with self.subTest(prior=len(prior)):
                self.assertEqual(detection(prior+burst(status=503))['name'],'http_request_pressure')
    def test_twenty_percent_and_minimum_samples_and_4xx_not_degradation(self):
        for count,expected in ((19,'http_request_pressure'),(20,'possible_http_dos')):
            b=burst()
            for e in b[:count]:e['http_status']=503
            self.assertEqual(detection(baseline()+b)['name'],expected)
        self.assertEqual(detection(baseline()+burst(status=404))['name'],'http_request_pressure')
    def test_low_rate_baseline_not_part_of_scan_followup_onset(self):
        events=baseline()+scan(25)+burst()
        c=chains(events)[0];self.assertEqual(len(c['stages']),2)
        self.assertEqual(c['stages'][-1]['start_time'],time_at(30));self.assertEqual(c['risk_score'],55)
        self.assertEqual(http_cases([row(i,i) for i in range(100)],CONFIG),[])
    def test_delayed_duplicate_and_shuffled_views_do_not_inflate(self):
        events=baseline()+burst(status=503)
        self.assertEqual(http_cases(events,CONFIG),http_cases(list(reversed(events))+events,CONFIG))
        self.assertEqual(http_cases([{'kind':'model_summary','predicted_label':'DoS'}],CONFIG),[])
    def test_partial_window_progression_stable_case_and_chain_ids(self):
        b=burst()
        for e in b[60:]:e['duration_us']=1500000;e['available_time']=time_at(35)
        first=http_cases(baseline()+b[:60],CONFIG)[0];last=http_cases(baseline()+b,CONFIG)[0]
        self.assertEqual(first['case_id'],last['case_id'])
        self.assertEqual(first['stages'][0]['name'],'http_request_pressure');self.assertEqual(last['stages'][0]['name'],'possible_http_dos')
        a=chains(baseline()+scan(25)+b[:60])[0];z=chains(baseline()+scan(25)+b)[0]
        self.assertEqual(a['chain_id'],z['chain_id']);self.assertEqual(z['risk_score'],85)
        docs=wire_events(z,'session','cases.json');self.assertEqual(docs[-2]['burst_p95_us'],1500000)
    def test_pressure_alert_metadata_emitted_once_per_revision_without_mlp(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);a=Activities(root,None);events=baseline()+burst(status=503)
            engine=SimpleNamespace(events={e['event_id']:e for e in events},config=CONFIG,snapshot=root/'cases.json')
            with contextlib.redirect_stdout(io.StringIO()):a.publish_http_load(engine);a.publish_http_load(engine)
            docs=[json.loads(x) for x in a.path.read_text().splitlines()]
            self.assertEqual(len(docs),1);d=docs[0]
            self.assertEqual(d['soc_ai_kind'],'http_load');self.assertTrue(d['service_degradation_observed'])
            self.assertEqual(d['risk_level'],'high');self.assertFalse(d['confirmed_compromise'])
            self.assertLess(len(json.dumps(d,ensure_ascii=False).encode()),6000)
    def test_raw_tsv_preserves_path_method_and_replay(self):
        config={**CONFIG,'source_kinds':{'web.tsv':'web','eve.jsonl':'eve'},
            'source_origins':{'web.tsv':{'source_container':'ubuntu-endpoint'},'eve.jsonl':{'source_container':'ubuntu-endpoint'}}}
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);raw=root/'raw';raw.mkdir();(raw/'web.tsv').touch();(raw/'eve.jsonl').touch()
            engine=Correlator(raw,root/'out',config)
            def append(rows):
                with (raw/'web.tsv').open('a') as f:
                    for e in rows:
                        start=int(instant(e['event_time']).timestamp()*1e6);elapsed=e['duration_us']
                        f.write('\t'.join(map(str,[start,start+elapsed,e['source_ip'],40000,e['target_ip'],80,'GET',e['url_path'],e['http_status'],100,elapsed,'fixture']))+'\n')
                while engine.consume():pass
            append(baseline());(raw/'eve.jsonl').write_text('\n'.join(json.dumps(syn(25,p)) for p in range(1,21))+'\n')
            append(burst(status=503));replay=Correlator(raw,root/'replay',config)
            while replay.consume():pass
            self.assertEqual(engine.chains,replay.chains);self.assertEqual(engine.counts['invalid_source_records'],0)
            self.assertEqual(engine.chains[0]['stages'][-1]['http_route'],ROUTE)
            self.assertEqual(engine.chains[0]['stages'][-1]['name'],'possible_http_dos')
    def test_load_bounds_public_targets_and_no_credential_fields(self):
        for kwargs in ({'requests':1001},{'rate':float('nan')},{'concurrency':17},{'path':'/arbitrary'},
                       {'requests':1000,'rate':1},{'phase':'baseline','rate':40}):
            a=dict(phase='flood',requests=100,rate=40,concurrency=8,timeout=2,path=ROUTE);a.update(kwargs)
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):client.validate(**a)
        with self.assertRaises(ValueError):client.target_ip('8.8.8.8')
        lock=threading.Lock();active=[0,0]
        def worker(*args):
            with lock:active[0]+=1;active[1]=max(active)
            time.sleep(.02)
            with lock:active[0]-=1
            return {'outcome':'200','latency_ms':20}
        with contextlib.redirect_stdout(io.StringIO()):r=client.run('172.20.0.3','flood',8,100,3,1,ROUTE,worker)
        self.assertEqual(r['started'],8);self.assertLessEqual(active[1],3);self.assertFalse(r['dos_success_proven'])
        self.assertFalse(r['credentials_saved']);self.assertFalse(r['cookies_saved'])
    def test_actual_client_get_response_redirect_not_followed_and_timeout_bounded(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path==ROUTE:code=200
                elif self.path=='/dvwa/':code=302
                else:time.sleep(.6);code=200
                self.send_response(code)
                if code==302:self.send_header('Location','http://example.invalid/')
                self.end_headers()
                try:self.wfile.write(b'lab fixture')
                except OSError:pass
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        real=http.client.HTTPConnection
        try:
            with patch.object(client.http.client,'HTTPConnection',side_effect=lambda target,port,timeout:real('127.0.0.1',server.server_port,timeout=timeout)):
                self.assertEqual(client.request('172.20.0.3',ROUTE,1)['outcome'],'200')
                self.assertEqual(client.request('172.20.0.3','/dvwa/',1)['outcome'],'302')
                start=time.monotonic();r=client.request('172.20.0.3','/dvwa/index.php',.2)
                self.assertEqual(r['outcome'],'timeout_or_transport_error');self.assertLess(time.monotonic()-start,.5)
        finally:server.shutdown();server.server_close();thread.join()
    def test_configuration_inconsistent_baseline_rejected(self):
        with self.assertRaises(ValueError):validate({'http_baseline_minimum':30,'http_baseline_maximum':20})

if __name__=='__main__':unittest.main()
