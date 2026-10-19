from copy import deepcopy
from datetime import datetime,timedelta,timezone
import importlib.util
import sys
import unittest
from collect_normal_http import select, CLIENT_SCRIPT
from lab_web import apache_tsv
from quality_audit import analyze


def fixture():
    start=datetime(2026,10,15,6,36,24,tzinfo=timezone.utc)
    end=start+timedelta(milliseconds=80)
    event={'event_type':'flow','record_id':'original','timestamp':(end+timedelta(seconds=61)).isoformat(),
        'src_ip':'172.20.0.4','src_port':40778,'dest_ip':'172.20.0.3','dest_port':80,
        'proto':'TCP','app_proto':'http','flow':{'start':start.isoformat(),'end':end.isoformat(),
        'pkts_toserver':6,'pkts_toclient':3,'bytes_toserver':492,'bytes_toclient':206,
        'state':'closed','reason':'timeout','age':0,'tx_cnt':1}}
    tag='SOC-Normal-HTTP/test-session'
    client={'tag':tag,'connections':[{'connection_id':0,'user_agent':tag,'opened_at':start.isoformat(),
        'closed_at':end.isoformat(),'source_ip':'172.20.0.4','source_port':40778,
        'target_ip':'172.20.0.3','target_port':80,'requests':[{'method':'GET','path':'/soc-lab-health',
        'status':200,'body_bytes':11,'minimum_response_payload_bytes':31}]}]}
    micro=int(start.timestamp())*1000000+10000
    raw=f'{micro}\t{micro+1000}\t172.20.0.4\t40778\t172.20.0.3\t80\tGET\t/soc-lab-health\t200\t11\t1000\t{tag}\n'.encode()
    return event,client,apache_tsv(raw)


class EvidenceTests(unittest.TestCase):
    def choose(self,e=None,c=None,w=None):
        a,b,d=fixture()
        return select([e or a],c or b,[w or d],'train','lab-session:test')
    def test_both_evidence_sources_required(self):
        e,c,w=fixture()
        self.assertEqual(len(self.choose()[0]),1)
        self.assertEqual(select([e],c,[],'train','s')[0],[])
    def test_wrong_user_agent_not_labeled(self):
        e,c,w=fixture();w['user_agent']='other-client'
        self.assertEqual(self.choose(w=w)[0],[])
    def test_wrong_port_not_labeled(self):
        e,c,w=fixture();w['source_port']+=1
        self.assertEqual(self.choose(w=w)[0],[])
    def test_old_same_port_not_labeled(self):
        e,c,w=fixture();e['flow']['start']='2026-10-14T00:00:00Z';e['flow']['end']='2026-10-14T00:00:01Z'
        self.assertEqual(self.choose(e=e)[0],[])
    def test_payload_in_query_not_labeled(self):
        e,c,w=fixture();w['request_target']="/soc-lab-health?id=1' UNION SELECT"
        self.assertEqual(self.choose(w=w)[0],[])
    def test_bad_status_not_labeled(self):
        e,c,w=fixture();w['http_status']=500
        self.assertEqual(self.choose(w=w)[0],[])
    def test_response_size_must_match(self):
        e,c,w=fixture();w['response_body_bytes']+=1
        self.assertEqual(self.choose(w=w)[0],[])
    def test_unmatched_extra_request_excludes_connection(self):
        e,c,w=fixture();other=deepcopy(w);other['user_agent']='sqlmap'
        self.assertEqual(select([e],c,[w,other],'train','s')[0],[])
    def test_incomplete_response_capture_not_labeled(self):
        e,c,w=fixture();c['connections'][0]['requests'][0]['minimum_response_payload_bytes']=500
        rows,stats,_=self.choose(c=c)
        self.assertEqual(rows,[]);self.assertEqual(stats['excluded_response_bytes_underflow'],1)
    def test_server_and_sensor_transaction_counts_must_agree(self):
        e,c,w=fixture();e['flow']['tx_cnt']=2
        self.assertEqual(self.choose(e=e)[0],[])
    def test_failed_client_not_labeled(self):
        e,c,w=fixture();c['connections'][0]['error']='connection closed'
        self.assertEqual(self.choose(c=c)[0],[])
    def test_repeated_views_deduplicate(self):
        e,c,w=fixture();other=deepcopy(e);other['flow_id']=999
        rows,stats,matched=select([e,other],c,[w],'train','s')
        self.assertEqual(len(rows),1);self.assertEqual(stats['duplicate_observations_removed'],1)
    def test_split_connection_not_arbitrarily_selected(self):
        e,c,w=fixture();other=deepcopy(e)
        other['flow']['start']='2026-10-15T06:36:24.005000Z'
        self.assertEqual(select([e,other],c,[w],'train','s')[0],[])
    def test_inconsistent_flow_observations_excluded(self):
        e,c,w=fixture();other=deepcopy(e);other['flow']['bytes_toserver']+=1
        self.assertEqual(select([e,other],c,[w],'train','s')[0],[])
    def test_label_identity_compatible_with_existing_mixer(self):
        from import_lab_normal import identity
        rows,_,_=self.choose();row=rows[0]
        self.assertEqual(row['record_id'],'lab-flow:'+identity(row['flow']))
        self.assertEqual(row['label'],'BENIGN');self.assertEqual(row['role'],'train')
    def test_zero_duration_excluded(self):
        e,c,w=fixture();e['flow']['end']=e['flow']['start']
        self.assertEqual(self.choose(e=e)[0],[])
    def test_remote_client_script_compiles(self):
        compile(CLIENT_SCRIPT,'controlled-http-client','exec')
    def test_fractional_duration_audit_and_identity(self):
        e,c,w=fixture();p={'record_id':e['record_id'],'src_ip':e['src_ip'],'dest_ip':e['dest_ip'],
            'src_port':e['src_port'],'dest_port':e['dest_port'],'predicted_label':'DDoS'}
        row=analyze([e],[p])[0]
        self.assertEqual(row['duration_seconds'],.08);self.assertEqual(row['packets'],9)
        self.assertFalse(row['label_verified_by_this_audit'])
        p['src_port']=5
        with self.assertRaises(ValueError):analyze([e],[p])



class HostCollectionTests(unittest.TestCase):
    def test_host_capture_writes_complete_import_after_all_evidence_matches(self):
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        import collect_normal_http as module
        event,client,web=fixture()
        connections=[];events=[];web_lines=[]
        for i in range(30):
            e=deepcopy(event);e['src_port']+=i;events.append(e)
            c=deepcopy(client['connections'][0]);c['connection_id']=i;c['source_port']+=i;connections.append(c)
            web_lines.append(f"1792046184010000\t1792046184011000\t172.20.0.4\t{40778+i}\t172.20.0.3\t80\tGET\t/soc-lab-health\t200\t11\t1000\t{client['tag']}\n")
        class FakeCollector:
            def __init__(self,args):
                self.folder=Path(args.output_dir)/'raw'/'fixture';self.folder.mkdir(parents=True)
                (self.folder/'suricata-eve.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
                (self.folder/'apache-requests.tsv').write_text(''.join(web_lines))
                self.lock_file=(self.folder/'lock').open('wb')
                self.state={'sources':[{'output':'suricata-eve.jsonl','pending':'','last_error':None,'records':30},
                    {'output':'apache-requests.tsv','pending':'','last_error':None,'records':30}], 'gaps':[],'partials':[]}
            def poll(self):return False
            def save(self):pass
            def finish_fragment(self,*a):pass
        result=SimpleNamespace(returncode=0,stdout=json.dumps({'tag':client['tag'],'connections':connections}).encode(),stderr=b'')
        with tempfile.TemporaryDirectory() as d,patch.object(module,'Collector',FakeCollector),patch.object(module.subprocess,'run',return_value=result):
            args=SimpleNamespace(connections=30,wait_seconds=30,server='172.20.0.3',port=80,
                source='kali-attacker',sensor='ubuntu-endpoint',role='train',output_root=Path(d))
            folder=module.collect(args)
            report=json.loads((folder/'report.json').read_text())
            self.assertTrue(report['complete']);self.assertEqual(report['counts']['selected_records'],30)
            self.assertEqual(len((folder/'labeled-flows.jsonl').read_text().splitlines()),30)
            self.assertTrue((Path(d)/'last-import.json').exists())

if __name__=='__main__':unittest.main()
