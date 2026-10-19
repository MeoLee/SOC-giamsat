"""Generate controlled normal HTTP, preserve logs, and match evidence to flows.

This is a data-collection tool, not an IP filter for AI Live. It does not train,
change weights, or convert model predictions into labels. Run separate sessions
for train/validation/test, without simultaneous attack traffic.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import uuid

from soc_ai.common import digest, sha256, write_json
from soc_ai.flow import FEATURE_HASH, features, normalize, parse_time, utc
from soc_live_collector import Collector
from lab_web import apache_tsv

PATHS=('/soc-lab-health','/dvwa/login.php')
SCHEMA='soc-lab-labeled-flow/0.1'

# All generated traffic uses GET, two fixed normal pages, no payload or credentials.
CLIENT_SCRIPT=r'''
import http.client,hashlib,json,random,subprocess,sys,time
from datetime import datetime,timezone
cfg=json.load(sys.stdin); rows=[]
rng=random.Random(cfg['seed'])
try:curl_agent='curl/'+subprocess.check_output(['curl','--version'],text=True).split()[1]
except (OSError,subprocess.SubprocessError):curl_agent='Python-http.client/3'
agents=(curl_agent,curl_agent,'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36')
def now():return datetime.now(timezone.utc).isoformat(timespec='microseconds')
for i in range(cfg['connections']):
    conn=http.client.HTTPConnection(cfg['server'],cfg['port'],timeout=10)
    group={'connection_id':i,'opened_at':now(),'requests':[],'user_agent':rng.choice(agents)}
    try:
        conn.connect()
        group['source_ip'],group['source_port']=conn.sock.getsockname()[:2]
        group['target_ip'],group['target_port']=conn.sock.getpeername()[:2]
        count=rng.choice((1,1,2,4))
        for j in range(count):
            path=rng.choice(('/soc-lab-health','/dvwa/login.php'))
            start=now()
            # Preserve ordinary curl-like headers; no dataset tag in network bytes.
            conn.putrequest('GET',path,skip_accept_encoding=True)
            conn.putheader('User-Agent',group['user_agent'])
            conn.putheader('Accept','*/*')
            conn.endheaders()
            if conn.sock and conn.sock.getsockname()[1]!=group['source_port']:
                raise RuntimeError('HTTP client reconnected unexpectedly')
            response=conn.getresponse(); body=response.read(2*1024*1024+1)
            if len(body)>2*1024*1024:raise RuntimeError('Response exceeds capture size limit')
            # Lower bound only: omit optional header spaces and chunk framing.
            version='HTTP/1.0' if response.version==10 else 'HTTP/1.1'
            minimum=(version+' '+str(response.status)+' '+response.reason+'\r\n'+
                ''.join(k+':'+v+'\r\n' for k,v in response.getheaders())+'\r\n').encode('latin-1',errors='replace')
            group['requests'].append({'method':'GET','path':path,'started_at':start,
                'ended_at':now(),'status':response.status,'body_bytes':len(body),
                'body_sha256':hashlib.sha256(body).hexdigest(),
                'minimum_response_payload_bytes':len(minimum)+len(body)})
            if response.status!=200:raise RuntimeError('Expected HTTP 200 on normal page')
            if j<count-1:
                if conn.sock is None:raise RuntimeError('Server closed keep-alive early')
                time.sleep(rng.choice((0,.1,.3)))
    except Exception as exc:group['error']=str(exc)
    finally:
        conn.close();group['closed_at']=now();rows.append(group)
    if group.get('error'):break
    time.sleep(rng.uniform(.25,.65))
print(json.dumps({'version':'soc-controlled-http-client/0.1','tag':cfg['tag'],'connections':rows}))
'''


def load_jsonl(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def flow_identity(flow):
    ends=sorted(((flow['src_ip'],flow['src_port']),(flow['dest_ip'],flow['dest_port'])))
    return digest([flow['protocol'],ends,flow['start_time'],flow['end_time']])


def select(events, requests, web_events, role, session_id):
    tag=requests['tag']; groups=defaultdict(list); stats=Counter(); selected=[]
    client_index=defaultdict(list); server_index=defaultdict(list)
    for item in requests['connections']:
        if item.get('error') or not item.get('requests'):
            stats['client_connections_failed']+=1;continue
        key=(item['source_ip'],item['source_port'],item['target_ip'],item['target_port'])
        client_index[key].append(item)
    for row in web_events:
        key=(row['source_ip'],row['source_port'],row['target_ip'],row['destination_port'])
        server_index[key].append(row)
    for event in events:
        if event.get('event_type')!='flow':continue
        try:
            flow=normalize(event)
        except (ValueError,TypeError,KeyError):
            stats['invalid_flow']+=1;continue
        key=(flow['src_ip'],flow['src_port'],flow['dest_ip'],flow['dest_port'])
        if key not in client_index:continue
        if (flow['protocol']!='TCP' or flow['app_protocol']!='http' or
            flow['duration_seconds']<=0 or flow['pkts_toserver']+flow['pkts_toclient']<=1 or
            flow['flow_reason']=='tcp_reuse'):
            stats['excluded_out_of_scope']+=1;continue
        groups[flow_identity(flow)].append((flow,event))
    matched_connections=set()
    for identity,observations in groups.items():
        flow,raw=observations[0]
        if any(not (features(flow)==features(other)).all() for other,_ in observations[1:]):
            stats['excluded_inconsistent_observations']+=1;continue
        key=(flow['src_ip'],flow['src_port'],flow['dest_ip'],flow['dest_port'])
        start,end=parse_time(flow['start_time']),parse_time(flow['end_time'])
        candidates=[c for c in client_index[key]
            if -1<=(start-parse_time(c['opened_at'])).total_seconds()
            and (end-parse_time(c['closed_at'])).total_seconds()<=1
            and parse_time(c['opened_at'])<=end and parse_time(c['closed_at'])>=start]
        if len(candidates)!=1:
            stats['excluded_client_time_ambiguity']+=1;continue
        c=candidates[0]
        observed=[row for row in server_index[key]
            if -1<=(parse_time(row['event_time'])-start).total_seconds()
            and (parse_time(row['event_time'])-end).total_seconds()<=1]
        if not observed:
            stats['excluded_no_server_evidence']+=1;continue
        if any(row['user_agent']!=c['user_agent'] or row['request_target'] not in PATHS or
               row['http_method']!='GET' or row['http_status']!=200 for row in observed):
            stats['excluded_other_or_failed_http_activity']+=1;continue
        client_counts=Counter((r['method'],r['path'],r['status'],r['body_bytes']) for r in c['requests'])
        server_counts=Counter((r['http_method'],r['request_target'],r['http_status'],r['response_body_bytes']) for r in observed)
        if client_counts!=server_counts:
            stats['excluded_request_count_or_size_mismatch']+=1;continue
        # Do not teach the model that a visibly truncated capture is a full HTTP exchange.
        payload_min=sum(r['minimum_response_payload_bytes'] for r in c['requests'])
        tcp_ip_min=40 if ipaddress.ip_address(flow['src_ip']).version==4 else 60
        if flow['bytes_toclient'] < payload_min+tcp_ip_min*flow['pkts_toclient']:
            stats['excluded_response_bytes_underflow']+=1;continue
        if raw.get('flow',{}).get('tx_cnt',len(observed))!=len(observed):
            stats['excluded_suricata_transaction_count_mismatch']+=1;continue
        flow={**flow,'record_id':'lab-flow:'+identity}
        selected.append({'schema_version':SCHEMA,'record_id':flow['record_id'],
            'session_id':session_id,'role':role,'label':'BENIGN','flow':flow,
            'label_method':'controlled_fixed_http_get_and_client_server_evidence',
            'evidence':{'client_connection_id':c['connection_id'],'client_manifest_tag':tag,'user_agent':c['user_agent'],
                'http_requests':len(observed),'paths':sorted({r['request_target'] for r in observed}),
                'server_record_ids':[r['record_id'] for r in observed]}})
        stats['duplicate_observations_removed']+=len(observations)-1
    # Never pick an arbitrary fragment if the sensor split one client connection.
    connection_counts=Counter(item['evidence']['client_connection_id'] for item in selected)
    stats['excluded_split_connection']=sum(n for n in connection_counts.values() if n!=1)
    selected=[item for item in selected if connection_counts[item['evidence']['client_connection_id']]==1]
    matched_connections={item['evidence']['client_connection_id'] for item in selected}
    stats['selected_records']=len(selected)
    return selected,dict(stats),matched_connections


def read_web(path):
    rows=[]
    with Path(path).open('rb') as stream:
        for raw in stream:
            if raw.strip():rows.append(apache_tsv(raw))
    return rows


def finish_collector(collector, complete):
    for source in collector.state['sources']:
        collector.finish_fragment(source,'normal-http-end')
    collector.state.update(closed=True,status='completed' if complete else 'incomplete',
        ended_at_utc=datetime.now(timezone.utc).isoformat())
    collector.state['sha256']={s['output']:sha256(collector.folder/s['output']) for s in collector.state['sources']}
    collector.save()


def collect(args):
    if not 30<=args.connections<=500:raise ValueError('connections must be 30..500')
    if not 30<=args.wait_seconds<=600:raise ValueError('wait-seconds must be 30..600')
    if ipaddress.ip_address(args.server).is_global:raise ValueError('Use a private lab target, not a public address')
    if args.source==args.sensor:raise ValueError('Client and sensor must be separate lab containers')
    check=subprocess.run(['docker','exec',args.sensor,'pgrep','-f',r'^([^[:space:]]*/)?suricata([[:space:]]|$)'],capture_output=True,timeout=15)
    if check.returncode:raise RuntimeError('Suricata not running; no traffic generated')
    tag='SOC-Normal-HTTP/'+uuid.uuid4().hex
    capture_args=SimpleNamespace(resume=None,from_start=False,docker_command='docker',
        output_dir=args.output_root,scenario_id='normal-http-'+args.role,
        sources=[('eve',args.sensor,'/var/log/suricata/eve.json','suricata-eve.jsonl'),
                 ('web',args.sensor,'/var/log/apache2/soc-lab-requests.tsv','apache-requests.tsv')])
    collector=Collector(capture_args); folder=collector.folder
    session_id='lab-session:'+digest([folder.name,tag,args.role])
    report={'version':'soc-lab-import/0.1','complete':False,'feature_hash':FEATURE_HASH,
        'label':'BENIGN','role':args.role,'session_id':session_id,
        'session_context':'controlled-normal-http-'+args.role,
        'policy':{'fixed_normal_pages_only':True,'client_and_apache_evidence_required':True,
                  'predictions_are_not_labels':True,'ip_is_collection_scope_not_observer_filter':True},
        'warnings':['Controlled GET requests only; these labels do not apply to arbitrary HTTP 200 traffic.',
                    'Separate capture sessions are required for train/validation/test.',
                    'This small baseline does not establish attack recall or production quality.']}
    write_json(folder/'report.json',report)
    print('CAPTURE:',folder,flush=True)
    print('Normal HTTP only; no sqlmap, no payloads. Do not run attacks during this capture.',flush=True)
    config={'server':args.server,'port':args.port,'connections':args.connections,'tag':tag,'seed':uuid.uuid4().int&0xffffffff}
    executor=ThreadPoolExecutor(max_workers=1); success=False
    try:
        # Bounded remote client; the host keeps collecting while it runs.
        future=executor.submit(subprocess.run,['docker','exec','-i',args.source,'python3','-c',CLIENT_SCRIPT],
            input=json.dumps(config).encode(),capture_output=True,timeout=args.connections*30+60)
        last_print=0
        while not future.done():
            collector.poll()
            if time.monotonic()-last_print>=10:
                print('GENERATING normal GET requests; server records=',collector.state['sources'][1]['records'],flush=True)
                last_print=time.monotonic()
            time.sleep(1)
        result=future.result()
        (folder/'client.stderr').write_bytes(result.stderr)
        if result.returncode:raise RuntimeError('HTTP client failed: '+result.stderr.decode(errors='replace')[-800:])
        requests=json.loads(result.stdout);write_json(folder/'client-requests.json',requests)
        if any(c.get('error') for c in requests['connections']):
            raise RuntimeError('Some normal requests failed; inspect client-requests.json. No complete import produced.')
        deadline=time.monotonic()+args.wait_seconds; selected=[];counts={};matched=set();last_print=0
        while time.monotonic()<deadline:
            more=collector.poll()
            selected,counts,matched=select(load_jsonl(folder/'suricata-eve.jsonl'),requests,
                read_web(folder/'apache-requests.tsv'),args.role,session_id)
            if len(matched)==args.connections and not more and not any(s['pending'] for s in collector.state['sources']):break
            if time.monotonic()-last_print>=10:
                print('WAITING for completed flows:',len(matched),'/',args.connections,
                      'remaining_seconds=',round(deadline-time.monotonic()),flush=True)
                last_print=time.monotonic()
            time.sleep(2)
        source_bad=collector.state['gaps'] or collector.state['partials'] or any(s['last_error'] or s['pending'] for s in collector.state['sources'])
        success=len(matched)==args.connections and not source_bad
        target=folder/'labeled-flows.jsonl'
        with target.open('x',encoding='utf-8',newline='\n') as stream:
            for item in selected:stream.write(json.dumps(item,ensure_ascii=False,allow_nan=False)+'\n')
        report.update(complete=success,counts=counts,
            generated_connections=args.connections,matched_connections=len(matched),
            unique_feature_vectors=len({features(item['flow']).tobytes() for item in selected}),
            data_sha256=sha256(target),inputs={name:{'path':str(folder/name),'sha256':sha256(folder/name)}
                for name in ('suricata-eve.jsonl','apache-requests.tsv','client-requests.json')})
        write_json(folder/'report.json',report)
        if not success:raise RuntimeError('Capture/import incomplete. Inspect report.json (including response_bytes_underflow for possible capture gaps). Raw logs were preserved; do not train with it.')
        write_json(Path(args.output_root)/'last-import.json',{'directory':str(folder),'role':args.role,'report_sha256':sha256(folder/'report.json')})
        print('NORMAL_HTTP_IMPORT_COMPLETE:',folder,flush=True)
        print(json.dumps({'role':args.role,'counts':counts,'unique_feature_vectors':report['unique_feature_vectors']},indent=2),flush=True)
        return folder
    finally:
        # Remote requests are bounded, so do not force-kill Docker or the sensor.
        executor.shutdown(wait=False,cancel_futures=True)
        finish_collector(collector,success)
        if collector.lock_file:collector.lock_file.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role',choices=('train','validation','test'),required=True)
    p.add_argument('--connections',type=int,default=120)
    p.add_argument('--source',default='kali-attacker');p.add_argument('--sensor',default='ubuntu-endpoint')
    p.add_argument('--server',default='172.20.0.3');p.add_argument('--port',type=int,default=80)
    p.add_argument('--wait-seconds',type=int,default=180)
    p.add_argument('--output-root',type=Path,default=Path(r'E:\SOC-Lab\AI\lab-data\normal-http'))
    a=p.parse_args()
    if not 1<=a.port<=65535:p.error('Invalid port')
    try:collect(a)
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as exc:
        p.exit(1,'ERROR: '+str(exc)+'\n')


if __name__=='__main__':main()
