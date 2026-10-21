"""Back up and remove only historical Lab A dashboard records after new import.

Default is a read-only plan. Never deletes visualizations, index patterns,
Wazuh native dashboards, alerts, indices, rules, logs or model files.
"""
import argparse,base64,getpass,json,ssl,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from chain_unified import DASHBOARD_ID
OLD_TITLES={'SOC Lab A - Attack Chain & Scoring','SOC Lab A - Chain Investigation',
            'SOC Lab A - Điều tra Chain','SOC Lab A - Hồ sơ Chain'}

def candidates(rows):
    return [r for r in rows if r.get('type')=='dashboard' and r.get('id')!=DASHBOARD_ID
            and r.get('attributes',{}).get('title') in OLD_TITLES]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url',required=True,help='Dashboard origin plus base path, e.g. https://localhost')
    p.add_argument('--username',default='admin');p.add_argument('--insecure',action='store_true',help='Allow lab self-signed TLS')
    p.add_argument('--apply',action='store_true');p.add_argument('--backup-dir',type=Path,default=Path('dashboard-backups'));a=p.parse_args()
    from urllib.parse import urlsplit,quote
    parts=urlsplit(a.url)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        p.error('Use an origin/base path without credentials, query or fragment')
    if parts.scheme=='http' and parts.hostname not in ('localhost','127.0.0.1','::1'):p.error('Use HTTPS for a remote dashboard')
    password=getpass.getpass('Wazuh Dashboard password (local input only): ')
    auth=base64.b64encode((a.username+':'+password).encode()).decode();base=a.url.rstrip('/')
    context=ssl._create_unverified_context() if a.insecure else ssl.create_default_context()
    def request(method,path,value=None):
        req=urllib.request.Request(base+path,data=json.dumps(value).encode() if value is not None else None,method=method,
            headers={'Authorization':'Basic '+auth,'osd-xsrf':'true','Content-Type':'application/json'})
        with urllib.request.urlopen(req,context=context,timeout=30) as r:return r.read()
    current=json.loads(request('GET','/api/saved_objects/dashboard/'+DASHBOARD_ID))
    if current.get('attributes',{}).get('title') not in ('Attack Chain','SOC Lab A - Attack Chain'):raise ValueError('Import the new dashboard before cleanup')
    rows=[];page=1
    while True:
        result=json.loads(request('GET',f'/api/saved_objects/_find?type=dashboard&per_page=100&page={page}'))
        rows+=result['saved_objects']
        if len(rows)>=result['total']:break
        page+=1
    old=candidates(rows);print(json.dumps({'delete_dashboard_records':[{'id':r['id'],'title':r['attributes']['title']} for r in old],
        'keep':DASHBOARD_ID,'apply':a.apply},ensure_ascii=False,indent=2))
    if not a.apply or not old:return
    backup=request('POST','/api/saved_objects/_export',{'objects':[{'type':'dashboard','id':r['id']} for r in old],
                                                      'includeReferencesDeep':False})
    exported=[json.loads(line) for line in backup.decode().splitlines() if line.strip()]
    if {r['id'] for r in old}!={r['id'] for r in exported if r.get('type')=='dashboard'}:
        raise RuntimeError('Export incomplete; no dashboards deleted')
    a.backup_dir.mkdir(parents=True,exist_ok=True)
    path=a.backup_dir/('legacy-chain-dashboards-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.ndjson')
    with path.open('xb') as f:
        f.write(backup);f.flush();__import__('os').fsync(f.fileno())
    print('BACKUP:',path)
    for r in old:request('DELETE','/api/saved_objects/dashboard/'+quote(r['id'],safe=''))
    print('LEGACY_DASHBOARD_RECORDS_REMOVED:',len(old))
if __name__=='__main__':main()
