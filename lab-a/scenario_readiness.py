"""Read-only private-lab readiness report. Never prints passwords or config bodies."""
import argparse,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
from soc_ai.common import write_json
from live_config import load_config
from wazuh_scenarios import lab_scope

AGENT_CHECK=r'''
import json,os,pathlib,shutil,re,xml.etree.ElementTree as ET
p=pathlib.Path('/var/ossec/etc/ossec.conf')
r=ET.fromstring('<document>'+re.sub(r'<\?xml[^>]*\?>','',p.read_text())+'</document>')
syschecks=list(r.iter('syscheck'))
def state(name):
 p=pathlib.Path(name)
 return {'exists':p.exists(),'regular_file':p.is_file(),'directory':p.is_dir(),'bytes':p.stat().st_size if p.is_file() else None}
logs=['/var/log/auth.log','/var/log/suricata/eve.json','/var/log/apache2/soc-lab-requests.tsv','/var/log/apache2/soc-lab-access.log','/var/log/kern.log','/var/log/ufw.log','/var/log/audit/audit.log']
print(json.dumps({'logs':{n:state(n) for n in logs},'programs':{n:shutil.which(n) for n in ['curl','python3','sudo','crontab','auditctl','iptables']},
 'fim':[{'disabled':s.findtext('disabled'),'alert_new_files':s.findtext('alert_new_files'),'directories':[{'path':n.text,'realtime':n.get('realtime'),'restrict':n.get('restrict')} for n in s.findall('directories')]} for s in syschecks],
 'wazuh_inputs':[{'format':x.findtext('log_format'),'location':x.findtext('location')} for x in r.iter('localfile')],
 'test_account_exists':__import__('pwd').getpwnam('soctest').pw_uid>0}))
'''
RULE_CHECK=r'''
import json,pathlib,re,xml.etree.ElementTree as ET
wanted={str(i) for i in (5157,5712,5720,5760,5763,31103,31108,2500,2502,4100,4101,4151,550,553,554,87105,119212,119213,119214,119250,119251,119252,119253,119254)}
result={}
for folder in ('/var/ossec/ruleset/rules','/var/ossec/etc/rules'):
 for p in pathlib.Path(folder).glob('*.xml'):
  try:root=ET.fromstring('<document>'+re.sub(r'<\?xml[^>]*\?>','',p.read_text())+'</document>')
  except ET.ParseError:continue
  for n in root.iter('rule'):
   if n.get('id') in wanted:result[n.get('id')]={'file':str(p),'level':n.get('level'),'description':n.findtext('description'),'parent':n.findtext('if_sid'),'matched_parent':n.findtext('if_matched_sid')}
print(json.dumps(result))
'''


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,default=Path(__file__).with_name('live-config.json'))
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Choose a new report filename')
    runtime=load_config(a.config);scope=lab_scope('kali-attacker','ubuntu-endpoint','172.20.0.3')
    report={'schema_version':'soc-scenario-readiness/0.1','created_at_utc':datetime.now(timezone.utc).isoformat(),
            'scope':scope,'read_only':True,'checks':{},'errors':[],
            'notice':'Configuration/readability do not prove real collection, delivery, packet completeness or scenario success.'}
    def check(name,argv,as_json=False):
        try:
            r=subprocess.run(argv,capture_output=True,timeout=30)
            if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[-1000:] or 'exit '+str(r.returncode))
            report['checks'][name]=json.loads(r.stdout) if as_json else r.stdout.decode(errors='replace')[:3000]
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:report['errors'].append({'check':name,'error':str(e)})
    check('endpoint',['docker','exec','ubuntu-endpoint','python3','-c',AGENT_CHECK],True)
    launcher='if [ -x /var/ossec/framework/python/bin/python3 ]; then exec /var/ossec/framework/python/bin/python3 "$@"; else exec python3 "$@"; fi'
    check('wazuh_rule_catalog',['docker','exec',runtime['wazuh_manager'],'sh','-c',launcher,'soc-readiness','-c',RULE_CHECK],True)
    check('nmap_execution',['docker','exec','kali-attacker','nmap','--version'])
    check('endpoint_processes',['docker','top','ubuntu-endpoint','-eo','comm'])
    report['attack_chains_enabled']=runtime['correlation']['attack_chain_enabled']
    report['source_kinds']=[{'kind':s['kind'],'container':s['container'],'path':s['path']} for s in runtime['sources']]
    write_json(a.output,report);print(json.dumps(report,ensure_ascii=False,indent=2));return 2 if report['errors'] else 0

if __name__=='__main__':raise SystemExit(main())
