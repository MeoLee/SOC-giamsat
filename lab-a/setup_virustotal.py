"""Opt-in native Wazuh VT hash lookup, scoped to new files in the lab FIM directory.

The key is prompted locally, passed on stdin and never put in host argv/files.
No sample upload, API request, Active Response or execution is done at setup.
"""
import argparse
import getpass
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from wazuh_install_checks import RuleCheck, embedded_support, wait_manager_ready

MARKER='SOC-VT MANAGED v0.4.10'
RULE_ID='119253'


def config_update(text,key):
    if not re.fullmatch(r'[a-fA-F0-9]{64}',key):
        raise ValueError('Expected a 64-character hexadecimal VirusTotal API key; do not paste it into chat.')
    root=ET.fromstring('<document>'+re.sub(r'<\?xml[^>]*\?>','',text)+'</document>')
    existing=[n for n in root.iter('integration') if (n.findtext('name') or '').strip()=='virustotal']
    if len(existing)>1:raise ValueError('Multiple VirusTotal integrations; inspect before installing.')
    snippet=('<!-- '+MARKER+' -->\n  <integration>\n    <name>virustotal</name>\n'
             '    <api_key>'+key+'</api_key>\n    <rule_id>'+RULE_ID+'</rule_id>\n'
             '    <alert_format>json</alert_format>\n    <timeout>20</timeout>\n'
             '    <retries>0</retries>\n  </integration>')
    if existing:
        pattern=r'<!-- '+re.escape(MARKER)+r' -->\s*<integration>.*?</integration>'
        matches=list(re.finditer(pattern,text,re.S))
        if len(matches)!=1:raise ValueError('An unmanaged VirusTotal integration already exists; preserve and review it.')
        match=matches[0]
        node=ET.fromstring(re.sub(r'<!--.*?-->','',match.group(),flags=re.S))
        if node.findtext('name')!='virustotal':raise ValueError('Managed integration marker mismatch.')
        return text[:match.start()]+snippet+text[match.end():]
    for token in re.finditer(r'<!--.*?-->|</ossec_config\s*>',text,re.S):
        if token.group().startswith('</ossec_config'):
            return text[:token.start()]+'\n  '+snippet+'\n'+text[token.start():]
    raise ValueError('Missing real ossec_config closing tag.')


def install_remote(payload):
    import os,tempfile,time
    key=payload['api_key']
    config=Path('/var/ossec/etc/ossec.conf');old=config.read_bytes()
    candidate=config_update(old.decode('utf-8-sig'),key).encode()
    if not Path('/var/ossec/integrations/virustotal').is_file() or not Path('/var/ossec/integrations/virustotal.py').is_file():
        raise ValueError('Native VirusTotal integration is missing; check the manager installation.')
    # Confirm dependencies without making an external request or printing a key.
    import requests
    rules=Path('/var/ossec/etc/rules/soc_scenario_rules.xml').read_text()
    if 'SOC-SCENARIO MANAGED' not in rules or not re.search(r'<rule\s+id="119253"',rules):
        raise ValueError('Install setup_scenario_fim.py and setup_scenario_rules.py first.')
    backup=Path('/var/ossec/backup')/('soc-vt-'+str(time.time_ns()))
    backup.mkdir(mode=0o700,parents=True)
    fd=os.open(backup/'ossec.conf',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(old)
    print('PRIVATE_CONFIG_BACKUP:',backup,flush=True)
    stat=config.stat()
    def write(data):
        fd,name=tempfile.mkstemp(prefix='.soc-vt-',dir=config.parent)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.chmod(name,stat.st_mode & 0o640);os.chown(name,stat.st_uid,stat.st_gid);os.replace(name,config)
        finally:
            if os.path.exists(name):os.unlink(name)
    def run(argv,check=True):
        result=subprocess.run(argv,capture_output=True,timeout=60)
        output=(result.stdout+result.stderr).decode(errors='replace').replace(key,'[REDACTED]')
        print(output,flush=True)
        if result.returncode and check:raise RuntimeError('Validation/restart failed: '+argv[0])
        return output
    restarted=False
    try:
        write(candidate)
        run(['/var/ossec/bin/wazuh-analysisd','-t'])
        run(['/var/ossec/bin/wazuh-integratord','-t'])
        sample=json.dumps({'integration':'virustotal','virustotal':{'found':1,'malicious':1,'positives':1,
            'source':{'file':'/var/lib/soc-lab/fim/fixture.txt'}}})+'\n'
        check=RuleCheck(sample,[87105]);check.before_restart()
        restarted=True;run(['/var/ossec/bin/wazuh-control','restart'])
        check.after_restart()
        deadline=time.monotonic()+30
        while True:
            output=run(['/var/ossec/bin/wazuh-control','status'],check=False)
            if re.search(r'^wazuh-integratord\s+is running\b',output,re.M):break
            if time.monotonic()>=deadline:raise RuntimeError('wazuh-integratord did not become ready.')
            time.sleep(2)
    except BaseException:
        write(old)
        print('Previous configuration restored.',flush=True)
        if restarted:
            try:run(['/var/ossec/bin/wazuh-control','restart'])
            except Exception as error:print('ROLLBACK_RESTART_FAILED:',str(error).replace(key,'[REDACTED]'),flush=True)
        raise
    print('VIRUSTOTAL_CONFIGURED: new lab FIM files only (119253); hash lookup, no upload or Active Response.')
    print('Credentials/quota and FIM -> VirusTotal -> index/dashboard delivery still require the live test.')


def remote_script():
    source=Path(__file__).read_text(encoding='utf-8').rsplit("\nif __name__",1)[0]
    return embedded_support()+source+'\ninstall_remote(json.load(sys.stdin))\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager',default='single-node-wazuh.manager-1');args=parser.parse_args()
    from live_config import container_name
    container_name(args.manager)
    if not sys.stdin.isatty():raise ValueError('Run interactively to enter the API key locally.')
    key=getpass.getpass('VirusTotal API key (hidden; do not send it in chat): ').strip()
    # Validate before invoking Docker; never embed the key in command arguments.
    config_update('<ossec_config></ossec_config>',key)
    launcher='if [ -x /var/ossec/framework/python/bin/python3 ]; then exec /var/ossec/framework/python/bin/python3 "$@"; else exec python3 "$@"; fi'
    return subprocess.run(['docker','exec','-i','--user','0',args.manager,'sh','-c',launcher,'soc-vt','-c',remote_script()],
                          input=json.dumps({'api_key':key}).encode()).returncode


if __name__=='__main__':raise SystemExit(main())
