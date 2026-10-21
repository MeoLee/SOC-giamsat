"""Install additive, collision-checked exercise rules, with backup and rollback."""
import argparse,json,re,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
RULE_PATH='/var/ossec/etc/rules/soc_scenario_rules.xml'
MARKER='SOC-SCENARIO MANAGED'
FIREWALL_SAMPLE='Oct 21 12:00:00 ubuntu-endpoint kernel: SOC_LAB_FW_DROP IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=172.20.0.4 DST=172.20.0.3 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=45000 DPT=4444 WINDOW=1024 RES=0x00 SYN URGP=0'


def check_collisions(rules,existing):
    ids={r.attrib['id'] for r in ET.fromstring(rules).iter('rule')}
    if ids!={str(i) for i in range(119250,119255)}:raise ValueError('Unexpected scenario rule ID set')
    for path,text in existing.items():
        if path==RULE_PATH:
            if MARKER not in text and text!=rules:raise ValueError('Unmanaged scenario rule filename')
        elif ids.intersection(re.findall(r'<rule\b[^>]*\bid\s*=\s*[\"\x27](\d+)',text)):
            raise ValueError('Scenario rule ID collision: '+path)


def install_remote(payload):
    import os,grp,tempfile,time
    path=Path(RULE_PATH);old=path.read_bytes() if path.exists() else None
    existing={str(p):p.read_text(encoding='utf-8-sig') for p in Path('/var/ossec/etc').glob('**/*.xml')}
    check_collisions(payload['rules'],existing)
    group=grp.getgrnam('wazuh').gr_gid
    backup=Path('/var/ossec/backup')/('soc-scenario-'+str(time.time_ns()));backup.mkdir(mode=0o700,parents=True)
    if old is not None:(backup/path.name).write_bytes(old);(backup/path.name).chmod(0o600)
    (backup/'installation.json').write_text(json.dumps({'rule_file_previously_existed':old is not None}))
    print('RULE_BACKUP:',backup,flush=True)
    def write(data):
        fd,name=tempfile.mkstemp(prefix='.soc-scenario-',dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            os.chmod(name,0o640);os.chown(name,0,group);os.replace(name,path)
        finally:
            if os.path.exists(name):os.unlink(name)
    def run(argv,**kw):
        r=subprocess.run(argv,capture_output=True,timeout=60,**kw);output=(r.stdout+r.stderr).decode(errors='replace')
        print(output,flush=True)
        if r.returncode:raise RuntimeError('Scenario validation/restart failed: '+argv[0])
        return output
    restarted=False
    try:
        write(payload['rules'].encode());run(['/var/ossec/bin/wazuh-analysisd','-t'])
        output=run(['/var/ossec/bin/wazuh-logtest'],input=(FIREWALL_SAMPLE+'\n').encode())
        if not re.search(r"id:\s*'119254'",output):raise RuntimeError('Firewall decoder/rule sample did not match; rules restored')
        restarted=True;run(['/var/ossec/bin/wazuh-control','restart'])
    except BaseException:
        if old is None:path.unlink(missing_ok=True)
        else:write(old)
        if restarted:run(['/var/ossec/bin/wazuh-control','restart'])
        raise
    print('SCENARIO_RULES_INSTALLED; fixture logtest is not a live firewall/FIM verification.')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manager',default='single-node-wazuh.manager-1');a=p.parse_args()
    from live_config import container_name
    container_name(a.manager)
    code=Path(__file__).read_text().rsplit("\nif __name__",1)[0]+'\ninstall_remote(json.load(sys.stdin))\n'
    launcher='if [ -x /var/ossec/framework/python/bin/python3 ]; then exec /var/ossec/framework/python/bin/python3 "$@"; else exec python3 "$@"; fi'
    payload={'rules':Path(__file__).with_name('soc_scenario_rules.xml').read_text()}
    return subprocess.run(['docker','exec','-i','--user','0',a.manager,'sh','-c',launcher,'soc-scenario','-c',code],input=json.dumps(payload).encode()).returncode

if __name__=='__main__':raise SystemExit(main())
