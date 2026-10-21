"""Opt-in scoped FIM for scenario exercises; preserve unrelated agent config."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

PATHS=('/var/lib/soc-lab/fim','/opt/soc-lab/DVWA/hackable/uploads')


def config_update(text,kernel_log=None):
    root=ET.fromstring('<document>'+re.sub(r'<\?xml[^>]*\?>','',text)+'</document>')
    nodes=list(root.iter('syscheck'))
    if len(nodes)>1:raise ValueError('Multiple syscheck blocks: review before changing FIM')
    block=nodes[0] if nodes else ET.Element('syscheck')
    for key,value in [('disabled','no'),('alert_new_files','yes')]:
        found=block.findall(key)
        if len(found)>1:raise ValueError('Duplicate syscheck '+key)
        node=found[0] if found else ET.SubElement(block,key);node.text=value
    for path in PATHS:
        found=[n for n in block.findall('directories') if (n.text or '').strip()==path]
        if len(found)>1:raise ValueError('Duplicate FIM directory: '+path)
        node=found[0] if found else ET.SubElement(block,'directories')
        if any(k in node.attrib for k in ('restrict','ignore')):raise ValueError('Existing restricted directory: '+path)
        node.text=path;node.set('check_all','yes');node.set('realtime','yes')
    block.tail=None
    rendered=ET.tostring(block,encoding='unicode')
    # Match actual elements; never edit a sample inside an XML comment.
    tokens=list(re.finditer(r'<!--.*?-->|<syscheck\b[^>]*>.*?</syscheck\s*>|<syscheck\s*/>|</ossec_config\s*>',text,re.S))
    if nodes:
        matches=[m for m in tokens if m.group().startswith('<syscheck')]
        if len(matches)!=1:raise ValueError('Ambiguous syscheck text')
        m=matches[0];updated=text[:m.start()]+rendered+text[m.end():]
    else:
        closing=next((m for m in tokens if m.group().startswith('</ossec_config')),None)
        if not closing:raise ValueError('Missing ossec_config close')
        updated=text[:closing.start()]+'\n'+rendered+'\n'+text[closing.start():]
    if kernel_log:
        if kernel_log not in ('/var/log/kern.log','/var/log/ufw.log'):raise ValueError('Unsupported kernel log path')
        existing=[n for n in root.iter('localfile') if (n.findtext('location') or '').strip()==kernel_log]
        if len(existing)>1 or (existing and existing[0].findtext('log_format')!='syslog'):
            raise ValueError('Conflicting kernel log input')
        if not existing:
            close=next(m for m in re.finditer(r'<!--.*?-->|</ossec_config>',updated,re.S) if m.group().startswith('</ossec_config'))
            snippet='<localfile><log_format>syslog</log_format><location>'+kernel_log+'</location></localfile>\n'
            updated=updated[:close.start()]+snippet+updated[close.start():]
    return updated


def install_remote(kernel_log=None):
    import os,time,tempfile
    config=Path('/var/ossec/etc/ossec.conf')
    if os.geteuid()!=0 or not Path('/.dockerenv').is_file():raise ValueError('Run inside the lab agent container as root')
    old=config.read_bytes();candidate=config_update(old.decode('utf-8-sig'),kernel_log).encode()
    if kernel_log and (not Path(kernel_log).is_file() or Path(kernel_log).is_symlink()):
        raise ValueError('A real existing kernel log file is required; no synthetic file is created')
    for name in PATHS:
        p=Path(name)
        if p.is_symlink() or any(x.is_symlink() for x in p.parents):raise ValueError('FIM directory contains symlink: '+name)
        if name.endswith('/uploads') and not p.is_dir():raise ValueError('Install/check DVWA first; upload directory missing')
    import pwd
    account=pwd.getpwnam('soctest')
    directory=Path(PATHS[0]);marker=directory/'.soc-scenario-managed'
    if directory.exists() and not marker.is_file():
        raise ValueError('Existing FIM directory is unmanaged; inspect before changing permissions')
    directory.mkdir(parents=True,exist_ok=True)
    if directory.stat().st_uid!=0:raise ValueError('Expected root-owned exercise directory')
    os.chown(directory,0,account.pw_gid);os.chmod(directory,0o770)
    import stat as stat_module
    if not marker.exists():
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o640)
        try:os.write(fd,b'SOC-SCENARIO MANAGED\n');os.fsync(fd)
        finally:os.close(fd)
    fd=os.open(marker,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or info.st_nlink!=1 or not stat_module.S_ISREG(info.st_mode):raise ValueError('Invalid directory ownership marker')
    finally:os.close(fd)
    if candidate==old:
        print('FIM_ALREADY_CONFIGURED; confirm baseline completion and directory monitoring in ossec.log');return
    backup=config.parent/('ossec.conf.before-scenario-fim-'+str(time.time_ns()))
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(old);f.flush();os.fsync(f.fileno())
    print('CONFIG_BACKUP:',backup,flush=True)
    stat=config.stat()
    def write(data):
        fd,name=tempfile.mkstemp(prefix='.scenario-fim-',dir=config.parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            os.chmod(name,stat.st_mode & 0o777);os.chown(name,stat.st_uid,stat.st_gid);os.replace(name,config)
        finally:
            if os.path.exists(name):os.unlink(name)
    restarted=False
    try:
        write(candidate)
        for program in ('wazuh-agentd','wazuh-syscheckd','wazuh-logcollector'):
            subprocess.run(['/var/ossec/bin/'+program,'-t'],check=True,timeout=30)
        restarted=True;subprocess.run(['/var/ossec/bin/wazuh-control','restart'],check=True,timeout=60)
    except BaseException:
        write(old)
        if restarted:subprocess.run(['/var/ossec/bin/wazuh-control','restart'],check=True,timeout=60)
        raise
    print('FIM_SCOPED_CONFIGURED; wait for baseline completion before creating test artifacts. No VirusTotal/Active Response configured.')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sensor',default='ubuntu-endpoint');p.add_argument('--kernel-log',choices=('/var/log/kern.log','/var/log/ufw.log'));a=p.parse_args()
    from live_config import container_name
    container_name(a.sensor)
    code=Path(__file__).read_text().rsplit("\nif __name__",1)[0]+'\ninstall_remote('+repr(a.kernel_log)+')\n'
    return subprocess.run(['docker','exec','--user','0',a.sensor,'python3','-c',code]).returncode

if __name__=='__main__':raise SystemExit(main())
