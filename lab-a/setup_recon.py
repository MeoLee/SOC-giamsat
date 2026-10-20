"""Replace the known SYN-count heuristic with managed SYN observations.

Validate the candidate with Suricata -T and an isolated positive/control PCAP,
then run the same Python detector used by Live. Back up and atomically replace
the loaded -S file only after those checks pass; request SIGUSR2 hot reload.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time

BEGIN='# BEGIN SOC-RECON OBSERVATIONS'
END='# END SOC-RECON OBSERVATIONS'
LEGACY='alert tcp any any -> any any (msg:"Possible TCP SYN reconnaissance"; flags:S; flow:stateless; threshold:type both, track by_both, count 20, seconds 10; classtype:attempted-recon; sid:9900001; rev:2;)'


def merge_rules(old,managed):
    if old.count(BEGIN)!=old.count(END) or old.count(BEGIN)>1:
        raise ValueError('Ambiguous managed recon block')
    had_managed=BEGIN in old
    if had_managed:
        match=re.search(re.escape(BEGIN)+r'\n(.*?)\n'+re.escape(END),old,re.S)
        if not match or match.group(1).strip()!=managed.strip():
            raise ValueError('Managed recon block was edited; inspect before replacing it')
        old=old[:match.start()]+old[match.end():]
    compact=lambda value:re.sub(r'\s+','',value)
    found=0;kept=[]
    for line in old.splitlines(keepends=True):
        if not line.lstrip().startswith('#') and re.search(r'\bsid\s*:\s*9900001\s*;',line):
            found+=1
            canonical=re.sub(r'rev\s*:\s*1\s*;', 'rev:2;',line)
            if compact(canonical)!=compact(LEGACY):
                raise ValueError('SID 9900001 differs from the reviewed lab rule; preserve and inspect it')
        else:kept.append(line)
    if found>1 or not found and not had_managed:
        raise ValueError('Expected one reviewed legacy rule or an existing managed installation')
    rest=''.join(kept)
    if re.search(r'\bsid\s*:\s*9900003\s*;',rest):
        raise ValueError('Unmanaged SID 9900003 collision')
    return rest.rstrip()+'\n\n'+BEGIN+'\n'+managed.strip()+'\n'+END+'\n'


def test_pcap():
    from setup_suricata_web import packet, test_pcap as web_pcap
    data=bytearray(web_pcap())
    base=1792020000
    def add(frame,t):
        seconds=int(t);micro=round((t-seconds)*1000000)
        data.extend(struct.pack('<IIII',base+seconds,micro,len(frame),len(frame)))
        data.extend(frame)
    dst='192.0.2.10'
    for i in range(33):
        src='198.51.100.30';sport=32000+i
        req=b'GET /soc-lab-health HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n'
        resp=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
        frames=[packet(src,dst,sport,80,1000,0,2),packet(dst,src,80,sport,2000,1001,18),
            packet(src,dst,sport,80,1001,2001,16),packet(src,dst,sport,80,1001,2001,24,req),
            packet(dst,src,80,sport,2001,1001+len(req),16),
            packet(dst,src,80,sport,2001,1001+len(req),24,resp),
            packet(src,dst,sport,80,1001+len(req),2001+len(resp),16),
            packet(src,dst,sport,80,1001+len(req),2001+len(resp),17),
            packet(dst,src,80,sport,2001+len(resp),1002+len(req),17),
            packet(src,dst,sport,80,1002+len(req),2002+len(resp),16)]
        for j,frame in enumerate(frames):add(frame,1+i*.25+j*.0001)
    for src,ports,start in [('198.51.100.20',range(1,33),12),
                            ('198.51.100.40',[22]*24,20)]:
        for i,port in enumerate(ports):
            add(packet(src,dst,41000+i,port,1000,0,2),start+i*.2)
            add(packet(dst,src,port,41000+i,0,1001,20),start+i*.2+.001)
    return bytes(data)


def remote_install(payload):
    if os.geteuid()!=0:raise RuntimeError('Run as root in the sensor container')
    processes=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:args=[os.fsdecode(x) for x in (entry/'cmdline').read_bytes().split(b'\0') if x]
        except OSError:continue
        if args and Path(args[0]).name=='suricata':processes.append((int(entry.name),args))
    if len(processes)!=1:raise RuntimeError('Expected exactly one live Suricata process')
    pid,args=processes[0]
    if '-S' not in args or '-c' not in args:raise RuntimeError('Expected existing -S rules and -c YAML startup options')
    rules=Path(args[args.index('-S')+1]);yaml=args[args.index('-c')+1]
    old=rules.read_bytes();merged=merge_rules(old.decode('utf-8'),payload['rules'])
    algorithm={};exec(compile(payload['algorithm'],'lab_recon.py','exec'),algorithm)
    with tempfile.TemporaryDirectory(prefix='soc-recon-check-') as folder:
        root=Path(folder);candidate=root/'candidate.rules';candidate.write_text(merged)
        subprocess.run([args[0],'-T','--init-errors-fatal','-c',yaml,'-S',str(candidate),'-l',str(root)],check=True,timeout=90)
        pcap=root/'recon-controls.pcap';pcap.write_bytes(base64.b64decode(payload['pcap'],validate=True))
        subprocess.run([args[0],'--runmode','single','--init-errors-fatal','-c',yaml,'-S',str(candidate),
            '-r',str(pcap),'-k','none','-l',str(root),'--set','unix-command.enabled=no'],check=True,timeout=90)
        alerts=[]
        for path in root.glob('eve*.json'):
            for line in path.read_text().splitlines():
                event=json.loads(line)
                if event.get('event_type')=='alert':alerts.append(event)
        observations=[]
        for event in alerts:
            if str(event['alert']['signature_id'])!='9900003':continue
            row=algorithm['observation'](event,'pcap-sensor','pcap-target')
            row['event_id']='pcap:'+hashlib.sha256(json.dumps(row,sort_keys=True).encode()).hexdigest()
            observations.append(row)
        for src,required in [('198.51.100.20',set(range(1,33))),
                              ('198.51.100.30',{80}),('198.51.100.40',{22})]:
            subset=[e for e in observations if e['source_ip']==src]
            if {e['destination_port'] for e in subset}!=required:
                raise RuntimeError('PCAP SYN observation coverage failed for '+src)
            expected={'198.51.100.20':32,'198.51.100.30':33,'198.51.100.40':24}[src]
            if len(subset)!=expected:raise RuntimeError('PCAP SYN count differs from known generated attempts')
        scans=algorithm['scan_evidence'](observations,{})
        if not scans or {e['source_ip'] for e in scans}!={'198.51.100.20'}:
            raise RuntimeError('PCAP distinct-port positive/control checks failed')
        actual={(str(e['alert']['signature_id']),e.get('src_port')) for e in alerts}
        if ('9900101',30001) not in actual or ('9900102',30002) not in actual:
            raise RuntimeError('Existing SQLi positive PCAP checks failed')
        if any(str(e['alert']['signature_id']) in ('9900101','9900102') and
                (e.get('src_ip')=='198.51.100.30' or e.get('src_port')==30003) for e in alerts):
            raise RuntimeError('Benign HTTP PCAP triggered a SQLi signature')
        print('RECON_PCAP_VALIDATED: scan detected; HTTP and single-port controls produced no recon',flush=True)
    if rules.read_bytes()!=old:raise RuntimeError('Rule file changed during validation; no live update made')
    stat=rules.stat();backup=rules.with_name(rules.name+'.before-recon-'+str(time.time_ns()))
    fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(old);stream.flush();os.fsync(stream.fileno())
    def replace(content):
        name=None
        try:
            with tempfile.NamedTemporaryFile(dir=rules.parent,prefix='.soc-recon-',delete=False) as stream:
                name=stream.name;stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.chmod(name,stat.st_mode&0o777);os.chown(name,stat.st_uid,stat.st_gid)
            os.replace(name,rules);name=None
        finally:
            if name is not None:os.unlink(name)
    try:
        replace(merged.encode('utf-8'));os.kill(pid,signal.SIGUSR2)
    except BaseException:
        replace(old)
        try:os.kill(pid,signal.SIGUSR2)
        except OSError:pass
        raise
    print('SURICATA_RECON_RULES_VALIDATED_AND_RELOAD_REQUESTED',flush=True)
    print('BACKUP:',backup,flush=True)
    print('Live HTTP and port-scan sessions must still verify the active reload.',flush=True)


def remote_script():
    return Path(__file__).read_text().rsplit("\nif __name__=='__main__':",1)[0]+'\nremote_install(json.load(sys.stdin))\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--container',default='ubuntu-endpoint')
    a=p.parse_args()
    from live_config import container_name
    container_name(a.container)
    root=Path(__file__).parent
    payload={'rules':(root/'soc-recon.rules').read_text(),
        'algorithm':(root/'lab_recon.py').read_text(),
        'pcap':base64.b64encode(test_pcap()).decode('ascii')}
    try:
        return subprocess.run(['docker','exec','-i','--user','0',a.container,'python3','-c',remote_script()],
                              input=json.dumps(payload).encode(),timeout=240).returncode
    except (OSError,subprocess.TimeoutExpired) as exc:
        print('RECON_SETUP_ERROR:',exc,file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
