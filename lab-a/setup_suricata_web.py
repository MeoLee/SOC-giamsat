"""Add SQLi signatures to the SAME file already loaded using -S.

Validate configuration and positive/negative PCAP first; preserve existing
rules and use SIGUSR2 hot reload. Does not change YAML or restart the sensor.
This adds local SQLi and bounded DVWA HTTP-rate indicators, not ET Open.
"""
import argparse
import ipaddress
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

BEGIN = '# BEGIN SOC-WEB MANAGED RULES'
END = '# END SOC-WEB MANAGED RULES'


def merge_rules(old, web):
    if old.count(BEGIN)!=old.count(END) or old.count(BEGIN)>1:
        raise ValueError('Ambiguous SOC-WEB rule block')
    old = re.sub(re.escape(BEGIN)+'.*?'+re.escape(END), '',old,flags=re.S)
    for sid in ('9900101','9900102','9900104'):
        if re.search(r'\bsid\s*:\s*'+sid+r'\s*;',old):
            raise ValueError('Signature ID collision: '+sid)
    return old.rstrip()+'\n\n'+BEGIN+'\n'+web.strip()+'\n'+END+'\n'


def checksum(data):
    if len(data)%2: data+=b'\x00'
    number = sum(struct.unpack('!%dH'%(len(data)//2),data))
    while number>>16: number=(number&65535)+(number>>16)
    return (~number)&65535


def packet(src,dst,sport,dport,seq,ack,flags,payload=b''):
    a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
    tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,80,flags,65535,0,0)+payload
    value=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp)
    tcp=tcp[:16]+struct.pack('!H',value)+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),0,0,64,6,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'+ip+tcp


def test_pcap():
    result=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    requests=[
        b'GET /?id=1%27%20UNION%20ALL%20SELECT%20NULL,NULL--%20- HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n',
        b'POST / HTTP/1.1\r\nHost: lab\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\nConnection: close\r\n\r\nid=1%27+UNION+ALL+SELECT+NULL%2CNULL--+-',
        b'GET /?q=union+representatives HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n',
    ]
    # Always calculate POST Content-Length from bytes, never a guessed value.
    head,body=requests[1].split(b'\r\n\r\n',1)
    head=re.sub(rb'Content-Length: \d+',b'Content-Length: '+str(len(body)).encode(),head)
    requests[1]=head+b'\r\n\r\n'+body
    count=0
    for i,req in enumerate(requests):
        src,dst='198.51.100.10','192.0.2.10'; port=30001+i
        resp=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
        frames=[packet(src,dst,port,80,1000,0,2),packet(dst,src,80,port,2000,1001,18),
            packet(src,dst,port,80,1001,2001,16),packet(src,dst,port,80,1001,2001,24,req),
            packet(dst,src,80,port,2001,1001+len(req),16),
            packet(dst,src,80,port,2001,1001+len(req),24,resp),
            packet(src,dst,port,80,1001+len(req),2001+len(resp),16),
            packet(src,dst,port,80,1001+len(req),2001+len(resp),17),
            packet(dst,src,80,port,2001+len(resp),1002+len(req),17),
            packet(src,dst,port,80,1002+len(req),2002+len(resp),16)]
        for frame in frames:
            result+=struct.pack('<IIII',1792020000,count*1000,len(frame),len(frame))+frame
            count+=1
    return bytes(result)


def flood_pcap():
    # Separate fixture: keep test_pcap() stable for the recon exact-count test.
    result=bytearray(test_pcap());count=1000
    for src,number,path in [('198.51.100.11',61,'/dvwa/login.php'),
                            ('198.51.100.12',33,'/dvwa/login.php'),
                            ('198.51.100.13',61,'/soc-lab-health')]:
        for i in range(number):
            dst='192.0.2.10';port=31000+i
            req=('GET '+path+' HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n').encode()
            resp=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
            frames=[packet(src,dst,port,80,1000,0,2),packet(dst,src,80,port,2000,1001,18),
                packet(src,dst,port,80,1001,2001,16),packet(src,dst,port,80,1001,2001,24,req),
                packet(dst,src,80,port,2001,1001+len(req),16),packet(dst,src,80,port,2001,1001+len(req),24,resp),
                packet(src,dst,port,80,1001+len(req),2001+len(resp),16),
                packet(src,dst,port,80,1001+len(req),2001+len(resp),17),
                packet(dst,src,80,port,2001+len(resp),1002+len(req),17),
                packet(src,dst,port,80,1002+len(req),2002+len(resp),16)]
            for frame in frames:
                result+=struct.pack('<IIII',1792020001+count//1000,(count%1000)*1000,len(frame),len(frame))+frame;count+=1
    return bytes(result)


def remote_install(payload):
    if os.geteuid()!=0: raise RuntimeError('Run as root in the sensor container')
    processes=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try: args=(entry/'cmdline').read_bytes().split(b'\x00')
        except OSError: continue
        if args and Path(os.fsdecode(args[0])).name=='suricata': processes.append((int(entry.name),[os.fsdecode(x) for x in args if x]))
    if len(processes)!=1: raise RuntimeError('Expected exactly one live Suricata process')
    pid,args=processes[0]
    if '-S' not in args or '-c' not in args:
        raise RuntimeError('Unexpected startup command; inspect before changing rule loading')
    rules=Path(args[args.index('-S')+1]); yaml=args[args.index('-c')+1]
    if not rules.is_file() or rules.is_symlink(): raise RuntimeError('Loaded rule file must be a regular non-symlink file')
    old=rules.read_bytes()
    merged=merge_rules(old.decode('utf-8'),payload['rules'])
    with tempfile.TemporaryDirectory(prefix='soc-web-check-') as directory:
        root=Path(directory); candidate=root/'candidate.rules'; candidate.write_text(merged)
        subprocess.run(['suricata','-T','--init-errors-fatal','-c',yaml,'-S',str(candidate),'-l',str(root)],check=True)
        pcap=root/'web-check.pcap'; pcap.write_bytes(flood_pcap())
        subprocess.run(['suricata','--runmode','single','--init-errors-fatal','-c',yaml,'-S',str(candidate),
            '-r',str(pcap),'-k','none','-l',str(root),'--set','unix-command.enabled=no'],check=True,timeout=90)
        alerts=[]
        for path in root.glob('eve*.json'):
            for line in path.read_text().splitlines():
                event=json.loads(line)
                if event.get('event_type')=='alert': alerts.append(event)
        actual={(str(e['alert']['signature_id']),e.get('src_port')) for e in alerts}
        if ('9900101',30001) not in actual or ('9900102',30002) not in actual:
            raise RuntimeError('SQLi positive PCAP test failed; live rule file was not changed')
        if any(str(e['alert']['signature_id']) in ('9900101','9900102') and e.get('src_port')==30003 for e in alerts):
            raise RuntimeError('Benign PCAP triggered SQLi rule; live rule file was not changed')
        flood=[e for e in alerts if str(e['alert']['signature_id'])=='9900104']
        if len(flood)!=1 or flood[0].get('src_ip')!='198.51.100.11':
            raise RuntimeError('DVWA rate positive/low-volume/other-route PCAP controls failed; live rule file was not changed')
    if rules.read_bytes()!=old: raise RuntimeError('Rule file changed during validation; retry after inspecting')
    metadata=rules.stat()
    backup=rules.with_name(rules.name+'.before-web-'+str(time.time_ns()))
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(old);stream.flush();os.fsync(stream.fileno())
    def atomic(data):
        fd,name=tempfile.mkstemp(dir=rules.parent,prefix='.soc-web-')
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.chmod(name,metadata.st_mode&0o777);os.chown(name,metadata.st_uid,metadata.st_gid);os.replace(name,rules)
        finally:
            if os.path.exists(name):os.unlink(name)
    try:
        atomic(merged.encode('utf-8'))
        os.kill(pid,signal.SIGUSR2)
    except BaseException:
        atomic(old)
        raise
    print('RULE_BACKUP:',backup,flush=True)
    print('SURICATA_WEB_RULES_VALIDATED_AND_RELOAD_REQUESTED',flush=True)
    print('Preserved original rules/startup command. Verify SQLi and DVWA HTTP-rate alerts with live traffic.',flush=True)


def remote_script():
    return Path(__file__).read_text().rsplit("\nif __name__=='__main__':",1)[0]+'\nremote_install(json.load(sys.stdin))\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--container',default='ubuntu-endpoint')
    a=p.parse_args()
    rules=Path(__file__).with_name('soc-web.rules').read_text()
    result=subprocess.run(['docker','exec','-i','--user','0',a.container,'python3','-c',remote_script()],
                          input=json.dumps({'rules':rules}).encode())
    return result.returncode


if __name__=='__main__': raise SystemExit(main())
