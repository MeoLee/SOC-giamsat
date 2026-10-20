"""Event-time port sweep evidence from SYN observations, never SYN volume alone.

This module is stdlib-only so the sensor installer can run this exact detector
against its isolated Suricata PCAP output before changing the live rule file.
"""
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import re

SYN_SID = '9900003'
PORT_THRESHOLD = 20
WINDOW_SECONDS = 10

SENSOR_RULE_CHECK = r'''
import json,os,re
from pathlib import Path
found=[]
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():continue
    try:args=[os.fsdecode(x) for x in (entry/'cmdline').read_bytes().split(b'\0') if x]
    except OSError:continue
    if args and Path(args[0]).name=='suricata':found.append(args)
if len(found)!=1 or '-S' not in found[0]:raise RuntimeError('Expected one Suricata process using -S')
args=found[0];path=Path(args[args.index('-S')+1])
rules='\n'.join(line for line in path.read_text().splitlines() if not line.lstrip().startswith('#'))
if re.search(r'\bsid\s*:\s*9900001\s*;',rules) or not re.search(r'\bsid\s*:\s*9900003\s*;',rules):
    raise RuntimeError('Run setup_recon.py: distinct-port collection rule is not installed')
print(json.dumps({'rule_file':str(path),'syn_observation_sid':9900003,
    'live_reload_and_capture_verified_by_this_check':False}))
'''


def instant(value):
    if not isinstance(value,str): raise ValueError('SYN timestamp must be a string')
    # Suricata emits +0000/-0400; Python versions in some sensor images
    # require the colon even though the Windows inference venv accepts both.
    value=re.sub(r'([+-][0-9]{2})([0-9]{2})$',r'\1:\2',value.replace('Z','+00:00'))
    t=datetime.fromisoformat(value)
    if t.tzinfo is None: raise ValueError('SYN timestamp requires timezone')
    return t.astimezone(timezone.utc)


def number(value, name):
    if isinstance(value,str) and value.isascii() and value.isdecimal(): value=int(value)
    if type(value) is not int or not 0<=value<=65535: raise ValueError('Invalid SYN '+name)
    return value


def observation(event, sensor_id, target_host):
    if (event.get('event_type')!='alert' or not isinstance(event.get('alert'),dict)
            or str(event['alert'].get('signature_id'))!=SYN_SID
            or event.get('proto')!='TCP'):
        raise ValueError('Expected managed TCP SYN observation')
    if (not isinstance(sensor_id,str) or not sensor_id or len(sensor_id)>256
            or any(ord(c)<32 for c in sensor_id)):
        raise ValueError('SYN sensor identity required')
    fid=event.get('flow_id')
    if (isinstance(fid,bool) or not isinstance(fid,(int,str))
            or isinstance(fid,int) and fid<0 or isinstance(fid,str) and not fid.strip()):
        raise ValueError('Invalid SYN flow ID')
    return {'kind':'network.tcp_syn',
        'event_time':instant(event['timestamp']).isoformat(timespec='microseconds').replace('+00:00','Z'),
        'source_ip':str(ipaddress.ip_address(event['src_ip'])),
        'target_ip':str(ipaddress.ip_address(event['dest_ip'])), 'target_host':target_host,
        'source_port':number(event.get('src_port'),'source port'),
        'destination_port':number(event.get('dest_port'),'destination port'),
        'flow_id':str(fid),'signature_id':SYN_SID,'sensor_id':sensor_id}


def scan_evidence(events, config):
    threshold=config.get('recon_port_threshold',PORT_THRESHOLD)
    seconds=config.get('recon_port_window_seconds',WINDOW_SECONDS)
    if type(threshold) is not int or not 2<=threshold<=65536:
        raise ValueError('Invalid recon_port_threshold')
    if type(seconds) is not int or not 1<=seconds<=3600:
        raise ValueError('Invalid recon_port_window_seconds')
    groups=defaultdict(list)
    for event in events:
        if event['kind']=='network.tcp_syn':
            groups[(event['sensor_id'],event['source_ip'],event['target_ip'])].append(event)
    scans=[]
    for timeline in groups.values():
        recent=deque(); ports=Counter();last_trigger=None
        for event in sorted(timeline,key=lambda e:(e['event_time'],e['event_id'])):
            t=instant(event['event_time'])
            while recent and (t-instant(recent[0]['event_time'])).total_seconds()>seconds:
                old=recent.popleft();port=old['destination_port'];ports[port]-=1
                if not ports[port]: del ports[port]
            recent.append(event);ports[event['destination_port']]+=1
            if len(ports)<threshold: continue
            # One proof per window per sensor/pair. Copying a growing evidence
            # list for every packet would turn a large burst into O(n**2) state.
            if last_trigger is not None and (t-last_trigger).total_seconds()<seconds:
                continue
            last_trigger=t
            # IDs reference the original normalized SYN records, not invented
            # events or MLP predictions. Repeated ports cannot raise this count.
            scans.append({**event,'kind':'network.possible_recon',
                'recon_evidence_ids':[e['event_id'] for e in recent],
                'recon_window_start':recent[0]['event_time'],
                'distinct_destination_ports':len(ports),
                'destination_ports':sorted(ports),'port_threshold':threshold,
                'port_window_seconds':seconds})
    return sorted(scans,key=lambda e:(e['event_time'],e['event_id']))


def stage(scans):
    if not scans: raise ValueError('Recon stage requires port sweep evidence')
    best=max(scans,key=lambda e:(e['distinct_destination_ports'],e['event_time'],e['event_id']))
    ids=list(dict.fromkeys(eid for scan in scans for eid in scan['recon_evidence_ids']))
    return {'name':'possible_recon',
        'start_time':min(e['recon_window_start'] for e in scans),
        'end_time':max(e['event_time'] for e in scans),'evidence_ids':ids,
        'detection_method':'distinct_tcp_destination_ports',
        'distinct_destination_ports':best['distinct_destination_ports'],
        'destination_port_sample':best['destination_ports'][:64],
        'port_threshold':best['port_threshold'],'port_window_seconds':best['port_window_seconds'],
        'qualifying_window_start':best['recon_window_start'],
        'qualifying_window_end':best['event_time'],
        'sensor_ids':sorted({e['sensor_id'] for e in scans})}
