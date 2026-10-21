"""Early SSH service contact: neutral candidate, never Nmap/attack attribution."""
from collections import defaultdict
from copy import deepcopy


def contact_cases(events,config):
    from lab_correlation import instant,digest
    from lab_recon import scan_evidence
    if not config.get('ssh_contact_observations_enabled'):return []
    known=defaultdict(list)
    for e in events:
        if e['kind'].startswith('auth.'):
            known[(e['source_ip'],e['target_ip'],e['target_host'],e.get('source_port'))].append(instant(e['event_time']))
    scans=scan_evidence(events,config);groups=defaultdict(dict)
    for e in events:
        if e['kind']!='network.tcp_syn' or e.get('signature_id')!='9900003' or e.get('destination_port')!=22:continue
        if e['target_host'].startswith('ip:') or e.get('sensor_id')!=e['target_host']:continue
        key=tuple(e[k] for k in ('source_ip','target_ip','target_host','sensor_id'))
        flow=(e.get('flow_id'),e.get('source_port'));old=groups[key].get(flow)
        if old is None or (e['event_time'],e['event_id'])<(old['event_time'],old['event_id']):groups[key][flow]=e
    result=[]
    for key,flows in sorted(groups.items()):
        segments=[]
        for e in sorted(flows.values(),key=lambda e:(e['event_time'],e['event_id'])):
            t=instant(e['event_time']);auth_key=(*key[:3],e.get('source_port'))
            # Match the FIRST SYN of a flow. Later retransmissions cannot revive
            # a known SSH login, and old auth cannot mask reused source ports.
            if any(0<=(a-t).total_seconds()<=config['success_window_seconds'] for a in known[auth_key]):continue
            if any(all(s[k]==e[k] for k in ('source_ip','target_ip','target_host')) and
                -config['recon_port_window_seconds'] <= (t-instant(s['event_time'])).total_seconds() < config['chain_idle_seconds'] for s in scans):continue
            if not segments or (instant(e['event_time'])-instant(segments[-1][-1]['event_time'])).total_seconds()>=config['chain_idle_seconds'] or (instant(e['event_time'])-instant(segments[-1][0]['event_time'])).total_seconds()>=config['chain_max_seconds']:segments.append([])
            segments[-1].append(e)
        for rows in segments:
            cid='ssh-contact:'+digest([key,rows[0]['event_id']])
            s=dict(name='ssh_service_contact',start_time=rows[0]['event_time'],end_time=rows[-1]['event_time'],
                evidence_ids=[e['event_id'] for e in rows],target_port=22,connection_count=len(rows),reconnaissance_proven=False,
                detection_method='suricata_unique_ssh_syn_contact',limitation='One-port TCP contact cannot identify Nmap or distinguish authorized SSH from reconnaissance.')
            result.append(dict(case_id=cid,_contact_root_id=cid,source_ip=key[0],target_ip=key[1],target_host=key[2],username=None,stages=[s]))
    return result


def attach_contacts(branches,events,config):
    from lab_correlation import instant
    if not config.get('ssh_contact_observations_enabled'):return branches
    contacts=contact_cases(events,config);used=set();result=[]
    pressure_ids={i for b in branches for s in b['stages'] if s['name']=='syn_connection_pressure' for i in s['evidence_ids']}
    contacts=[c for c in contacts if not set(c['stages'][0]['evidence_ids']).intersection(pressure_ids)]
    for original in branches:
        b=deepcopy(original)
        if any(s['name']=='possible_recon' for s in b['stages']):result.append(b);continue
        # Replace the old delayed process-only contact with the same early root.
        parts=[s for s in b['stages'] if s['name']!='ssh_service_contact']
        if not parts:result.append(b);continue
        first=min(instant(s['start_time']) for s in parts)
        candidates=[];by_id={e['event_id']:e for e in events}
        for c in contacts:
            if not all(c[k]==b[k] for k in ('source_ip','target_ip','target_host')):continue
            prefix=[by_id[i] for i in c['stages'][0]['evidence_ids'] if instant(by_id[i]['event_time'])<=first]
            if not prefix or (first-instant(prefix[-1]['event_time'])).total_seconds()>=config['chain_idle_seconds']:continue
            stage={**c['stages'][0],'end_time':prefix[-1]['event_time'],
                   'evidence_ids':[e['event_id'] for e in prefix],'connection_count':len(prefix)}
            candidates.append((c,stage))
        if candidates:
            c,stage=max(candidates,key=lambda v:(v[1]['end_time'],v[0]['case_id']))
            b['stages']=[stage]+parts;b['_contact_root_id']=c['case_id'];used.add(c['case_id'])
        result.append(b)
    return result+[c for c in contacts if c['case_id'] not in used]
