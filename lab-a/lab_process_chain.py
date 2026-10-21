"""Normalize root-owned /proc observations and bind to native SSH authentication.

A connection alone, shell name, model score or successful login cannot create
a reverse-shell stage. No privilege escalation or Critical detector is added.
"""
import json
import re
from process_observer import SCHEMA,SHELLS,identity,private


def normalize(raw,config,source):
    from lab_correlation import instant,stamp,ip_host
    e=json.loads(raw)
    if not isinstance(e,dict) or e.get('schema_version')!=SCHEMA:
        raise ValueError('Process observer schema required')
    if e.get('kind') not in ('process.shell_socket',):
        raise ValueError('Unsupported process observation')
    origin=config.get('source_origins',{}).get(source,{})
    if (origin.get('source_path')!='/var/log/soc-lab/process-observer/events.jsonl'
            or e.get('observer_uid')!=0 or type(e['observer_uid']) is not int
            or e.get('kernel_process_observation') is not True):
        raise ValueError('Root-owned process-observer source required')
    src,dst=private(e['source_ip']),private(e['target_ip']);host=ip_host(dst,config)
    if host.startswith('ip:') or origin.get('source_container')!=host:
        raise ValueError('Process observation target must match its sensor/asset')
    for k in ('pid','start_ticks','source_port','session_uid'):
        if type(e.get(k)) is not int or e[k]<=0:raise ValueError('Invalid process/session integer: '+k)
    if e['source_port']>65535 or e.get('target_port')!=22:
        raise ValueError('SSH port identity required')
    if e.get('executable') not in SHELLS:
        raise ValueError('Actual shell executable required')
    if not re.fullmatch(r'[a-f0-9-]{36}',e.get('boot_id','')) or e.get('process_id')!=identity(e['boot_id'],e['pid'],e['start_ticks']):
        raise ValueError('Kernel boot/PID/start identity required')
    user=e.get('username')
    if not isinstance(user,str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user):
        raise ValueError('Invalid process account')
    for key in ('real_uid','effective_uid'):
        if type(e.get(key)) is not int or e[key]<0:raise ValueError('Invalid UID')
    for key in ('ancestry_process_ids','sshd_process_ids'):
        value=e.get(key)
        if not isinstance(value,list) or not value or len(value)>32 or any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{64}',x) for x in value):
            raise ValueError('Invalid process ancestry identities')
    for key in ('ancestry_pids','sshd_pids'):
        value=e.get(key)
        if not isinstance(value,list) or not value or len(value)>32 or any(type(x) is not int or x<=0 for x in value):
            raise ValueError('Invalid process ancestry PIDs')
    if len(e['ancestry_process_ids'])!=len(e['ancestry_pids']) or len(e['sshd_process_ids'])!=len(e['sshd_pids']):
        raise ValueError('Ancestry arrays differ in length')
    if not set(zip(e['sshd_pids'],e['sshd_process_ids']))<=set(zip(e['ancestry_pids'],e['ancestry_process_ids'])):
        raise ValueError('SSHD must be an actual ancestor')
    result={k:e[k] for k in ('kind','pid','start_ticks','process_id','boot_id','executable','real_uid','effective_uid',
        'session_uid','username','source_port','sshd_pids','sshd_process_ids','ancestry_pids','ancestry_process_ids')}
    result.update(event_time=stamp(instant(e['event_time'])),source_ip=src,target_ip=dst,target_host=host,
        observer_uid=0,kernel_process_observation=True,telemetry_trust='root_owned_kernel_proc_polling_not_tamper_resistant')
    if e['kind']=='process.shell_socket':
        if e.get('stdin_stdout_same_socket') is not True or not str(e.get('socket_inode','')).isdecimal():
            raise ValueError('Shell stdin/stdout socket evidence required')
        if e.get('peer_ip')!=src or e.get('local_ip')!=dst:
            raise ValueError('Callback peer must match the authenticated actor')
        for key in ('peer_port','local_port'):
            if type(e.get(key)) is not int or not 1<=e[key]<=65535:raise ValueError('Invalid callback port')
        result.update({k:e[k] for k in ('socket_inode','peer_ip','peer_port','local_ip','local_port')})
        result['stdin_stdout_same_socket']=True
    return result


def with_callback_proofs(events):
    """Attach outgoing SYN evidence before opposite-direction episodes split.

    Input order and duplicated EVE streams cannot change direction evidence.
    The field is internal and always recomputed, never accepted from the probe.
    """
    from lab_correlation import instant
    syns=[s for s in events if s['kind']=='network.tcp_syn' and s.get('signature_id')=='9900003']
    result=[]
    for e in events:
        if e['kind']!='process.shell_socket':result.append(e);continue
        hits=[s for s in syns if (s['source_ip'],s['target_ip'],s.get('source_port'),s.get('destination_port'),s.get('sensor_id'))==
              (e['local_ip'],e['peer_ip'],e['local_port'],e['peer_port'],e['target_host'])
              and 0<=(instant(e['event_time'])-instant(s['event_time'])).total_seconds()<=10]
        result.append({**e,'_callback_syn_ids':sorted({s['event_id'] for s in hits})})
    return result


def extend_process_cases(cases,events,config):
    """Join only exact native SSH PID, account, endpoints, port and callback tuple."""
    from lab_correlation import instant,digest
    rows=list({e['event_id']:e for e in events}.values())
    # Whole-session builds can recompute proofs; episode builds retain already
    # correlated opposite-direction evidence after partitioning by target.
    by_id={e['event_id']:e for e in with_callback_proofs(rows)}
    for e in rows:
        if e['kind']!='process.shell_socket':continue
        proofs=by_id[e['event_id']].get('_callback_syn_ids') or e.get('_callback_syn_ids',[])
        if not proofs:continue
        auth=[a for a in rows if a['kind']=='auth.success' and a.get('sshd_pid') in e['sshd_pids']
              and all(a.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username','source_port'))
              and 0<=(instant(e['event_time'])-instant(a['event_time'])).total_seconds()<=config.get('chain_max_seconds',900)]
        if len(auth)!=1:continue
        a=auth[0]
        candidates=[c for c in cases.values() if all(c.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username'))
            and any(s['name']=='auth_success_after_failures' and a['event_id'] in s['evidence_ids'] for s in c['stages'])]
        if len(candidates)>1:continue
        if candidates:c=candidates[0]
        else:
            cid='process:'+digest(a['event_id'])
            c=cases.setdefault(cid,dict(schema_version='soc-correlation-case/0.1',case_id=cid,
                status='observed_reverse_shell',source_ip=e['source_ip'],target_ip=e['target_ip'],target_host=e['target_host'],
                username=e['username'],first_seen=a['event_time'],last_seen=a['event_time'],
                stages=[dict(name='observed_ssh_session',start_time=a['event_time'],end_time=a['event_time'],
                    evidence_ids=[a['event_id']],sshd_pid=a['sshd_pid'],source_port=a['source_port'])],
                confirmed_compromise=False,training_label=None,
                explanation='Exact native SSH authentication + shell socket FDs + outgoing TCP SYN. Authorization and compromise are unconfirmed.'))
            failures=[x for x in rows if x['kind']=='auth.failure' and x.get('auth_method')=='password'
                and all(x.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username'))
                and 0<(instant(a['event_time'])-instant(x['event_time'])).total_seconds()<=config['failure_window_seconds']]
            if failures and not any(s['name']=='observed_auth_failures' for s in c['stages']):
                failures.sort(key=lambda x:(x['event_time'],x['event_id']))
                c['stages'].insert(0,dict(name='observed_auth_failures',start_time=failures[0]['event_time'],end_time=failures[-1]['event_time'],
                    evidence_ids=[x['event_id'] for x in failures],failure_count=len(failures),threshold=config['failure_threshold'],window_seconds=config['failure_window_seconds']))
        c['status']='observed_reverse_shell';c['endpoint_evidence_scope']='kernel_proc_ssh_pid_fd_outgoing_syn'
        existing=next((s for s in c['stages'] if s['name']=='observed_reverse_shell'),None)
        stage={k:e[k] for k in ('pid','process_id','boot_id','start_ticks','executable','real_uid','effective_uid',
            'session_uid','source_port','sshd_pids','peer_ip','peer_port','local_ip','local_port','socket_inode','stdin_stdout_same_socket')}
        stage.update(name='observed_reverse_shell',start_time=e['event_time'],end_time=e['event_time'],
            evidence_ids=sorted({e['event_id'],a['event_id'],*proofs}),callback_syn_evidence_ids=proofs,
            native_ssh_session_verified=True,outgoing_syn_verified=True,kernel_process_observation=True,
            callback_process_count=1,telemetry_trust='root_owned_proc_polling_not_complete_audit')
        if existing:
            existing['evidence_ids']=sorted(set(existing['evidence_ids']+stage['evidence_ids']))
            existing['callback_syn_evidence_ids']=sorted(set(existing['callback_syn_evidence_ids']+proofs))
            existing['start_time']=min(existing['start_time'],stage['start_time']);existing['end_time']=max(existing['end_time'],stage['end_time'])
            existing['callback_process_count']=len({x['process_id'] for x in rows if x['kind']=='process.shell_socket' and x['event_id'] in existing['evidence_ids']})
        else:c['stages'].append(stage)
        add_contact_context(c,rows,config)
        c['first_seen']=min(s['start_time'] for s in c['stages']);c['last_seen']=max(s['end_time'] for s in c['stages'])


def add_contact_context(case,events,config):
    """Single-port contact is context, never proof of Nmap/recon or a risk bonus."""
    from lab_correlation import instant
    if any(s['name'] in ('possible_recon','ssh_service_contact') for s in case['stages']):return
    first=min(instant(s['start_time']) for s in case['stages'])
    known_ports={e.get('source_port') for e in events if e['kind'].startswith('auth.') and
        all(e.get(k)==case.get(k) for k in ('source_ip','target_ip','target_host'))}
    contacts=[e for e in events if e['kind']=='network.tcp_syn' and e.get('signature_id')=='9900003'
        and all(e.get(k)==case.get(k) for k in ('source_ip','target_ip','target_host'))
        and e.get('destination_port')==22 and e.get('source_port') not in known_ports
        and 0<(first-instant(e['event_time'])).total_seconds()<=60]
    if not contacts:return
    contacts=sorted({(e['flow_id'],e['source_port']):e for e in contacts}.values(),key=lambda e:(e['event_time'],e['event_id']))
    case['stages'].insert(0,dict(name='ssh_service_contact',start_time=contacts[0]['event_time'],end_time=contacts[-1]['event_time'],
        evidence_ids=[e['event_id'] for e in contacts],target_port=22,connection_count=len(contacts),reconnaissance_proven=False,
        detection_method='unattributed_pre_auth_ssh_syn_context',limitation='Single-port SYN cannot identify Nmap or malicious reconnaissance.'))
