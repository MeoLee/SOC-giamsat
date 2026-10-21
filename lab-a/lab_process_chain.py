"""Verified shell/socket behavior with explicit SSH attribution strength."""
import json
import re
from process_observer import SCHEMA,SHELLS,identity,private


def normalize(raw,config,source):
    from lab_correlation import instant,stamp,ip_host
    e=json.loads(raw)
    if not isinstance(e,dict):raise ValueError('Observer object required')
    if e.get('kind') in ('file.artifact_closed','file.cron_changed','process.script_execution'):
        from artifact_chain import normalize_artifact
        return normalize_artifact(e,config,source)
    if e.get('schema_version') not in ('soc-process-observer/0.1',SCHEMA) or e.get('kind')!='process.shell_socket':raise ValueError('Unsupported process observation')
    origin=config.get('source_origins',{}).get(source,{})
    if origin.get('source_path')!='/var/log/soc-lab/process-observer/events.jsonl' or type(e.get('observer_uid')) is not int or e['observer_uid']!=0 or e.get('kernel_process_observation') is not True:raise ValueError('Root-owned kernel process source required')
    src,dst=private(e['source_ip']),private(e['target_ip']);host=ip_host(dst,config)
    if host.startswith('ip:') or origin.get('source_container')!=host:raise ValueError('Observer target must match its configured asset')
    method=e.get('ssh_context_method','live_ssh_ancestry')
    if method not in ('live_ssh_ancestry','cached_observed_ancestry','environment_hint','unavailable'):raise ValueError('Invalid SSH context method')
    for k in ('pid','start_ticks'):
        if type(e.get(k)) is not int or e[k]<=0:raise ValueError('Invalid process identity')
    for k in ('source_port','session_uid','real_uid','effective_uid'):
        if type(e.get(k)) is not int or e[k]<0:raise ValueError('Invalid process/session integer')
    if e['source_port']>65535 or method!='unavailable' and (e['source_port']==0 or e.get('target_port')!=22):raise ValueError('Invalid SSH port identity')
    if method in ('live_ssh_ancestry','cached_observed_ancestry') and e['session_uid']==0:raise ValueError('Legacy session UID must be non-root')
    if e.get('executable') not in SHELLS:raise ValueError('Actual shell executable required')
    if not re.fullmatch(r'[a-f0-9-]{36}',e.get('boot_id','')) or e.get('process_id')!=identity(e['boot_id'],e['pid'],e['start_ticks']):raise ValueError('Kernel boot/PID/start identity required')
    if not isinstance(e.get('username'),str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',e['username']):raise ValueError('Invalid process account')
    for ids,pids in (('ancestry_process_ids','ancestry_pids'),('sshd_process_ids','sshd_pids')):
        a,b=e.get(ids),e.get(pids)
        if not isinstance(a,list) or not isinstance(b,list) or len(a)!=len(b) or len(a)>32 or any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{64}',x) for x in a) or any(type(x) is not int or x<=0 for x in b):raise ValueError('Invalid process ancestry')
    if method=='live_ssh_ancestry' and (not e['sshd_pids'] or not set(zip(e['sshd_pids'],e['sshd_process_ids']))<=set(zip(e['ancestry_pids'],e['ancestry_process_ids']))):raise ValueError('SSHD must be an actual ancestor')
    if method=='cached_observed_ancestry' and not e['sshd_pids']:raise ValueError('Cached ancestry requires a previously observed SSH ancestor')
    if e.get('stdin_stdout_same_socket') is not True or not str(e.get('socket_inode','')).isdecimal() or int(e['socket_inode'])<=0:raise ValueError('Shell stdin/stdout socket proof required')
    if e.get('peer_ip')!=src or e.get('local_ip')!=dst:raise ValueError('Socket tuple must match source and target')
    for k in ('peer_port','local_port'):
        if type(e.get(k)) is not int or not 1<=e[k]<=65535:raise ValueError('Invalid callback port')
    fields=('kind','pid','start_ticks','process_id','boot_id','executable','real_uid','effective_uid','session_uid','username','source_port','sshd_pids','sshd_process_ids','ancestry_pids','ancestry_process_ids','socket_inode','peer_ip','peer_port','local_ip','local_port','stdin_stdout_same_socket')
    result={k:e[k] for k in fields}
    result.update(event_time=stamp(instant(e['event_time'])),source_ip=src,target_ip=dst,target_host=host,observer_uid=0,kernel_process_observation=True,ssh_context_method=method,telemetry_trust='root_owned_kernel_proc_polling_not_tamper_resistant')
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


def matching_auth(e,rows,config):
    from lab_correlation import instant
    matches=[a for a in rows if a['kind']=='auth.success' and all(a.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username')) and 0<=(instant(e['event_time'])-instant(a['event_time'])).total_seconds()<=config.get('chain_max_seconds',900)]
    method=e.get('ssh_context_method','live_ssh_ancestry')
    if method in ('live_ssh_ancestry','cached_observed_ancestry'):
        matches=[a for a in matches if a.get('sshd_pid') in e['sshd_pids'] and a.get('source_port')==e['source_port']]
        link='native_ssh_pid' if method=='live_ssh_ancestry' else 'cached_kernel_ssh_ancestry'
    elif e.get('source_port'):
        matches=[a for a in matches if a.get('source_port')==e['source_port']];link='environment_and_unique_auth_hypothesis'
    else:link='unique_account_peer_time_hypothesis'
    return (matches[0],link) if len(matches)==1 else (None,'ambiguous_or_missing_ssh_context')


def extend_process_cases(cases,events,config):
    from lab_correlation import instant,digest
    rows=list({e['event_id']:e for e in events}.values());by_id={e['event_id']:e for e in with_callback_proofs(rows)}
    for e in rows:
        if e['kind']!='process.shell_socket':continue
        proofs=by_id[e['event_id']].get('_callback_syn_ids') or e.get('_callback_syn_ids',[])
        if not proofs:continue
        auth,link=matching_auth(e,rows,config)
        # Legacy strict behavior is kept outside the opt-in extended profile.
        if auth is None and not config.get('ssh_extended_chains_enabled'):continue
        candidates=[c for c in cases.values() if all(c.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username')) and auth and any(auth['event_id'] in s['evidence_ids'] for s in c['stages'])]
        if len(candidates)>1:
            candidates=[];auth=None;link='ambiguous_case_context'
        if candidates:c=candidates[0]
        else:
            cid='process:'+digest(auth['event_id'] if auth else e['process_id'])
            c=cases.setdefault(cid,dict(schema_version='soc-correlation-case/0.1',case_id=cid,status='observed_reverse_shell',source_ip=e['source_ip'],target_ip=e['target_ip'],target_host=e['target_host'],username=e['username'],first_seen=e['event_time'],last_seen=e['event_time'],stages=[],confirmed_compromise=False,training_label=None,explanation='Kernel-observed shell stdin/stdout on an established socket and matching outgoing SYN. SSH association strength is explicit; authorization and escalation are unconfirmed.'))
            if auth and not c['stages']:c['stages'].append(dict(name='observed_ssh_session',start_time=auth['event_time'],end_time=auth['event_time'],evidence_ids=[auth['event_id']],sshd_pid=auth.get('sshd_pid'),source_port=auth['source_port']))
            failures=[a for a in rows if auth and a['kind']=='auth.failure' and a.get('auth_method')=='password' and all(a.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username')) and 0<(instant(auth['event_time'])-instant(a['event_time'])).total_seconds()<=config['failure_window_seconds']]
            if failures and not any(s['name']=='observed_auth_failures' for s in c['stages']):
                failures.sort(key=lambda a:(a['event_time'],a['event_id']));c['stages'].insert(0,dict(name='observed_auth_failures',start_time=failures[0]['event_time'],end_time=failures[-1]['event_time'],evidence_ids=[a['event_id'] for a in failures],failure_count=len(failures),threshold=config['failure_threshold'],window_seconds=config['failure_window_seconds']))
        c.update(status='observed_reverse_shell',endpoint_evidence_scope='kernel_proc_shell_fd_outgoing_syn_with_explicit_ssh_attribution')
        stage={k:e[k] for k in ('pid','process_id','boot_id','start_ticks','executable','real_uid','effective_uid','session_uid','source_port','sshd_pids','peer_ip','peer_port','local_ip','local_port','socket_inode','stdin_stdout_same_socket')}
        stage.update(name='observed_reverse_shell',start_time=e['event_time'],end_time=e['event_time'],evidence_ids=sorted({e['event_id'],*proofs,*([auth['event_id']] if auth else [])}),callback_syn_evidence_ids=proofs,native_ssh_session_verified=link in ('native_ssh_pid','cached_kernel_ssh_ancestry'),ssh_session_link_method=link,outgoing_syn_verified=True,kernel_process_observation=True,reverse_shell_behavior_verified=True,callback_process_count=1,telemetry_trust='root_owned_proc_polling_not_complete_audit')
        existing=next((s for s in c['stages'] if s['name']=='observed_reverse_shell'),None)
        if existing:
            existing['evidence_ids']=sorted(set(existing['evidence_ids']+stage['evidence_ids']));existing['callback_syn_evidence_ids']=sorted(set(existing['callback_syn_evidence_ids']+proofs));existing['end_time']=max(existing['end_time'],stage['end_time'])
            existing['callback_process_count']=len({a['process_id'] for a in rows if a['kind']=='process.shell_socket' and a['event_id'] in existing['evidence_ids']})
        else:c['stages'].append(stage)
        add_contact_context(c,rows,config)
        c['stages'].sort(key=lambda s:(s['start_time'],s['name']));c['first_seen']=min(s['start_time'] for s in c['stages']);c['last_seen']=max(s['end_time'] for s in c['stages'])

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
