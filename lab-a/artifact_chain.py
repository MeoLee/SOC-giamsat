"""File presence, interpreter paths and cron changes; transport is not inferred."""
import re
from pathlib import PurePosixPath


def normalize_artifact(e,config,source):
    from lab_correlation import host_ip,stamp,instant,ip_host
    from process_observer import SCHEMA,identity,SHELLS,private
    if e.get('schema_version')!=SCHEMA:raise ValueError('Artifact observer schema required')
    origin=config.get('source_origins',{}).get(source,{})
    if origin.get('source_path')!='/var/log/soc-lab/process-observer/events.jsonl' or type(e.get('observer_uid')) is not int or e['observer_uid']!=0:raise ValueError('Root-owned artifact source required')
    host=origin.get('source_container');target=host_ip(host,config)
    if not host or ip_host(target,config)!=host:raise ValueError('Configured artifact asset required')
    kind=e.get('kind');action={'file.artifact_closed':'file_closed','file.cron_changed':'cron_changed','process.script_execution':'script_execution'}.get(kind)
    if not action:raise ValueError('Unsupported artifact kind')
    path=e.get('artifact_path');p=PurePosixPath(path) if isinstance(path,str) else None
    parents=('/tmp','/var/lib/soc-lab/fim','/var/spool/cron','/var/spool/cron/crontabs')
    if p is None or not p.is_absolute() or '..' in p.parts or str(p.parent) not in parents or any(ord(c)<32 for c in path):raise ValueError('Artifact path outside scope')
    if not re.fullmatch('[a-f0-9]{64}',e.get('artifact_sha256','')) or e.get('artifact_hash_complete') is not True:raise ValueError('Complete artifact hash required')
    for k in ('artifact_bytes','artifact_uid','artifact_device','artifact_inode','artifact_mtime_ns'):
        if type(e.get(k)) is not int or e[k]<0:raise ValueError('Invalid artifact metadata')
    if e['artifact_bytes']>1048576:raise ValueError('Artifact exceeds bounded observation')
    if not isinstance(e.get('artifact_owner'),str) or not re.fullmatch('[A-Za-z0-9_-]{1,32}',e['artifact_owner']):raise ValueError('Invalid artifact owner')
    result={k:e[k] for k in ('artifact_path','artifact_sha256','artifact_hash_complete','artifact_bytes','artifact_uid','artifact_owner','artifact_device','artifact_inode','artifact_mtime_ns')}
    result.update(kind=kind,event_time=stamp(instant(e['event_time'])),artifact_action=action,target_ip=target,target_host=host,source_ip=None,username=e['artifact_owner'],observer_uid=0,file_transport_verified=False)
    if kind=='process.script_execution':
        if e.get('kernel_process_observation') is not True or e.get('executable') not in SHELLS:raise ValueError('Kernel interpreter evidence required')
        for k in ('pid','start_ticks','real_uid','effective_uid'):
            if type(e.get(k)) is not int or e[k]<0 or k in ('pid','start_ticks') and e[k]==0:raise ValueError('Invalid interpreter identity')
        if not re.fullmatch(r'[a-f0-9-]{36}',e.get('boot_id','')) or e.get('process_id')!=identity(e['boot_id'],e['pid'],e['start_ticks']):raise ValueError('Interpreter boot/PID/start proof required')
        for k in ('pid','start_ticks','real_uid','effective_uid','executable','process_id','boot_id','source_port','sshd_pids','sshd_process_ids','ancestry_process_ids','ancestry_pids','ssh_context_method'):
            if k in e:result[k]=e[k]
        for ids,pids in (('ancestry_process_ids','ancestry_pids'),('sshd_process_ids','sshd_pids')):
            a,b=e.get(ids),e.get(pids)
            if not isinstance(a,list) or not isinstance(b,list) or len(a)!=len(b) or len(a)>32 or any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{64}',x) for x in a) or any(type(x) is not int or x<=0 for x in b):raise ValueError('Invalid interpreter ancestry')
        if type(e.get('source_port')) is not int or not 0<=e['source_port']<=65535:raise ValueError('Invalid interpreter source port')
        if e.get('ssh_context_method') not in ('live_ssh_ancestry','cached_observed_ancestry','environment_hint','unavailable'):raise ValueError('Invalid interpreter context')
        result['kernel_process_observation']=True
        if e.get('source_ip'):
            result.update(source_ip=private(e['source_ip']),username=e.get('username',e['artifact_owner']))
            if e.get('target_ip')!=target:raise ValueError('Script target differs from protected asset')
    else:
        if e.get('kernel_file_observation') is not True:raise ValueError('Root kernel file observation required')
        result['kernel_file_observation']=True
    if action=='cron_changed':
        refs=e.get('referenced_paths',[])
        if not isinstance(refs,list) or len(refs)>16 or any(not isinstance(x,str) or not x.startswith(('/tmp/','/var/lib/soc-lab/fim/')) or '..' in PurePosixPath(x).parts for x in refs):raise ValueError('Invalid bounded cron references')
        result['referenced_paths']=refs
    return result


def attribute_artifacts(events,config):
    if not config.get('artifact_observation_enabled'):return events
    from lab_correlation import instant
    rows=list(events);result=[]
    for original in rows:
        if original['kind'] not in ('file.artifact_closed','file.cron_changed','process.script_execution'):result.append(original);continue
        e=dict(original);auth=[a for a in rows if a['kind']=='auth.success' and a['target_host']==e['target_host'] and a['target_ip']==e['target_ip'] and a['username']==e['username'] and 0<=(instant(e['event_time'])-instant(a['event_time'])).total_seconds()<config['chain_idle_seconds']]
        if e.get('source_ip'):
            auth=[a for a in auth if a['source_ip']==e['source_ip'] and (not e.get('source_port') or a.get('source_port')==e['source_port'])]
        actors={a['source_ip'] for a in auth}
        if len(actors)==1:
            e.update(source_ip=next(iter(actors)),_artifact_auth_ids=sorted(a['event_id'] for a in auth),artifact_association='file_owner_or_interpreter_and_unique_auth_hypothesis')
        else:
            # An actual interpreter ancestor can bind a detached callback to a
            # script, independently of an environment string or SSH session.
            children=[p for p in rows if p['kind']=='process.shell_socket' and p['target_host']==e['target_host'] and e.get('process_id') and (e['process_id']==p['process_id'] or e['process_id'] in p.get('ancestry_process_ids',[])) and p.get('real_uid')==e.get('real_uid')]
            peers={p['source_ip'] for p in children}
            if len(peers)==1:e.update(source_ip=next(iter(peers)),artifact_association='interpreter_parent_of_shell_socket')
        if e['kind']=='file.cron_changed' and not e.get('referenced_paths'):e['source_ip']=None
        result.append(e)
    return result


def extend_artifact_cases(cases,events,config):
    if not config.get('artifact_observation_enabled'):return
    from lab_correlation import instant,digest
    rows=attribute_artifacts(events,config)
    for e in sorted(rows,key=lambda e:(e['event_time'],e['event_id'])):
        if e['kind'] not in ('file.artifact_closed','file.cron_changed','process.script_execution') or not e.get('source_ip'):continue
        names={'file.artifact_closed':'observed_script_file','process.script_execution':'observed_script_execution','file.cron_changed':'observed_cron_change'}
        name=names[e['kind']];authids=set(e.get('_artifact_auth_ids',[]))
        candidates=[c for c in cases.values() if all(c.get(k)==e.get(k) for k in ('source_ip','target_ip','target_host','username')) and any(authids.intersection(s['evidence_ids']) for s in c['stages'])]
        if len(candidates)>1:continue
        if candidates:c=candidates[0]
        else:
            cid='artifact:'+digest([e['target_host'],e['source_ip'],e['username'],e['event_id']]);c=dict(case_id=cid,status='observed_artifact_activity',schema_version='soc-correlation-case/0.1',source_ip=e['source_ip'],target_ip=e['target_ip'],target_host=e['target_host'],username=e['username'],stages=[],first_seen=e['event_time'],last_seen=e['event_time'],confirmed_compromise=False,training_label=None,explanation='Artifact metadata/interpreter observations associated with a bounded account and endpoint context; file transport and maliciousness are unconfirmed.');cases[cid]=c
        stage={k:e[k] for k in ('artifact_path','artifact_sha256','artifact_bytes','artifact_uid','artifact_owner','artifact_device','artifact_inode','artifact_association','executable','pid','process_id','effective_uid','source_port','referenced_paths') if k in e}
        stage.update(name=name,start_time=e['event_time'],end_time=e['event_time'],evidence_ids=sorted({e['event_id'],*authids}),file_transport_verified=False,artifact_observation_verified=True)
        # Each path/version is an observation, not an invented transfer action.
        old=next((s for s in c['stages'] if s['name']==name),None)
        if old:
            old['evidence_ids']=sorted(set(old['evidence_ids']+stage['evidence_ids']));old['end_time']=max(old['end_time'],stage['end_time']);old['artifact_observation_count']=old.get('artifact_observation_count',1)+1
        else:c['stages'].append(stage)
        c['stages'].sort(key=lambda s:(s['start_time'],s['name']));c['first_seen']=min(s['start_time'] for s in c['stages']);c['last_seen']=max(s['end_time'] for s in c['stages'])
