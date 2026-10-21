"""Bounded scan-rooted hypotheses with separate auth, HTTP and SQLi branches.

No scenario names, model predictions or operator reports enter this detector.
A shared source/target/time links branches; it does not prove common intent.
"""
from collections import defaultdict
from copy import deepcopy
from datetime import timedelta

DEFAULTS = {'attack_chain_enabled': False, 'chain_max_seconds': 900,
            'ssh_extended_chains_enabled':False,'artifact_observation_enabled':False,'ssh_contact_observations_enabled':False,'http_load_alerts_enabled':False,'syn_load_alerts_enabled':False,
            'http_pressure_threshold': 60, 'http_pressure_window_seconds': 10,
            'http_slow_us': 1000000, 'http_baseline_minimum': 10,
            'http_baseline_maximum':20,'http_latency_multiplier':5,'http_pressure_gap_us':500000,
            'chain_idle_seconds':90,'chain_rescan_gap_seconds':30}
CATEGORIES = {'observed_script_file':'file_observation','observed_script_execution':'execution','observed_cron_change':'persistence_observation','ssh_service_contact':'authentication_observation','observed_ssh_session':'authentication_observation','observed_reverse_shell':'execution','syn_connection_pressure':'availability_pressure','observed_auth_failures':'authentication_observation','possible_recon': 'reconnaissance',
    'observed_eicar_transfer':'test_file_transfer',
    'repeated_auth_failures': 'credential_access', 'auth_success_after_failures': 'credential_access',
    'observed_shell_execution': 'execution', 'observed_file_transfer': 'transfer',
    'possible_web_sqli': 'web_exploitation_attempt',
    'http_request_pressure': 'availability_pressure', 'possible_http_dos': 'availability_degradation'}
BASE = {'observed_script_file':30,'observed_script_execution':60,'observed_cron_change':60,'ssh_service_contact':0,'observed_ssh_session':0,'observed_reverse_shell':95,'syn_connection_pressure':50,'observed_auth_failures':15,'possible_recon': 40, 'repeated_auth_failures': 65, 'auth_success_after_failures': 85,
        'observed_eicar_transfer':40,
        'observed_shell_execution': 85, 'observed_file_transfer': 85,
        'possible_web_sqli': 60, 'http_request_pressure': 45, 'possible_http_dos': 75}


def validate(config):
    result = {**DEFAULTS, **config}
    for name in ('attack_chain_enabled','ssh_extended_chains_enabled','artifact_observation_enabled','ssh_contact_observations_enabled','http_load_alerts_enabled','syn_load_alerts_enabled'):
        if type(result[name]) is not bool:
            raise ValueError(name+' must be boolean')
    for key, low, high in [('chain_max_seconds',60,3600),('http_pressure_threshold',10,10000),
                           ('http_pressure_window_seconds',1,60),('http_slow_us',1000,60000000),
                           ('http_baseline_minimum',5,1000),('http_baseline_maximum',10,1000),
                           ('http_latency_multiplier',2,100),('http_pressure_gap_us',10000,5000000),('chain_idle_seconds',30,1800),('chain_rescan_gap_seconds',10,600)]:
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError('Invalid campaign setting: '+key)
    if result['http_baseline_maximum']<result['http_baseline_minimum']:
        raise ValueError('HTTP maximum baseline must cover its minimum')
    return result


def http_cases(events, config):
    from http_load_detection import http_cases as detect
    return detect(events, config)


def build_chains(events, branches, config):
    from lab_chain_episode import episodes
    from lab_correlation import build_cases
    c=validate(config)
    if not c['attack_chain_enabled']:return []
    result=[]
    for episode in episodes(events,c):
        # Rebuild auth/SQLi inside the episode to prevent a legacy 600-second
        # aggregation from gluing distinct operations across a fresh scan.
        local=episode['events']
        branch_events=[e for e in local if not e.get('_chain_baseline_only')]
        for chain in _build_episode_chains(local,build_cases(branch_events,c),c):
            chain['isolation_method']=episode['method']
            chain['episode_boundary']=episode['boundary']
            chain['actor_intent_proven']=False
            result.append(chain)
    from lab_file_chain import enrich
    return enrich(sorted(result,key=lambda r:(r['first_seen'],r['chain_id'])), events)


def _build_episode_chains(events, branches, config):
    from lab_correlation import instant, digest
    from lab_recon import scan_evidence, stage as recon_stage
    c=validate(config)
    if not c['attack_chain_enabled']: return []
    roots={}; groups=defaultdict(list)
    for e in scan_evidence(events,config):
        groups[(e['source_ip'],e['target_ip'],e['target_host'],e['sensor_id'])].append(e)
    for key, scans in sorted(groups.items()):
        clusters=[]
        for e in scans:
            if not clusters or (instant(e['event_time'])-instant(clusters[-1][0]['event_time'])).total_seconds()>config['recon_window_seconds']:
                clusters.append([])
            clusters[-1].append(e)
        for cluster in clusters:
            seed=cluster[0]; cid='campaign:'+digest([key,seed['event_id']])
            # Identity is anchored to first qualifying proof, even as evidence grows.
            roots[cid]={'case_id':cid,'source_ip':key[0],'target_ip':key[1], 'target_host':key[2],
                        'anchor_time':seed['event_time'],'proofs':cluster,'stages':[], 'branches':[]}
    all_branches=[b for b in branches if any(s['name']!='possible_recon' for s in b['stages'])]
    consumed={eid for b in all_branches for s in b['stages'] for eid in s['evidence_ids']}
    auth_groups=defaultdict(list)
    for e in events:
        if e['kind']=='auth.failure' and e.get('auth_method')=='password' and e['event_id'] not in consumed:
            candidates=[r for r in roots.values() if
                (r['source_ip'],r['target_ip'],r['target_host'])==(e['source_ip'],e['target_ip'],e['target_host']) and
                0<(instant(e['event_time'])-instant(r['anchor_time'])).total_seconds()<=config['recon_window_seconds']]
            if candidates:
                root=max(candidates,key=lambda r:(r['anchor_time'],r['case_id']))
                auth_groups[(root['case_id'],e['username'])].append(e)
    for (root_id,user), rows in auth_groups.items():
        rows=sorted(rows,key=lambda e:(e['event_time'],e['event_id']));r=roots[root_id]
        all_branches.append({'case_id':'auth-context:'+digest([root_id,user]), 'source_ip':r['source_ip'],
            'target_ip':r['target_ip'],'target_host':r['target_host'],'username':user,'stages':[{
                'name':'observed_auth_failures','start_time':rows[0]['event_time'],'end_time':rows[-1]['event_time'],
                'evidence_ids':[e['event_id'] for e in rows],'failure_count':len(rows),
                'threshold':config['failure_threshold'],'window_seconds':config['failure_window_seconds']}]})
    from syn_load_detection import syn_cases
    all_branches+=http_cases(events,c)+syn_cases(events,c)
    from ssh_contact_detection import attach_contacts
    all_branches=attach_contacts(all_branches,events,c)
    for b in sorted(all_branches,key=lambda b:b['case_id']):
        parts=[deepcopy(s) for s in b['stages'] if s['name']!='possible_recon']
        start=min(instant(s['start_time']) for s in parts)
        candidates=[r for r in roots.values() if r.get('proofs') and
                    (r['source_ip'],r['target_ip'],r['target_host'])==(b['source_ip'],b['target_ip'],b['target_host'])
                    and 0<(start-instant(r['anchor_time'])).total_seconds()<=min(config['recon_window_seconds'],c['chain_max_seconds'])]
        # Multiple sensors proving the same episode do not establish which root
        # caused an action. Choose the latest proof, record other candidates.
        root=max(candidates,key=lambda r:(r['anchor_time'],r['case_id'])) if candidates else None
        if root is None:
            cid='campaign:'+digest(['ssh-contact-root',b['_contact_root_id']]) if b.get('_contact_root_id') else 'campaign:'+digest(['unobserved-recon',b['case_id']])
            root=roots.setdefault(cid,{'case_id':cid,'source_ip':b['source_ip'],'target_ip':b['target_ip'],
                'target_host':b['target_host'],'anchor_time':parts[0]['start_time'],'stages':[], 'branches':[]})
        limit=instant(root['anchor_time'])+timedelta(seconds=c['chain_max_seconds'])
        accepted=[s for s in parts if instant(s['end_time'])<=limit]
        if not accepted: continue
        branch_id='BR-'+digest(b['case_id'])[:16]
        root['branches'].append({'branch_id':branch_id,'case_id':b['case_id'],
            'username':b.get('username'),'association':'same_source_target_time_hypothesis',
            'alternative_roots':len(candidates)-1 if candidates else 0})
        for s in accepted:
            s.update(branch_id=branch_id,username=b.get('username'))
            root['stages'].append(s)
    output=[]
    for r in roots.values():
        stages=r['stages']
        if r.get('proofs'):
            # Root proof is complete before follow-up stages start. Later scans
            # remain separate evidence, not a retroactively longer first step.
            first_follow=min((instant(s['start_time']) for s in stages), default=None)
            proofs=[p for p in r['proofs'] if first_follow is None or instant(p['event_time'])<first_follow]
            stages.insert(0,{**recon_stage(proofs),'branch_id':'recon','username':None})
        stages.sort(key=lambda s:(instant(s['start_time']),s['branch_id'],s['name']))
        chain_id='CHAIN-'+digest(r['case_id'])[:16].upper(); previous={}
        root_id=None
        for s in stages:
            s['stage_id']='ST-'+digest([chain_id,s['branch_id'],s['name']])[:24]
            parents=[previous[s['branch_id']]] if s['branch_id'] in previous else ([root_id] if root_id else [])
            s['parent_relation']='same_source_target_time_hypothesis' if parents and parents[0]==root_id else 'within_branch_observed_sequence'
            s['parent_stage_ids']=parents
            parent=next((p for p in stages if parents and p.get('stage_id')==parents[0]),None)
            s['stage_position']=parent['stage_position']+1 if parent else 0
            previous[s['branch_id']]=s['stage_id']
            if s['name']=='possible_recon':root_id=s['stage_id']
        parents={p for s in stages for p in s['parent_stage_ids']}
        for s in stages:s['is_terminal']=s['stage_id'] not in parents
        cats=sorted({CATEGORIES[s['name']] for s in stages})
        # Execution and transfer strengthen the same auth branch, not three
        # independent attack families. Diversity bonus is capped at five.
        families={('credential_access' if x in ('execution','transfer') else
                   'availability' if x.startswith('availability_') else x) for x in cats if x not in ('reconnaissance','authentication_observation','file_observation')}
        base=max(BASE[s['name']] for s in stages)
        recon=10 if root_id and families else 0; diversity=5 if len(families)>1 else 0
        users=sorted({s['username'] for s in stages if s.get('username')})
        r.update(chain_id=chain_id, stages=stages,categories=cats,accounts=users,
            username=users[0] if len(users)==1 else None,
            first_seen=min(s['start_time'] for s in stages),last_seen=max(s['end_time'] for s in stages),
            risk_policy='soc-operational-risk/0.3',risk_score_base=base,risk_score_recon_bonus=recon,
            risk_score_diversity_bonus=diversity,risk_score_cap=95,risk_score=min(95,base+recon+diversity),
            recon_observed=bool(root_id),confirmed_compromise=False,training_label=None,
            schema_version='soc-attack-chain/0.2', association='same_source_target_time_hypothesis',
            explanation='Branches share source, exact target IP/host and a bounded time window. '
                        'Auth remains per-account/session. Cross-branch causality and compromise are unproven.')
        verified=any(s['name']=='observed_reverse_shell' and s.get('reverse_shell_behavior_verified',s.get('native_ssh_session_verified',False)) and s.get('outgoing_syn_verified') and s.get('stdin_stdout_same_socket') for s in stages)
        r['reverse_shell_behavior_verified']=bool(verified)
        r['risk_level']='critical' if verified else 'high' if r['risk_score']>=70 else 'medium' if r['risk_score']>=40 else 'low'
        if verified:r.update(risk_score=95,risk_score_base=95,risk_policy='soc-operational-risk/0.5')
        r.pop('proofs',None)
        output.append(r)
    return sorted(output,key=lambda r:(r['first_seen'],r['chain_id']))


def stage_detail(stage):
    s=stage
    line=f"{s['start_time']} -> {s['end_time']}; evidence={len(s['evidence_ids'])}"
    for key in ('syn_connection_count','handshake_completion_verified','detection_method','limitation','distinct_destination_ports','port_threshold','port_window_seconds','failure_count',
                'threshold','window_seconds','command','request_count','server_5xx_count','slow_request_count',
                'baseline_request_count','healthy_baseline_observed','service_degradation_observed',
                'window_rate_rps','http_route','http_method','application','target_port','server_5xx_ratio','slow_request_ratio',
                'baseline_p95_us','burst_p50_us','burst_p95_us','slow_us','latency_multiplier','baseline_comparison_scope',
                'artifact_bytes','transfer_url','artifact_path','artifact_sha256','artifact_md5',
                'transfer_method','source_port','test_artifact','executed','vt_status',
                'fim_alert_id','vt_alert_id','vt_rule_id','vt_positives','vt_report_time',
                'pid','process_id','executable','real_uid','effective_uid','session_uid','sshd_pids',
                'peer_ip','peer_port','local_ip','local_port','native_ssh_session_verified','outgoing_syn_verified',
                'reverse_shell_behavior_verified','ssh_session_link_method','artifact_association','file_transport_verified','artifact_observation_count','referenced_paths','callback_process_count','connection_count','reconnaissance_proven','telemetry_trust'):
        if key in s: line+='; '+key+'='+str(s[key])
    return line


def wire_events(chain, session_id, evidence_file, runtime=None):
    from lab_correlation import digest, instant
    from lab_risk import STAGE_LABELS
    from wazuh_bridge import make_event
    c=chain; revision=digest(c); stages=c['stages'];eids={eid for s in stages for eid in s['evidence_ids']}
    common=dict(chain_id=c['chain_id'],session_id=session_id,source_ip=c['source_ip'],target_ip=c['target_ip'],
                target_host=c['target_host'],evidence_file=str(evidence_file),chain_schema=c['schema_version'],chain_revision_id=revision,
                attack_chain_stage_count=len(stages),chain_formed=len(stages)>=2)
    docs=[]
    for s in stages:
        # Evidence reference arrays are samples; the case snapshot has every ID.
        fields={**common, 'stage_id':s['stage_id'],'branch_id':s['branch_id'], 'stage_name':s['name'],'stage_category':CATEGORIES[s['name']],
                'username':s.get('username'),'parent_stage_ids':s['parent_stage_ids'],
                'parent_relation':s['parent_relation'],'stage_position':s['stage_position'],'is_terminal':s['is_terminal'],
                'baseline_evidence_count':len(s.get('baseline_evidence_ids',[])),
                'baseline_evidence_ids':s.get('baseline_evidence_ids',[])[:4],
                'start_time':s['start_time'],'end_time':s['end_time'],'event_time':s['end_time'],
                'evidence_count':len(s['evidence_ids']),'evidence_ids':s['evidence_ids'][:4],
                'stage_details':stage_detail(s),'candidate_technique':STAGE_LABELS[s['name']][1] or 'unmapped',
                'confirmed_compromise':False,'prediction_is_not_ground_truth':True}
        if s['name']=='observed_reverse_shell':
            fields.update({k:s[k] for k in ('pid','process_id','executable','real_uid','effective_uid','session_uid',
                'source_port','sshd_pids','peer_ip','peer_port','local_ip','local_port','socket_inode',
                'stdin_stdout_same_socket','native_ssh_session_verified','outgoing_syn_verified','kernel_process_observation',
                'callback_process_count','telemetry_trust','reverse_shell_behavior_verified','ssh_session_link_method') if k in s})
        if s['name'] in ('observed_script_file','observed_script_execution','observed_cron_change'):
            fields.update({k:s[k] for k in ('artifact_path','artifact_sha256','artifact_bytes','artifact_owner','artifact_association','file_transport_verified','artifact_observation_verified','referenced_paths','executable','pid','process_id') if k in s})
        if s['name']=='ssh_service_contact':
            fields.update({k:s[k] for k in ('target_port','connection_count','reconnaissance_proven','detection_method','limitation')})
        if s['name']=='syn_connection_pressure':
            fields.update({k:s[k] for k in ('syn_connection_count','threshold','window_seconds','target_port','sensor_id','handshake_completion_verified','service_degradation_observed','detection_method','limitation')})
        if s['name']=='observed_eicar_transfer':
            fields.update({k:s[k] for k in ('artifact_path','artifact_sha256','artifact_md5','artifact_bytes',
                'test_artifact','executed','vt_status','fim_alert_id','vt_alert_id','vt_rule_id',
                'vt_positives','vt_report_time','transfer_method','source_port') if k in s})
        if s['name'] in ('http_request_pressure','possible_http_dos'):
            fields.update({k:s[k] for k in ('request_count','threshold','window_seconds','window_rate_rps',
                'http_route','http_method','application','target_port','server_5xx_count','server_5xx_ratio',
                'slow_request_count','slow_request_ratio','slow_us','baseline_request_count','baseline_p95_us',
                'burst_p50_us','burst_p95_us','healthy_baseline_observed','service_degradation_observed',
                'baseline_comparison_scope','detection_method') if k in s})
        docs.append(make_event('chain_stage',[session_id,s['stage_id'],revision],**fields))
    names=list(dict.fromkeys(s['name'] for s in stages))
    fields={**common,**{k:c[k] for k in ('risk_policy','risk_score','risk_level','risk_score_base',
        'risk_score_recon_bonus','risk_score_diversity_bonus','risk_score_cap','recon_observed')},
        'chain_active':True,'case_id':c['case_id'],'case_status':'attack_chain','username':c['username'],'accounts':';'.join(c['accounts'][:16]),'account_count':len(c['accounts']),'accounts_truncated':len(c['accounts'])>16,
        'categories':';'.join(c['categories']),'attack_chain':' -> '.join(names),
        'attack_chain_stage_count':len(stages),'branch_count':len(c['branches']),
        'chain_started_at':c['first_seen'],'chain_last_seen_at':c['last_seen'],'event_time':c['last_seen'],
        'chain_evidence_count':len(eids),'chain_password_failure_count':sum(s.get('failure_count',0) for s in stages),
        'activity':c['explanation'],'association':c['association'],
        'isolation_method':c.get('isolation_method','legacy_window'),'episode_boundary':c.get('episode_boundary',''),
        'actor_intent_proven':False, 'risk_is_probability':False,'reverse_shell_behavior_verified':c.get('reverse_shell_behavior_verified',False),
        'attack_chain_is_causal_proof':False,'confirmed_compromise':False,'techniques_are_hypotheses':True,
        'techniques':';'.join(dict.fromkeys(STAGE_LABELS[n][1] for n in names if STAGE_LABELS[n][1])) or 'unmapped',
        'endpoint_evidence_scope':'controlled_lab_probe_only' if any(n in ('observed_shell_execution','observed_file_transfer','observed_eicar_transfer') for n in names) else 'no_endpoint_probe',
        'chain_duration_seconds':round((instant(c['last_seen'])-instant(c['first_seen'])).total_seconds(),6)}
    if 'observed_reverse_shell' in names:fields['endpoint_evidence_scope']='kernel_proc_ssh_pid_fd_outgoing_syn'
    # Stage documents are queued first; the summary points to their revision IDs.
    summary=make_event('attack_chain',[session_id,c['chain_id'],digest(c)],**fields)
    # The revision list can grow without bound on large cases. Keep an explicit
    # count/digest instead: raw stage docs + local snapshot are authoritative.
    summary.update(runtime or {'chain_status':'unknown','next_step_ready':False,'chain_end_proven':False})
    summary['event_id']=digest([summary['event_id'],summary['chain_status']])
    summary.update(stage_revision_digest=digest([d['event_id'] for d in docs]),
                   stage_revision_count=len(docs))
    return docs+[summary]
