"""Observe bounded SSH auth activity even below the guessing threshold."""
from collections import defaultdict


def extend_auth_context(cases,events,config):
    if not config.get('ssh_extended_chains_enabled'):return
    from lab_correlation import instant,digest
    from ssh_contact_detection import contact_cases
    contacts=contact_cases(events,config);groups=defaultdict(list)
    for e in events:
        if e['kind'] in ('auth.failure','auth.success'):groups[tuple(e[k] for k in ('source_ip','target_ip','target_host','username'))].append(e)
    for key,timeline in sorted(groups.items()):
        segments=[]
        for e in sorted(timeline,key=lambda e:(e['event_time'],e['event_id'])):
            if not segments or (instant(e['event_time'])-instant(segments[-1][-1]['event_time'])).total_seconds()>=config['chain_idle_seconds'] or (instant(e['event_time'])-instant(segments[-1][0]['event_time'])).total_seconds()>=config['chain_max_seconds']:segments.append([])
            segments[-1].append(e)
        for rows in segments:
            ids={e['event_id'] for e in rows}
            existing=[c for c in cases.values() if tuple(c.get(k) for k in ('source_ip','target_ip','target_host','username'))==key and any(ids.intersection(s['evidence_ids']) for s in c['stages'])]
            if len(existing)>1:continue # do not collapse distinct bursts
            prior=any(all(c[k]==rows[0][k] for k in ('source_ip','target_ip','target_host')) and 0<=(instant(rows[0]['event_time'])-instant(c['stages'][0]['end_time'])).total_seconds()<config['chain_idle_seconds'] for c in contacts)
            failures=[e for e in rows if e['kind']=='auth.failure' and e.get('auth_method')=='password']
            if not existing and not prior and not failures:continue
            if existing:c=existing[0]
            else:
                cid='ssh-auth-context:'+digest([key,rows[0]['event_id']]);c=dict(case_id=cid,status='observed_ssh_activity',schema_version='soc-correlation-case/0.1',source_ip=key[0],target_ip=key[1],target_host=key[2],username=key[3],stages=[],first_seen=rows[0]['event_time'],last_seen=rows[-1]['event_time'],confirmed_compromise=False,training_label=None,explanation='Observed SSH authentication activity. Subthreshold failures do not prove brute-force; successive sessions are associated by source, target, account and bounded time.')
                cases[cid]=c
            covered={i for s in c['stages'] for i in s['evidence_ids']}
            for name,selected in [('observed_auth_failures',[e for e in failures if e['event_id'] not in covered]),('observed_ssh_session',[e for e in rows if e['kind']=='auth.success' and e['event_id'] not in covered])]:
                if not selected:continue
                stage=dict(name=name,start_time=selected[0]['event_time'],end_time=selected[-1]['event_time'],evidence_ids=[e['event_id'] for e in selected],source_port=selected[-1]['source_port'],ssh_session_count=len(selected))
                if name=='observed_auth_failures':stage.update(failure_count=len(selected),threshold=config['failure_threshold'],window_seconds=config['failure_window_seconds'])
                if selected[-1].get('sshd_pid'):stage['sshd_pid']=selected[-1]['sshd_pid']
                c['stages'].append(stage)
            c['stages'].sort(key=lambda s:(s['start_time'],s['name']));c['first_seen']=min(s['start_time'] for s in c['stages']);c['last_seen']=max(s['end_time'] for s in c['stages'])
