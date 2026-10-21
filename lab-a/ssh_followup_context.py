"""Join a unique account episode without inventing an exact SSH session link."""
from copy import deepcopy


def join_followups(cases,events,config):
    if not config.get('ssh_extended_chains_enabled'):return
    from lab_correlation import instant
    targets=('observed_reverse_shell','observed_artifact_activity')
    follow_names={'observed_reverse_shell','observed_script_file','observed_script_execution','observed_cron_change'}
    auth_names={'observed_ssh_session','auth_success_after_failures'}
    keys=('source_ip','target_ip','target_host','username')
    # Plan all assignments before mutation; input order cannot pick a winner.
    plan=[]
    for cid,c in sorted(cases.items()):
        if c['status'] not in targets:continue
        follow=[s for s in c['stages'] if s['name'] in follow_names]
        if not follow:continue
        first=min(instant(s['start_time']) for s in follow)
        candidates=[]
        for aid,a in sorted(cases.items()):
            if aid==cid or a['status'] in targets or not a.get('username') or any(a.get(k)!=c.get(k) for k in keys):continue
            if not any(s['name'] in auth_names for s in a['stages']):continue
            ids={i for s in a['stages'] for i in s['evidence_ids']}
            successes=[e for e in events if e['kind']=='auth.success' and e['event_id'] in ids and all(e.get(k)==c.get(k) for k in keys) and 0<=(first-instant(e['event_time'])).total_seconds()<config['chain_idle_seconds']]
            if not successes:continue
            lo=min(instant(a['first_seen']),instant(c['first_seen']))
            hi=max(instant(a['last_seen']),instant(c['last_seen']))
            if (hi-lo).total_seconds()>=config['chain_max_seconds']:continue
            candidates.append(aid)
        if len(candidates)==1:plan.append((cid,candidates[0]))
    for cid,aid in plan:
        c,a=cases[cid],cases[aid]
        incoming=[s for s in c['stages'] if s['name'] in follow_names]
        if any(s['name']==x['name'] for s in incoming for x in a['stages']):continue
        for original in incoming:
            s=deepcopy(original)
            s['account_episode_link_method']='unique_account_endpoint_episode_hypothesis'
            a['stages'].append(s)
        a['stages'].sort(key=lambda s:(s['start_time'],s['name']))
        a.update(first_seen=min(s['start_time'] for s in a['stages']),last_seen=max(s['end_time'] for s in a['stages']))
        if c['status']=='observed_reverse_shell':a['status']=c['status']
        a['explanation']+=' Follow-up associated by unique account, exact endpoints and bounded episode; exact SSH attribution remains a separate evidence field.'
        del cases[cid]
