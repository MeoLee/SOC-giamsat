"""Deterministic event-time isolation; no scenario IDs, UI input or ML labels."""
from bisect import bisect_right
from collections import defaultdict
from copy import deepcopy
from datetime import timedelta,datetime,timezone


def episodes(events,config):
    from lab_correlation import instant
    from lab_recon import scan_evidence
    from lab_campaign import http_cases
    scans=scan_evidence(events,config)
    proof_ids={i for s in scans for i in s['recon_evidence_ids']}
    http_ids={i for b in http_cases(events,config) for s in b['stages'] for i in s['evidence_ids']}
    grouped=defaultdict(list);scan_groups=defaultdict(list)
    def key(e):return e['source_ip'],e['target_ip'],e['target_host']
    for e in events:
        if all(e.get(k) is not None for k in ('source_ip','target_ip','target_host')):grouped[key(e)].append(e)
    for s in scans:scan_groups[key(s)].append(s)
    result=[]
    for identity,rows in sorted(grouped.items()):
        roots=[];last_scan=None;root_start=None
        for s in scan_groups[identity]:
            t=instant(s['event_time'])
            if last_scan is None or (t-last_scan).total_seconds()>config['chain_rescan_gap_seconds'] or (t-root_start).total_seconds()>config['chain_max_seconds']:
                roots.append(instant(s['recon_window_start']));root_start=t
            last_scan=t
        anchors=sorted((e for e in rows if e['event_id'] in proof_ids or e['event_id'] in http_ids
            or e['kind'].startswith('auth.') or e['kind'] in ('process.execution','file.transfer','web.sqli_indicator')),
            key=lambda e:(instant(e['event_time']),e['event_id']))
        if not anchors:continue
        boundaries=[];previous=None;start=None
        for e in anchors:
            t=instant(e['event_time'])
            new_scan=previous is not None and any(previous<r<=t for r in roots)
            if previous is None or new_scan or (t-previous).total_seconds()>=config['chain_idle_seconds'] or (t-start).total_seconds()>=config['chain_max_seconds']:
                boundaries.append(t);start=t
            previous=t
        buckets=[[] for _ in boundaries]
        for e in rows:
            index=max(0,bisect_right(boundaries,instant(e['event_time']))-1)
            buckets[index].append(e)
        for i,bucket in enumerate(buckets):
            bucket_ids={e['event_id'] for e in bucket}
            # A previous healthy HTTP baseline may support degradation evidence,
            # but may not be counted again as an attack event in this episode.
            prior=[{**e,'_chain_baseline_only':True} for e in rows if e['kind'] in ('web.request','web.sqli_indicator')
                   and boundaries[i]-timedelta(seconds=120)<=instant(e['event_time'])<boundaries[i]
                   and e['event_id'] not in bucket_ids]
            result.append({'events':bucket+prior,'boundary':boundaries[i].isoformat(),
                           'method':'exact_endpoints_new_scan_or_idle_gap','overlap_cannot_establish_actor_intent':True})
    return result


def lifecycle(chain,config,now=None):
    from lab_correlation import instant
    now=now or datetime.now(timezone.utc)
    elapsed=(now-instant(chain['last_seen'])).total_seconds()
    state='clock_skew' if elapsed < -5 else 'quiescent' if elapsed>=config['chain_idle_seconds'] else 'waiting' if elapsed>=15 else 'active'
    formed=len(chain['stages'])>=2
    expired=state=='quiescent' and not formed
    return {'chain_status':'expired_singleton' if expired else state,
            'chain_active':not expired,
            'chain_display_state':'formed' if formed else 'expired_singleton' if expired else 'pending_singleton',
            'chain_expiration_reason':'single_observed_stage_idle_timeout' if expired else '',
            'chain_idle_seconds':config['chain_idle_seconds'],
            'chain_evaluated_at':now.isoformat(timespec='microseconds'),
            'chain_end_proven':False,'next_step_method':'curated_evidence_runbook',
            'next_step_probability_calibrated':False,
            'next_step_ready':state=='quiescent' and formed}
