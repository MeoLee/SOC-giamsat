"""Server-evidenced HTTP pressure, with same-route latency/error comparison.

Request volume alone is not service impact. Client reports/MLP labels never
supply detector evidence. Windows are bounded and deduplicate server records.
"""
from collections import defaultdict
from datetime import timedelta
import math


def route(event):
    value=event.get('url_path') or (event.get('request_target') or '').partition('?')[0]
    return value if isinstance(value,str) and value.startswith('/') and len(value.encode('utf-8'))<=512 else '__unknown_route__'


def percentile(values,q):
    ordered=sorted(values)
    return ordered[max(0,math.ceil(len(ordered)*q)-1)] if ordered else None


def http_cases(events,config):
    from lab_correlation import instant,digest
    from lab_campaign import validate
    c=validate(config);groups=defaultdict(dict);services=defaultdict(dict)
    for e in events:
        if e['kind'] not in ('web.request','web.sqli_indicator') or e.get('evidence_provider')!='apache_tsv':continue
        identity=e.get('http_record_id')
        if not identity or not e.get('http_origin'):continue
        # Method/path are part of the application boundary. Never compare a
        # cheap /health route against expensive PHP or mix GET and POST.
        key=(e['target_host'],e['target_ip'],e.get('destination_port'),e['http_origin'],e.get('http_method','GET'),route(e))
        if not e.get('_chain_baseline_only'):groups[(*key,e['source_ip'])][identity]=e
        services[key][identity]=e
    result=[]
    for key,unique in sorted(groups.items()):
        timeline=sorted(unique.values(),key=lambda e:(e['event_time'],e['event_id']))
        # A low-rate baseline must not become the beginning of a later flood
        # window (which would also place onset before a preceding port scan).
        segments=[]
        for e in timeline:
            if not segments or (instant(e['event_time'])-instant(segments[-1][-1]['event_time'])).total_seconds()*1e6>c['http_pressure_gap_us']:
                segments.append([])
            segments[-1].append(e)
        for segment in segments:
            i=0
            while i<len(segment):
                first=segment[i];start=instant(first['event_time']);end=start+timedelta(seconds=c['http_pressure_window_seconds'])
                j=i
                while j<len(segment) and instant(segment[j]['event_time'])<end:j+=1
                burst=segment[i:j]
                if len(burst)<c['http_pressure_threshold']:break
                prior=[e for e in services[key[:-1]].values() if start-timedelta(seconds=120)<=instant(e['event_time'])<start
                       and instant(e.get('available_time') or e['event_time'])<=start]
                baseline=sorted(prior,key=lambda e:(e['event_time'],e['event_id']))[-c['http_baseline_maximum']:]
                durations=[e['duration_us'] for e in baseline if type(e.get('duration_us')) is int]
                p95=percentile(durations,.95)
                healthy=bool(key[-2]!='__unknown_route__' and len(baseline)>=c['http_baseline_minimum']
                    and len(durations)==len(baseline)
                    and sum(e['duration_us']>=c['http_slow_us'] or not 200<=e.get('http_status',0)<400 for e in baseline)/len(baseline)<.1)
                cutoff=max(c['http_slow_us'],(p95 or 0)*c['http_latency_multiplier'])
                errors=sum(500<=e.get('http_status',0)<=599 for e in burst)
                slows=sum(e.get('duration_us',0)>=cutoff for e in burst)
                minimum=max(5,math.ceil(len(burst)*.2))
                degraded=healthy and (errors>=minimum or slows>=minimum)
                s=dict(name='possible_http_dos' if degraded else 'http_request_pressure',
                    start_time=first['event_time'],end_time=max(e.get('available_time') or e['event_time'] for e in burst),
                    evidence_ids=[e['event_id'] for e in burst],request_count=len(burst),
                    threshold=c['http_pressure_threshold'],window_seconds=c['http_pressure_window_seconds'],
                    window_rate_rps=round(len(burst)/c['http_pressure_window_seconds'],3),
                    http_route=key[-2],http_method=key[-3],application='dvwa' if key[-2].startswith('/dvwa/') else 'http',
                    target_port=key[2],server_5xx_count=errors,slow_request_count=slows,slow_us=cutoff,
                    server_5xx_ratio=round(errors/len(burst),4),slow_request_ratio=round(slows/len(burst),4),
                    baseline_request_count=len(baseline),baseline_p95_us=p95,
                    burst_p50_us=percentile([e.get('duration_us',0) for e in burst],.5),
                    burst_p95_us=percentile([e.get('duration_us',0) for e in burst],.95),
                    latency_multiplier=c['http_latency_multiplier'],baseline_evidence_ids=sorted(e['event_id'] for e in baseline),
                    healthy_baseline_observed=healthy,baseline_comparison_scope='same_host_ip_port_origin_method_path',
                    service_degradation_observed=degraded,dos_causality_proven=False,
                    detection_method='apache_completed_requests_rate_and_route_baseline',
                    limitation='Apache logs completed requests; unaccepted/timed-out requests and network completeness are not established')
                result.append(dict(case_id='http:'+digest([key,first['http_record_id']]),target_host=first['target_host'],
                    target_ip=first['target_ip'],source_ip=first['source_ip'],username=None,stages=[s]))
                i=j
    return result
