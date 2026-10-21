"""Unique TCP SYN connection pressure; never handshake failure or outage proof."""
from collections import defaultdict
from datetime import timedelta

def syn_cases(events,config):
    from lab_correlation import instant,digest
    if not config.get('syn_load_alerts_enabled'):return []
    groups=defaultdict(dict)
    for e in events:
        if e.get('kind')!='network.tcp_syn' or e.get('signature_id')!='9900003' or e.get('_chain_baseline_only'):continue
        if not e.get('flow_id') or not e.get('sensor_id'):continue
        key=(e['sensor_id'],e['source_ip'],e['target_ip'],e['target_host'],e['destination_port'])
        identity=(e['flow_id'],e['source_port'])
        old=groups[key].get(identity)
        if old is None or (e['event_time'],e['event_id'])<(old['event_time'],old['event_id']):groups[key][identity]=e
    result=[]
    for key,unique in sorted(groups.items()):
        rows=sorted(unique.values(),key=lambda e:(e['event_time'],e['event_id']));i=0
        while i<len(rows):
            start=instant(rows[i]['event_time']);j=i
            while j<len(rows) and instant(rows[j]['event_time'])<start+timedelta(seconds=10):
                if j>i and (instant(rows[j]['event_time'])-instant(rows[j-1]['event_time'])).total_seconds()>.5:break
                j+=1
            burst=rows[i:j]
            if len(burst)>=100:
                s=dict(name='syn_connection_pressure',start_time=burst[0]['event_time'],end_time=burst[-1]['event_time'],
                    evidence_ids=[e['event_id'] for e in burst],syn_connection_count=len(burst),threshold=100,
                    window_seconds=10,target_port=key[-1],sensor_id=key[0],
                    detection_method='suricata_unique_syn_flows_per_destination_port',
                    handshake_completion_verified=False,service_degradation_observed=False,dos_causality_proven=False,
                    limitation='Unique SYN flows are observations, not proven half-open connections. Retransmissions deduplicated; packet completeness, handshake outcome and DVWA availability unknown.')
                result.append(dict(case_id='syn:'+digest([key,burst[0]['event_id']]),source_ip=key[1],target_ip=key[2],target_host=key[3],username=None,stages=[s]))
            i=j
    return result
