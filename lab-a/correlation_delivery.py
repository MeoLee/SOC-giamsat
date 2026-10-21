"""Bound legacy correlation delivery; full events remain in live-activities.jsonl."""
from copy import deepcopy
from wazuh_bridge import encoded

LIMIT=6000

def compact(event,local_file):
    row=deepcopy(event)
    size=lambda:len(encoded(row).encode('utf-8'))
    if size()<=LIMIT:return row
    row.update(delivery_compacted=True,full_event_local_file=str(local_file),full_event_id=event['event_id'])
    removed=[]
    for key in ('attack_chain_json','chain_stage_details','activity','conclusion','attack_type','risk_basis','sample_request_target','evidence_ids'):
        if key in row:
            row.pop(key);removed.append(key)
            row['delivery_omitted_fields']=list(removed)
        if size()<=LIMIT:return row
    # Adversarially large optional metadata must not terminate the collector.
    keep=('soc_ai_producer','soc_ai_kind','event_id','schema_version','session_id','event_time',
          'timestamp','experimental','prediction_is_not_ground_truth','case_id','case_status','chain_id','source_ip','target_ip','target_host','username',
          'risk_score','risk_level','confirmed_compromise','attack_chain_stage_count','evidence_count')
    row={k:event[k] for k in keep if k in event}
    for k,v in list(row.items()):
        if isinstance(v,str):row[k]=v.encode('utf-8')[:160].decode('utf-8',errors='ignore')
    row.update(delivery_compacted=True,delivery_minimal_summary=True,full_event_id=event['event_id'],
        full_event_local_file=str(local_file).encode('utf-8')[:512].decode('utf-8',errors='ignore'))
    return row
