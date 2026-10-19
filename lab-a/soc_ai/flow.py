"""One versioned flow normalizer and one ordered feature function for batch/inference."""
from datetime import datetime, timezone
import ipaddress
import math
import numpy as np
from .common import digest

SCHEMA='soc-network-flow/0.1'
FEATURE_VERSION='soc-flow-features/0.1'
NUMERIC=['log_duration_ms','log_pkts_toserver','log_pkts_toclient',
         'log_bytes_toserver','log_bytes_toclient','log_mean_packet_bytes_toserver',
         'log_mean_packet_bytes_toclient','log_total_packets_per_second',
         'log_total_bytes_per_second','reply_packet_fraction','reply_byte_fraction',
         'log_total_mean_packet_bytes']
APPS=['ssh','ftp','http','tls','dns','other']
STATES=['new','established','closed','other']
FEATURE_NAMES=NUMERIC+['is_tcp','is_udp']+['app_'+x for x in APPS]+['state_'+x for x in STATES]
SPEC={'version':FEATURE_VERSION,'names':FEATURE_NAMES,'numeric_log':'natural log1p',
      'rate_duration_floor_seconds':0.001,'standardized_clip':10,
      'ip_ports_rule_ids_labels_not_features':True,'requires_completed_flow':True}
FEATURE_HASH=digest(SPEC)

def parse_time(value):
    if not isinstance(value,str) or not value: raise ValueError('timestamp must be a timezone-aware string')
    t=datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.tzinfo is None: raise ValueError('timezone required')
    return t.astimezone(timezone.utc)

def utc(value):
    return value.isoformat(timespec='microseconds').replace('+00:00','Z')

def counter(value):
    if isinstance(value,bool) or not isinstance(value,int) or not 0<=value<=10**15:
        raise ValueError('counter must be nonnegative integer <=1e15')
    return value

def port(value):
    if value is None: return None
    if isinstance(value,bool) or not isinstance(value,int) or not 0<=value<=65535:
        raise ValueError('invalid port')
    return value

def identifier(value):
    """Preserve native IDs without accepting lossy floats or boolean IDs."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('identifier must be an integer or nonempty string; floats lose precision')
    if isinstance(value, int) and value < 0 or isinstance(value, str) and not value.strip():
        raise ValueError('invalid identifier')
    return str(value)

def normalize(event):
    if event.get('schema_version')=='cic-experimental-cohort/0.1':
        return normalize(event['flow'])
    schema=event.get('schema_version')
    if schema in ('cic-suricata-flow-staging/0.1',SCHEMA):
        start=parse_time(event['start_time']); end=parse_time(event['end_time'])
        emitted=parse_time(event.get('eve_timestamp',event['end_time']))
        src,dst=event['src_ip'],event['dest_ip']
        sp,dp=event.get('src_port'),event.get('dest_port')
        proto=event['protocol']; app=event.get('app_protocol','other')
        state=event.get('flow_state','other'); reason=event.get('flow_reason','unknown')
        counts={k:counter(event[k]) for k in ('pkts_toserver','pkts_toclient','bytes_toserver','bytes_toclient')}
    elif event.get('event_type')=='flow':
        flow=event['flow']; start=parse_time(flow['start']); end=parse_time(flow['end'])
        emitted=parse_time(event['timestamp']); src,dst=event['src_ip'],event['dest_ip']
        sp,dp=event.get('src_port'),event.get('dest_port')
        proto=event['proto']; app=event.get('app_proto','other')
        state=flow.get('state','other'); reason=flow.get('reason','unknown')
        counts={k:counter(flow[k]) for k in ('pkts_toserver','pkts_toclient','bytes_toserver','bytes_toclient')}
    else: raise ValueError('unsupported input; expected completed Suricata flow or staging')
    if end<start: raise ValueError('flow end precedes start')
    proto=str(proto).upper()
    flags=[]
    if emitted<start: flags.append('event_timestamp_before_flow_start')
    # Complete counters become usable only at emission; never backdate to start.
    return {'schema_version':SCHEMA,'record_id':event.get('record_id'),
        'flow_id':identifier(event.get('flow_id')),
        'community_id':event.get('community_id'),'start_time':utc(start),'end_time':utc(end),
        'eve_timestamp':utc(emitted),'available_time':utc(max(emitted,end)),
        'duration_seconds':(end-start).total_seconds(),
        'src_ip':str(ipaddress.ip_address(src)),'src_port':port(sp),
        'dest_ip':str(ipaddress.ip_address(dst)),'dest_port':port(dp),
        'protocol':proto,'app_protocol':str(app).lower(),
        'flow_state':str(state).lower(),'flow_reason':reason,**counts,'quality_flags':flags}

def group_key(flow):
    if flow['protocol'] not in ('TCP','UDP') or flow['src_port'] is None or flow['dest_port'] is None:
        raise ValueError('only TCP/UDP endpoint tuples supported')
    ends=sorted([(flow['src_ip'],flow['src_port']),(flow['dest_ip'],flow['dest_port'])])
    return digest([ends,flow['protocol']])

def split_for_group(key,seed=42):
    # Group assignment is independent of provisional label and feature values.
    bucket=int(digest([seed,key])[:16],16)%10000
    return 0 if bucket<7000 else 1 if bucket<8500 else 2

def features(flow):
    if flow['protocol'] not in ('TCP','UDP'): raise ValueError('unsupported protocol for model')
    d=flow['duration_seconds']; p=flow['pkts_toserver']; q=flow['pkts_toclient']
    b=flow['bytes_toserver']; c=flow['bytes_toclient']; denom=max(d,0.001)
    log=math.log1p
    values=[log(d*1000),log(p),log(q),log(b),log(c),log(b/max(p,1)),log(c/max(q,1)),
            log((p+q)/denom),log((b+c)/denom),q/max(p+q,1),c/max(b+c,1),
            log((b+c)/max(p+q,1)),float(flow['protocol']=='TCP'),float(flow['protocol']=='UDP')]
    app=flow['app_protocol']; app=app if app in APPS else 'other'
    state=flow['flow_state']; state=state if state in STATES else 'other'
    values += [float(app==x) for x in APPS]+[float(state==x) for x in STATES]
    result=np.asarray(values,dtype=np.float32)
    if not np.isfinite(result).all(): raise ValueError('nonfinite feature')
    return result

def fit_preprocessor(train_x):
    mean=train_x.mean(axis=0,dtype=np.float64)
    std=train_x.std(axis=0,dtype=np.float64)
    std=np.where(std<1e-6,1.0,std)
    return {'feature_hash':FEATURE_HASH,'mean':mean.tolist(),'std':std.tolist(),'clip':10.0}

def transform(x,preprocessor):
    if preprocessor['feature_hash']!=FEATURE_HASH: raise ValueError('feature schema mismatch')
    mean=np.asarray(preprocessor['mean'],dtype=np.float32)
    std=np.asarray(preprocessor['std'],dtype=np.float32)
    if mean.shape!=(len(FEATURE_NAMES),) or std.shape!=mean.shape or np.any(std<=0):
        raise ValueError('invalid preprocessor shape/std')
    return np.clip((x-mean)/std,-preprocessor['clip'],preprocessor['clip']).astype(np.float32)
