"""Trace a unique bridge event into manager alerts and a supplied indexer result.

No indexer credentials, disabled TLS validation or assumed dashboard readiness.
The bounded manager read reports its coverage rather than claiming absence.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import time

from live_config import container_name
from soc_ai.common import read_json, write_json
from wazuh_bridge import Publisher, make_event

LAUNCHER = 'if [ -x /var/ossec/framework/python/bin/python3 ]; then exec /var/ossec/framework/python/bin/python3 "$@"; else exec python3 "$@"; fi'
READ_ALERTS = r'''
import json,os,sys
query=json.load(sys.stdin)
path='/var/ossec/logs/alerts/alerts.json'
with open(path,'rb') as f:
    size=os.fstat(f.fileno()).st_size; offset=max(0,size-4*1024*1024)
    f.seek(offset); block=f.read(4*1024*1024)
lines=block.splitlines()
if offset and lines: lines=lines[1:]
matches=[]; invalid=0
for raw in lines:
    try: alert=json.loads(raw)
    except (ValueError,UnicodeError): invalid+=1; continue
    data=alert.get('data',{})
    if not isinstance(data,dict): continue
    if data.get('soc_ai_producer')!='soc-ai-live': continue
    if query.get('event_id') and data.get('event_id')!=query['event_id']: continue
    if query.get('session_id') and data.get('session_id')!=query['session_id']: continue
    matches.append(alert)
print(json.dumps({'alerts':matches,'tail_limited':bool(offset),'bytes_read':len(block),
    'source_size':size,'invalid_json_lines':invalid}))
'''


def manager_alerts(manager, query, runner=subprocess.run):
    container_name(manager)
    r=runner(['docker','exec','-i',manager,'sh','-c',LAUNCHER,
              'soc-ai-trace','-c',READ_ALERTS], input=json.dumps(query).encode(),
             capture_output=True, timeout=15)
    if r.returncode:
        raise RuntimeError('Cannot read manager alerts: '+r.stderr.decode(errors='replace')[:500])
    data=json.loads(r.stdout)
    if not isinstance(data,dict) or not isinstance(data.get('alerts'),list):
        raise ValueError('Invalid manager alert response')
    return data


def index_query(event_id=None, session_id=None):
    field,value=('data.event_id',event_id) if event_id else ('data.session_id',session_id)
    return {'size':100,'query':{'match_phrase':{field:value}},'sort':[{'timestamp':'desc'}]}


def verify_index(report, response):
    eid=report['event_id']
    hits=response.get('hits',{}).get('hits',[])
    found=[h for h in hits if isinstance(h,dict) and
           str(h.get('_index','')).startswith('wazuh-alerts-') and
           h.get('_source',{}).get('data',{}).get('event_id')==eid and
           str(h.get('_source',{}).get('rule',{}).get('id'))=='119201']
    return {**report,'indexer_verified':bool(found),
            'indexer_verification_method':'operator_supplied_search_response',
            'indexed_document_ids':[h.get('_id') for h in found],
            'dashboard_rendering_verified':False}


def auth_outcomes(capture, operator):
    """Count raw server outcomes, not the number of client invocations."""
    from lab_correlation import auth_event, DEFAULTS, instant
    start,end=instant(operator['started_at']),instant(operator['ended_at'])
    source=operator['scope']['source_ip']; user=operator['username']
    config_path=capture/'correlation-cases.json'
    config=read_json(config_path).get('config',DEFAULTS) if config_path.exists() else DEFAULTS
    target=operator['scope'].get('target_ip',config.get('protected_ip'))
    events={}; invalid=0
    with (capture/'ubuntu-auth.log').open(encoding='utf-8-sig') as stream:
        for line in stream:
            try: event=auth_event(line.strip(),config)
            except (ValueError,KeyError,TypeError): invalid+=1; continue
            if not event or event['source_ip']!=source or event['username']!=user: continue
            if event['target_ip']!=target: continue
            if not start<=instant(event['event_time'])<=end: continue
            key=json.dumps(event,sort_keys=True)
            events[key]=event
    ordered=sorted(events.values(),key=lambda e:e['event_time'])
    failures=[e for e in ordered if e['kind']=='auth.failure' and e['auth_method']=='password']
    successes=[e for e in ordered if e['kind']=='auth.success']
    maximum=0
    for i,event in enumerate(failures):
        maximum=max(maximum,sum(0<=(instant(event['event_time'])-instant(old['event_time'])).total_seconds()<=60
                                for old in failures[:i+1]))
    later=bool(failures and any(0<(instant(e['event_time'])-instant(failures[-1]['event_time'])).total_seconds()<=300 for e in successes))
    return {'password_failures':len(failures),'successes':len(successes),
            'maximum_failures_in_60_seconds':maximum,
            'success_within_300_seconds_after_last_failure':later,
            'invalid_auth_lines':invalid,'source_clock_alignment_required':True,
            'events':ordered}


def recon_coverage(capture,operator):
    """Normalized, deduplicated SYN evidence in the operator's actual scope."""
    from lab_recon import instant, scan_evidence, canonical_flow_id
    path=capture/'correlation-events.jsonl'
    scenario=operator['scenario']
    minimum={'normal-http':12,'single-port':24,'port-scan':32,'chain':32,
             'normal-ssh':5,'ssh-negative':2,'ssh-burst':8,'ssh-success':1,'web-sqli':1}.get(scenario)
    if scenario=='http-burst':minimum=operator.get('http_requests')
    events={};event_ids=set();invalid=0
    if path.exists():
        start,end=instant(operator['started_at']),instant(operator['ended_at'])
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                try:
                    row=json.loads(line)
                    if not isinstance(row,dict):raise ValueError('Normalized record must be an object')
                    if row.get('kind')!='network.tcp_syn':continue
                    if (row['source_ip']!=operator['scope']['source_ip'] or
                            row['target_ip']!=operator['scope']['target_ip'] or
                            not start<=instant(row['event_time'])<=end):continue
                    # Old captures may contain two IDs for the same SYN:
                    # native 1034010540483425 and decoded "1034010540483425.000000".
                    # Canonicalize in memory; retain original evidence IDs/files.
                    row={**row,'flow_id':canonical_flow_id(row['flow_id'])}
                    identity=tuple(row[key] for key in ('sensor_id','flow_id','event_time',
                        'source_ip','source_port','target_ip','destination_port','target_host'))
                    event_ids.add(row['event_id'])
                    events.setdefault(identity,row)
                except (ValueError,KeyError,TypeError):invalid+=1
    connections={(e['sensor_id'],e['flow_id'],e['source_ip'],e['source_port'],
                  e['target_ip'],e['destination_port']) for e in events.values()}
    config_path=capture/'correlation-cases.json'
    config=read_json(config_path).get('config',{}) if config_path.exists() else {}
    sufficient=bool(operator.get('complete') and type(minimum) is int and minimum>0
                    and len(connections)>=minimum and not invalid)
    return {'normalized_syn_observations':len(events),'observed_connections':len(connections),
            'normalized_syn_event_ids_read':len(event_ids),
            'duplicate_syn_views_merged':len(event_ids)-len(events),
            'expected_minimum_connections':minimum,'coverage_sufficient':sufficient,
            'distinct_destination_ports':len({e['destination_port'] for e in events.values()}),
            'qualifying_port_sweep_windows':len(scan_evidence(list(events.values()),config)),
            'invalid_normalized_records':invalid,'source_clock_alignment_required':True,
            'packet_completeness_established':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    smoke=sub.add_parser('smoke')
    smoke.add_argument('--manager',default='single-node-wazuh.manager-1')
    smoke.add_argument('--outbox',type=Path,required=True)
    smoke.add_argument('--output',type=Path,required=True)
    trace=sub.add_parser('session')
    trace.add_argument('--manager',default='single-node-wazuh.manager-1')
    trace.add_argument('--capture',type=Path,required=True)
    trace.add_argument('--output',type=Path,required=True)
    trace.add_argument('--operator',type=Path,help='Optional scenario operator.json for raw auth verification')
    verify=sub.add_parser('verify-index')
    verify.add_argument('--report',type=Path,required=True)
    verify.add_argument('--response',type=Path,required=True)
    verify.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists(): p.error('Output exists; choose a new report path')
    if a.command=='verify-index':
        report=verify_index(read_json(a.report),read_json(a.response))
        code=0 if report['indexer_verified'] else 2
    elif a.command=='session':
        capture=read_json(a.capture/'session.json')
        result=manager_alerts(a.manager,{'session_id':capture['session_id']})
        alerts=result['alerts']
        from collections import Counter
        report={'schema_version':'soc-wazuh-session-trace/0.1',**result,
                'session_id':capture['session_id'],'capture_closed':capture['closed'],
                'alert_rule_counts':dict(Counter(str(r.get('rule',{}).get('id')) for r in alerts)),
                'indexer_verified':False,'dashboard_rendering_verified':False,
                'indexer_query':index_query(session_id=capture['session_id'])}
        if a.operator:
            operator=read_json(a.operator)
            if operator['capture_session_id']!=capture['session_id']:
                raise ValueError('Operator/capture session mismatch')
            report['scenario']=operator['scenario']
            report['expected_rule_ids']=operator['expected_rule_ids']
            report['missing_expected_rule_ids']=[i for i in operator['expected_rule_ids']
                                                if i not in report['alert_rule_counts']]
            report['expected_absent_rule_ids']=operator.get('expected_absent_rule_ids',[])
            report['unexpected_rule_ids']=[i for i in report['expected_absent_rule_ids']
                                           if i in report['alert_rule_counts']]
            report['recon_observation_coverage']=recon_coverage(a.capture,operator)
            if 'ssh' in operator['scenario'] or operator['scenario']=='chain':
                report['raw_auth_outcomes']=auth_outcomes(a.capture,operator)
            report['expectations_are_not_training_labels']=True
            report['negative_result_coverage_complete']=bool(capture['closed'] and not result['tail_limited'])
            if report['expected_absent_rule_ids']:
                report['negative_result_coverage_complete'] &= report['recon_observation_coverage']['coverage_sufficient']
        code=0 if alerts else 2
    else:
        started=time.monotonic()
        event=make_event('connection_test',['connection_test',time.time_ns()],
            activity='Explicit synthetic bridge connectivity probe',test_event=True)
        report={'schema_version':'soc-wazuh-delivery-probe/0.1','event_id':event['event_id'],
                'appended_to_manager':False,'manager_alert_verified':False,
                'indexer_verified':False,'dashboard_rendering_verified':False,
                'dashboard_query':'data.event_id: "'+event['event_id']+'"',
                'indexer_query':index_query(event_id=event['event_id'])}
        pub=Publisher(a.outbox,a.manager)
        try:
            pub.enqueue(event); pub.flush(limit=10,force=True)
            # An old outbox can contain earlier pending events; do not infer
            # append of this probe merely because some other event was sent.
            delivered=pub.db.execute('SELECT delivered FROM delivery WHERE id=?',(event['event_id'],)).fetchone()
            if not delivered or not delivered[0]:
                report['error']=pub.last_error or 'Probe still queued; retry after delivery repair'
            else:
                report['appended_to_manager']=True
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    result=manager_alerts(a.manager,{'event_id':event['event_id']})
                    found=[r for r in result['alerts'] if str(r.get('rule',{}).get('id'))=='119201']
                    report.update(manager_tail_limited=result.get('tail_limited',False))
                    if found:
                        report.update(manager_alert_verified=True,manager_alert=found[0],
                                      observed_delivery_seconds=round(time.monotonic()-started,3))
                        break
                    time.sleep(1)
        finally:
            pub.close()
        code=0 if report['manager_alert_verified'] else 2
    write_json(a.output,report)
    if a.command=='session':
        print(json.dumps({k:v for k,v in report.items() if k!='alerts'},indent=2))
    else: print(json.dumps(report,indent=2))
    print('REPORT:',a.output)
    return code


if __name__=='__main__':
    raise SystemExit(main())
