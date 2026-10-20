"""Readable activity summaries plus durable evidence references for Wazuh."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from wazuh_bridge import make_event
from lab_risk import assessment, case_assessment


def append(path, rows):
    import os
    if not rows:
        return
    with Path(path).open('ab') as stream:
        for row in rows:
            stream.write((json.dumps(row, ensure_ascii=False, allow_nan=False)+'\n').encode())
        stream.flush(); os.fsync(stream.fileno())


def safe(value):
    # Log data must not inject terminal escape codes or new lines.
    return ''.join(c if c.isprintable() else '?' for c in str(value))[:180]


class Activities:
    def __init__(self, folder, publisher=None, clock=time.monotonic,
                 publish_observations=False, summary_seconds=10):
        self.folder = Path(folder)
        self.publisher = publisher
        self.path = self.folder/'live-activities.jsonl'
        self.path.touch(exist_ok=False)
        self.clock = clock
        self.last_flush = clock()
        self.groups = {}
        self.sequence = 0
        self.seen_events = set()
        self.case_revisions = {}
        self.raw_rows = []
        self.publish_observations = publish_observations
        self.summary_seconds = summary_seconds
        self.sensor_counters = {}

    def emit(self, row):
        row['session_id'] = self.folder.name
        append(self.path, [row])
        if self.publisher:
            self.publisher.enqueue(row)

    def flush_raw(self):
        append(self.path, self.raw_rows)
        self.raw_rows.clear()

    def prediction(self, event, prediction):
        src, dst = event['src_ip'], event['dest_ip']
        label = prediction.get('predicted_label', prediction.get('reason', 'unknown'))
        # Group only within a sensor/source and outcome; never merge different targets.
        key = (event.get('_soc_source_file', ''), src, dst, event.get('proto'),
               event.get('app_proto', 'unknown'), label, prediction['decision'])
        if key not in self.groups:
            self.groups[key] = {'source_ip': src, 'target_ip': dst,
                'protocol': event.get('proto', 'unknown'), 'application': event.get('app_proto', 'unknown'),
                'predicted_label': label, 'decision': prediction['decision'], 'flow_count': 0,
                'destination_port_min': event.get('dest_port'), 'destination_port_max': event.get('dest_port'),
                'score_max': None, 'source_file': event.get('_soc_source_file', 'suricata-eve.jsonl'),
                'model_weights_sha256': prediction.get('model_weights_sha256', ''),
                'first_event_time': event.get('timestamp'), 'last_event_time': event.get('timestamp')}
        g = self.groups[key]
        g['sensor_tcp_gap_flow_count'] = g.get('sensor_tcp_gap_flow_count', 0) + int(
            bool(event.get('tcp', {}).get('ts_gap') or event.get('tcp', {}).get('tc_gap')))
        g['flow_count'] += 1
        g['last_event_time'] = event.get('timestamp')
        port = event.get('dest_port')
        if port is not None:
            g['destination_port_min'] = min(p for p in (port, g['destination_port_min']) if p is not None)
            g['destination_port_max'] = max(p for p in (port, g['destination_port_max']) if p is not None)
        score = prediction.get('attack_score')
        if score is not None:
            g['score_max'] = max(score, g['score_max'] if g['score_max'] is not None else score)
        # Bound groups even during high-cardinality traffic.
        if len(self.groups) >= 512:
            self.flush(force=True)

    def raw_event(self, event, source_file, source_container):
        kind = event.get('event_type')
        if kind == 'stats':
            stats = event.get('stats', {})
            def counter(*keys):
                value=stats
                for key in keys:
                    if not isinstance(value,dict): raise ValueError('Sensor stats must contain objects')
                    value=value.get(key,{} if key!=keys[-1] else 0)
                return value
            counters = {'ipv4_truncated_packets':counter('decoder','event','ipv4','trunc_pkt'),
                        'tcp_reassembly_gaps':counter('tcp','reassembly_gap'),
                        'kernel_drops':counter('capture','kernel_drops')}
            if any(type(v) is not int or v < 0 for v in counters.values()):
                raise ValueError('Invalid sensor quality counters')
            key = (source_file, source_container)
            previous = self.sensor_counters.get(key)
            self.sensor_counters[key] = counters
            if previous is not None:
                delta = {k:max(0,v-previous[k]) for k,v in counters.items()}
                if any(delta.values()):
                    self.emit(make_event('telemetry_warning', [self.folder.name, key, event.get('timestamp'), counters],
                        **assessment(20, 'Sensor counters increased; inspect capture quality', 'telemetry_warning'),
                        source_container=source_container, source_file=source_file,
                        event_time=event.get('timestamp'), **delta))
            return
        if kind not in ('alert', 'http', 'dns', 'tls', 'ssh', 'fileinfo', 'anomaly'):
            return
        # Store only observed application metadata; never claim decrypted content.
        details = {}
        observed = kind
        if kind == 'alert':
            if not isinstance(event.get('alert'), dict):
                raise ValueError('Suricata alert metadata must be an object')
            details = {k: event.get('alert', {}).get(k) for k in ('signature_id', 'signature', 'severity', 'category')}
            observed = details.get('signature') or 'Suricata alert'
        elif kind == 'http':
            if not isinstance(event.get('http'), dict):
                raise ValueError('HTTP metadata must be an object')
            details = {k: event.get('http', {}).get(k) for k in ('hostname', 'url', 'http_method', 'status')}
        elif kind == 'dns':
            if not isinstance(event.get('dns'), dict):
                raise ValueError('DNS metadata must be an object')
            details = {k: event.get('dns', {}).get(k) for k in ('type', 'rrname', 'rrtype', 'rcode')}
        elif kind == 'tls':
            if not isinstance(event.get('tls'), dict):
                raise ValueError('TLS metadata must be an object')
            details = {k: event.get('tls', {}).get(k) for k in ('sni', 'version', 'subject', 'issuerdn')}
        elif kind == 'ssh':
            details = {'note': 'SSH metadata observed; encrypted commands unavailable'}
        row = {'activity_type': 'observed_'+kind, 'event_time': event.get('timestamp'),
               'source_ip': event.get('src_ip'), 'source_port': event.get('src_port'),
               'target_ip': event.get('dest_ip'), 'target_port': event.get('dest_port'),
               'source_file': source_file, 'source_container': source_container,
               'flow_id': str(event.get('flow_id', '')), 'details': details}
        self.raw_rows.append(row)
        if len(self.raw_rows) >= 128:
            self.flush_raw()
        # These are collection observations, not independent attack signatures.
        # Keep raw evidence; only the distinct-port correlator creates a case.
        if kind=='alert' and str(details.get('signature_id')) in ('9900001','9900003'):
            return
        # Protocol metadata is in JSONL; alerts appear immediately in the console.
        if kind == 'alert':
            print('[SENSOR]', safe(row['event_time']), safe(row['source_ip']), '->', safe(row['target_ip']),
                  'port='+safe(row['target_port']), safe(observed), flush=True)
            self.flush_raw()
            self.emit(make_event('sensor_alert', [self.folder.name, source_file, source_container,
                event.get('timestamp'), str(event.get('flow_id')), event.get('tx_id'),
                event.get('src_ip'), event.get('src_port'), event.get('dest_ip'),
                event.get('dest_port'), details],
                **assessment(50, 'Suricata signature matched; severity is independent of model score'),
                **{k:v for k,v in row.items() if k != 'details'},
                signature_id=details['signature_id'], signature=details['signature'],
                signature_severity=details['severity']))

    def correlation(self, engine):
        http_groups = {}
        for e in getattr(engine, 'web_activity', []):
            key = (e['source_ip'], e['target_ip'], e['http_method'], e['http_status'])
            if key not in http_groups:
                http_groups[key] = [0, e['url_path'], set()]
            http_groups[key][0] += 1
            http_groups[key][2].update(e['sql_indicators'])
        for (src, dst, method, status), (count, path, indicators) in http_groups.items():
            print('[HTTP]', safe(src), '->', safe(dst), safe(method), safe(path),
                  'status='+str(status), 'requests='+str(count),
                  'indicators='+safe(','.join(sorted(indicators)) or 'none'), flush=True)
            if self.publish_observations:
                self.sequence += 1
                self.emit(make_event('http_observation', [self.folder.name, 'http', self.sequence],
                    **assessment(0, 'Observed HTTP transactions; status alone does not establish safety', 'observation'),
                    source_ip=src, target_ip=dst, http_method=method, http_status=status,
                    request_count=count, sample_request_target=path))
        # One compact console line per host/source/account/outcome per polling cycle.
        fresh = [e for eid, e in engine.events.items() if eid not in self.seen_events]
        groups = Counter()
        rows = []
        for e in fresh:
            self.seen_events.add(e['event_id'])
            if e['kind'].startswith('auth.'):
                groups[(e['kind'], e['target_host'], e['source_ip'], e['username'])] += 1
                rows.append({'activity_type': e['kind'], **e})
                if self.publish_observations:
                    self.emit(make_event('auth_observation', [self.folder.name, 'auth', e['event_id']],
                        **assessment(0 if e['kind']=='auth.success' else 15,
                            'Single authentication outcome; not an attack-chain verdict', 'observation'),
                        event_time=e['event_time'], activity_type=e['kind'],
                        source_ip=e['source_ip'], source_port=e['source_port'],
                        target_ip=e['target_ip'], target_host=e['target_host'],
                        username=e['username'], evidence_ids=[e['event_id']] ))
        append(self.path, rows)
        for (kind, host, src, user), count in groups.items():
            print('[AUTH]', safe(src), '->', safe(host), 'user='+safe(user), safe(kind), 'count='+str(count), flush=True)
        self.publish_chains(engine)
        for case in engine.cases:
            # Publish on stage/status transitions, not once per failed password.
            stages = [s['name'] for s in case['stages']]
            revision = (case['status'], tuple(stages))
            if self.case_revisions.get(case['case_id']) == revision:
                continue
            self.case_revisions[case['case_id']] = revision
            evidence = [eid for stage in case['stages'] for eid in stage['evidence_ids']]
            row = make_event('correlation', [self.folder.name, case['case_id'], revision],
                case_id=case['case_id'], case_status=case['status'], source_ip=case['source_ip'],
                target_ip=case['target_ip'], target_host=case['target_host'], username=case['username'],
                stages=' -> '.join(stages), evidence_ids=evidence[:4], evidence_count=len(evidence),
                evidence_file=str(engine.snapshot), confirmed_compromise=False,
                activity=case['explanation'])
            details = case_assessment(case)
            # Wazuh's JSON decoder does not support arrays of objects. Preserve
            # the graph as a JSON string; full structured stages stay local.
            graph = details.pop('attack_chain_graph')
            for node in graph['nodes']:
                if len(graph['nodes']) > 3:
                    # Keep a five-stage message below the Wazuh log limit.
                    # Full node/evidence links remain in correlation-cases.json.
                    node.pop('evidence_ids')
                else:
                    node['evidence_ids'] = node['evidence_ids'][:2]
            row.update(details, attack_chain_json=json.dumps(graph, separators=(',', ':')),
                       graph_evidence_ids_omitted=len(graph['nodes']) > 3,
                       event_time=case['last_seen'], session_id=self.folder.name)
            if case['status'] == 'possible_web_sqli':
                row.update(detection_method='http_rule_evidence',
                    sample_request_target=case.get('sample_request_target'),
                    evidence_providers=case.get('evidence_providers', []),
                    exploitation_success_proven=False)
            recon=next((s for s in case['stages'] if s['name']=='possible_recon'),None)
            if recon:
                row.update(recon_detection_method=recon['detection_method'],
                    distinct_destination_ports=recon['distinct_destination_ports'],
                    destination_port_sample=recon['destination_port_sample'],
                    port_threshold=recon['port_threshold'],
                    port_window_seconds=recon['port_window_seconds'])
            append(self.path, [row])
            print('[CORRELATION]', safe(case['source_ip']), '->', safe(case['target_host']),
                  safe(case['status']), safe(row['stages']), flush=True)
            if self.publisher:
                from wazuh_bridge import encoded
                if len(encoded(row).encode('utf-8')) > 6000:
                    raise RuntimeError('Correlation event exceeds 6000 bytes; local case/evidence preserved. Shorten metadata before Wazuh delivery.')
                self.publisher.enqueue(row)

    def publish_chains(self, engine):
        from lab_campaign import wire_events
        from lab_correlation import digest
        from wazuh_bridge import encoded
        if not hasattr(self, 'chain_revisions'):
            self.chain_revisions = {}
            self.chain_previous = {}
            self.chain_branch_cases = {}
        present = {c['chain_id']:c for c in getattr(engine,'chains',[])}
        for chain in present.values():
            revision=digest(chain)
            if self.chain_revisions.get(chain['chain_id'])==revision: continue
            docs=wire_events(chain,self.folder.name,engine.snapshot)
            if any(len(encoded(d).encode('utf-8'))>6000 for d in docs):
                raise RuntimeError('Chain document exceeds 6000 bytes; full local evidence preserved.')
            append(self.path, docs)
            if self.publisher:
                for doc in docs:self.publisher.enqueue(doc)
            self.chain_revisions[chain['chain_id']]=revision
            self.chain_previous[chain['chain_id']]=docs[-1]
            self.chain_branch_cases[chain['chain_id']]={b['case_id'] for b in chain['branches']}
            print('[CHAIN]',chain['chain_id'], 'stages='+str(len(chain['stages'])),
                  'risk='+str(chain['risk_score']), ';'.join(chain['categories']),flush=True)
        # Delayed evidence can attach a former standalone case to a scan root.
        # Publish a latest tombstone; readers must filter active AFTER latest.
        for chain_id in set(self.chain_previous)-set(present):
            old=self.chain_previous.pop(chain_id)
            self.chain_revisions.pop(chain_id,None)
            old_branches=self.chain_branch_cases.pop(chain_id,set())
            replacements=[c['chain_id'] for c in present.values() if
                old_branches.intersection(b['case_id'] for b in c['branches']) and
                (c['source_ip'],c['target_ip'],c['target_host'])==
                (old['source_ip'],old['target_ip'],old['target_host'])]
            tombstone={**old, 'chain_active':False, 'superseded_by':replacements,
                       'event_id':digest([old['event_id'],'superseded',replacements])}
            # Keep source sort monotonic, including late scan delivery.
            from lab_correlation import instant, stamp
            from datetime import timedelta
            tombstone['event_time']=stamp(instant(old['event_time'])+timedelta(microseconds=1))
            append(self.path,[tombstone])
            if self.publisher:self.publisher.enqueue(tombstone)

    def flush(self, force=False):
        self.flush_raw()
        if not force and self.clock()-self.last_flush < self.summary_seconds:
            return
        self.last_flush = self.clock()
        rows = []
        for g in self.groups.values():
            self.sequence += 1
            row = make_event('model_summary', [self.folder.name, 'summary', self.sequence], **g,
                activity='Flow model prediction; uncalibrated score, not verified attack',
                softmax_scores_calibrated=False, evidence_file=str(self.folder/'ai-predictions.jsonl'))
            row.update(assessment(35 if g['decision']=='possible_attack' else 0,
                'MLP operating decision; score_max is an uncalibrated model score',
                'unverified_detection' if g['decision']=='possible_attack' else 'observation'),
                session_id=self.folder.name)
            rows.append(row)
            print('[AI]', safe(g['source_ip']), '->', safe(g['target_ip']),
                  str(g['protocol'])+'/'+str(g['application']),
                  'ports='+str(g['destination_port_min'])+'..'+str(g['destination_port_max']),
                  'flows='+str(g['flow_count']), 'prediction='+safe(g['predicted_label']),
                  'decision='+safe(g['decision']), 'score_max='+str(g['score_max']), flush=True)
            if g['predicted_label']=='BENIGN' and g['decision']=='possible_attack':
                print('[MODEL NOTE] BENIGN is the largest individual class, but the sum of other classes exceeds the alert threshold. This is not verified attack evidence.', flush=True)
        # Persist local evidence before attempting enqueue/delivery.
        append(self.path, rows)
        if self.publisher:
            for row in rows:
                if row['decision'] == 'possible_attack' or self.publish_observations:
                    self.publisher.enqueue(row)
        self.groups.clear()
