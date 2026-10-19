"""Readable activity summaries plus durable evidence references for Wazuh."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from wazuh_bridge import make_event


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
    def __init__(self, folder, publisher=None, clock=time.monotonic):
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
        # Protocol metadata is in JSONL; alerts appear immediately in the console.
        if kind == 'alert':
            print('[SENSOR]', safe(row['event_time']), safe(row['source_ip']), '->', safe(row['target_ip']),
                  'port='+safe(row['target_port']), safe(observed), flush=True)

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
        # One compact console line per host/source/account/outcome per polling cycle.
        fresh = [e for eid, e in engine.events.items() if eid not in self.seen_events]
        groups = Counter()
        rows = []
        for e in fresh:
            self.seen_events.add(e['event_id'])
            if e['kind'].startswith('auth.'):
                groups[(e['kind'], e['target_host'], e['source_ip'], e['username'])] += 1
                rows.append({'activity_type': e['kind'], **e})
        append(self.path, rows)
        for (kind, host, src, user), count in groups.items():
            print('[AUTH]', safe(src), '->', safe(host), 'user='+safe(user), safe(kind), 'count='+str(count), flush=True)
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
                stages=' -> '.join(stages), evidence_ids=evidence[:32], evidence_count=len(evidence),
                evidence_file=str(engine.snapshot), confirmed_compromise=False,
                activity=case['explanation'])
            if case['status'] == 'possible_web_sqli':
                row.update(detection_method='http_rule_evidence',
                    sample_request_target=case.get('sample_request_target'),
                    evidence_providers=case.get('evidence_providers', []),
                    exploitation_success_proven=False)
            append(self.path, [row])
            print('[CORRELATION]', safe(case['source_ip']), '->', safe(case['target_host']),
                  safe(case['status']), safe(row['stages']), flush=True)
            if self.publisher:
                self.publisher.enqueue(row)

    def flush(self, force=False):
        self.flush_raw()
        if not force and self.clock()-self.last_flush < 10:
            return
        self.last_flush = self.clock()
        rows = []
        for g in self.groups.values():
            self.sequence += 1
            row = make_event('model_summary', [self.folder.name, 'summary', self.sequence], **g,
                activity='Flow model prediction; uncalibrated score, not verified attack',
                softmax_scores_calibrated=False, evidence_file=str(self.folder/'ai-predictions.jsonl'))
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
                if row['decision'] == 'possible_attack':
                    self.publisher.enqueue(row)
        self.groups.clear()
