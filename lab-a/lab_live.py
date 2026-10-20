"""Observe live Docker lab flows with the existing exported CPU model.

No packet blocking, training, configuration changes, or inferred ground-truth
labels. Raw auth/EVE/Wazuh files are captured by the existing collector.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import signal
import sys
import time

from soc_live_collector import Collector


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def append_records(path, records):
    import os
    with Path(path).open('ab') as stream:
        for record in records:
            stream.write((json.dumps(record, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8'))
        stream.flush()
        os.fsync(stream.fileno())


class FlowObserver:
    def __init__(self, directory, predictor, endpoints=None):
        self.directory = Path(directory)
        self.predictor = predictor
        self.endpoints = set(endpoints) if endpoints else None
        self.position = 0
        self.pending = b''
        self.counts = Counter()
        self.seen = set()
        self.source_positions = {}
        self.activities = None
        self.model_path = str(predictor.directory)
        self.weights_hash = predictor.metadata['weights_sha256']
        self.predictions = self.directory / 'ai-predictions.jsonl'
        self.errors = self.directory / 'ai-errors.jsonl'
        self.inputs = self.directory / 'ai-input-flows.jsonl'
        for path in (self.predictions, self.errors, self.inputs):
            if path.exists():
                raise ValueError('Live output exists; start a new collector session')
            path.touch()

    def process_lines(self, lines, source_file='suricata-eve.jsonl', source_container='ubuntu-endpoint'):
        from soc_ai.flow import normalize
        batch = []
        for raw in lines:
            if not raw.strip():
                continue
            key = hashlib.sha256(raw).hexdigest()
            try:
                event = json.loads(raw)
                if not isinstance(event, dict):
                    raise ValueError('Event must be a JSON object')
                if self.activities:
                    self.activities.raw_event(event, source_file, source_container)
                if event.get('event_type') != 'flow':
                    self.counts['ignored_non_flow'] += 1
                    continue
                if self.endpoints and {event.get('src_ip'), event.get('dest_ip')} != self.endpoints:
                    self.counts['other_endpoints'] += 1
                    continue
                flow = normalize(event)
                # Stable logical observation identity; independent of JSON order,
                # flow_id and time of final log emission. Counts distinguish
                # differing observations; this is not a training deduplicator.
                identity = {k: flow[k] for k in (
                    'src_ip', 'src_port', 'dest_ip', 'dest_port', 'protocol',
                    'start_time', 'end_time', 'pkts_toserver', 'pkts_toclient',
                    'bytes_toserver', 'bytes_toclient', 'app_protocol',
                    'flow_state', 'flow_reason')}
                identity['source_file'] = source_file
                key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                if key in self.seen:
                    self.counts['duplicate_observation'] += 1
                    continue
                event['record_id'] = 'live-flow:' + key
                event['_soc_source_file'] = source_file
                event['_soc_source_container'] = source_container
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                self.counts['invalid_flow_or_json'] += 1
                append_records(self.errors, [{'schema_version': 'soc-live-error/0.1',
                    'collected_at': now(), 'raw_sha256': key, 'error': str(exc)}])
                continue
            self.seen.add(key)
            batch.append(event)
            if len(batch) == 128:
                self.predict(batch)
                batch = []
        if batch:
            self.predict(batch)

    def predict(self, batch):
        # Critical prediction/write errors stop the bridge; never silently skip.
        results = self.predictor.predict(batch)
        if len(results) != len(batch):
            raise RuntimeError('Predictor returned a different record count')
        outputs = []
        for event, prediction in zip(batch, results):
            if prediction['record_id'] != event['record_id']:
                raise RuntimeError('Prediction/input identity mismatch')
            self.counts[prediction['decision']] += 1
            if prediction.get('predicted_label'):
                self.counts['label:' + prediction['predicted_label']] += 1
            outputs.append({**prediction, 'collected_at': now(),
                'model_directory': self.model_path, 'model_weights_sha256': self.weights_hash,
                'source_container': event.get('_soc_source_container', 'ubuntu-endpoint'),
                'source_file': event.get('_soc_source_file', 'suricata-eve.jsonl'), 'mode': 'observe',
                'prediction_is_not_ground_truth': True})
        append_records(self.inputs, batch)
        append_records(self.predictions, outputs)
        self.counts['written_predictions'] += len(outputs)
        if self.activities:
            for event, prediction in zip(batch, outputs):
                self.activities.prediction(event, prediction)

    def consume(self, source_file='suricata-eve.jsonl', source_container='ubuntu-endpoint'):
        path = self.directory / source_file
        position, pending = self.source_positions.get(source_file, (0, b''))
        if path.stat().st_size < position:
            raise RuntimeError('Captured host EVE file was truncated; stop and inspect')
        with path.open('rb') as stream:
            stream.seek(position)
            block = stream.read(4 * 1024 * 1024)
        position += len(block)
        combined = pending + block
        end = combined.rfind(b'\n') + 1
        pending = combined[end:]
        self.source_positions[source_file] = (position, pending)
        self.position, self.pending = position, pending
        if len(pending) > 16 * 1024 * 1024:
            raise RuntimeError('Host EVE line exceeds 16 MiB')
        self.process_lines(combined[:end].splitlines(), source_file, source_container)
        return bool(block) and path.stat().st_size > position


class LiveCollector(Collector):
    def __init__(self, args, predictor):
        super().__init__(args)
        self.publisher = None
        if getattr(args, 'publish_wazuh', False):
            from wazuh_bridge import Publisher
            self.publisher = Publisher(Path(args.output_dir)/'wazuh-outbox.sqlite', args.runtime['wazuh_manager'])
        self.observer = FlowObserver(self.folder, predictor,
                                    None if args.all_flows else args.endpoints)
        from live_activity import Activities
        self.activities = Activities(self.folder, self.publisher,
            publish_observations=getattr(args, 'publish_observations', False),
            summary_seconds=getattr(args, 'summary_seconds', 10))
        self.observer.activities = self.activities
        self.eve_sources = [(s['output'], s['container']) for s in getattr(args, 'runtime', {}).get('sources', []) if s['kind'] == 'eve'] or [('suricata-eve.jsonl', 'ubuntu-endpoint')]
        self.context = None
        context = dict(getattr(args, 'runtime', {}).get('context', {}))
        context_enabled = context.pop('enabled', False)
        if getattr(args, 'context', None) is not None:
            context_enabled = args.context
        if context_enabled:
            from context_runtime import ContextJournal
            self.context = ContextJournal(self.folder, args.runtime['sources'], context)
        self.correlator = None
        if not getattr(args, 'no_correlation', False):
            from lab_correlation import Correlator
            config_path = getattr(args, 'correlation_config', None)
            config = json.loads(Path(config_path).read_text(encoding='utf-8-sig')) if config_path else {}
            if hasattr(args, 'runtime'):
                config = {**config, **args.runtime['correlation']}
            self.correlator = Correlator(self.folder, self.folder, config)
        self.last_progress = 0
        self.last_heartbeat = time.monotonic()
        self.last_delivery_state = (False, None)
        self.live_started = now()
        self.write_status('running')

    def write_status(self, status, error=None):
        from soc_ai.common import write_json
        context_state = self.context.write_status(status) if self.context else None
        issues = {'invalid_prediction_inputs': self.observer.counts['invalid_flow_or_json'],
                  'unfinished_eve_sources': [name for name, (_, tail) in self.observer.source_positions.items() if tail],
                  'invalid_correlation_inputs': self.correlator.counts['invalid_source_records'] if self.correlator else 0,
                  'unfinished_correlation_sources': [name for name, tail in self.correlator.pending.items() if tail] if self.correlator else [],
                  'context_incomplete': context_state['quality']['incomplete'] if context_state else False,
                  'capture_incomplete': self.state['status'] != 'completed'}
        if status == 'completed' and any(issues.values()):
            status = 'degraded'
        if self.correlator:
            correlation_status = status
            if status == 'completed' and self.correlator.counts['invalid_source_records']:
                correlation_status = 'degraded'
            self.correlator.write(correlation_status, self.state['status'])
        report = {
            'version': 'soc-live-observer/0.4', 'status': status,
            'software_version': '0.4.5-research',
            'recon_policy': 'distinct_tcp_destination_ports/0.1',
            'complete': status == 'completed', 'mode': 'observe',
            'started_at': self.live_started, 'updated_at': now(),
            'model_directory': self.observer.model_path,
            'model_weights_sha256': self.observer.weights_hash,
            'feature_hash': self.observer.predictor.metadata['feature_hash'],
            'endpoints': sorted(self.observer.endpoints) if self.observer.endpoints else None,
            'counts': dict(self.observer.counts), 'capture_status': self.state['status'],
            'quality_issues': issues,
            'capture_gaps': self.state['gaps'], 'error': error,
            'correlation_implemented': self.correlator is not None,
            'correlation_case_count': len(self.correlator.cases) if self.correlator else 0,
            'context_shadow': {'enabled': self.context is not None,
                'signal_count': len(context_state['signals']) if context_state else 0,
                'quality': context_state['quality'] if context_state else None,
                'complete': context_state['complete'] if context_state else None,
                'runtime_counts': context_state['runtime_counts'] if context_state else None,
                'unfinished_source_lines': context_state['unfinished_source_lines'] if context_state else [],
                'publication_enabled': False, 'model_predictions_modified': False},
            'automatic_response': False,
            'sources': self.state['sources'],
            'wazuh_publication': {'enabled': self.publisher is not None,
                'observations_enabled': self.activities.publish_observations,
                'pending': self.publisher.pending if self.publisher else 0,
                'last_error': self.publisher.last_error if self.publisher else None,
                'ack_means': 'appended to manager log; indexing must be verified separately'},
            'note': 'Completed-flow inference; emission can follow connection closure by a sensor timeout. '
                    'Raw event logs are preserved. Predictions are not training labels.'}
        write_json(self.folder / 'ai-session.json', report)
        return report

    def poll(self):
        more = super().poll()
        for source_file, container in self.eve_sources:
            more = self.observer.consume(source_file, container) or more
        if self.correlator:
            more = self.correlator.consume() or more
            self.activities.correlation(self.correlator)
        if self.context:
            more = self.context.consume() or more
        self.activities.flush()
        if self.publisher:
            self.publisher.flush()
            delivery_state = (bool(self.publisher.pending), self.publisher.last_error)
            if delivery_state != self.last_delivery_state:
                if self.publisher.last_error:
                    print('[WAZUH ERROR]', self.publisher.last_error,
                          'pending=', self.publisher.pending, flush=True)
                elif self.publisher.pending:
                    print('[WAZUH PENDING]', self.publisher.pending, 'summaries awaiting delivery', flush=True)
                else:
                    print('[WAZUH RECOVERED] pending=0; queued summaries appended to manager log', flush=True)
                self.last_delivery_state = delivery_state
        if time.monotonic() - self.last_progress >= 10:
            self.last_progress = time.monotonic()
            self.write_status('running')
        heartbeat = getattr(self.args, 'heartbeat_seconds', 0)
        if heartbeat and time.monotonic() - self.last_heartbeat >= heartbeat:
            self.last_heartbeat = time.monotonic()
            print('LIVE: so du doan=', self.observer.counts['written_predictions'],
                  'nhan=', {k[6:]: v for k, v in self.observer.counts.items() if k.startswith('label:')},
                  'correlation_cases=', len(self.correlator.cases) if self.correlator else 0,
                  'loi nguon=', [s['name'] for s in self.state['sources'] if s['last_error']], flush=True)
            if self.publisher:
                print('WAZUH: pending=', self.publisher.pending, 'last_error=', self.publisher.last_error, flush=True)
        return more


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model', type=Path, required=True)
    p.add_argument('--output-dir', default=r'E:\SOC-Lab\AI\live')
    p.add_argument('--interval', type=float, default=3)
    p.add_argument('--grace', type=float, default=10)
    p.add_argument('--heartbeat-seconds', type=float, default=0,
                   help='Optional periodic counters; default 0 prints events and state changes only')
    scope = p.add_mutually_exclusive_group()
    scope.add_argument('--endpoints', nargs=2, default=None, help='Optional explicit pair filter. Default: no IP filter.')
    scope.add_argument('--all-flows', action='store_true', help='Compatibility flag; all flows is already the default.')
    p.add_argument('--config', type=Path, help='Sources, asset identities and correlation configuration')
    p.add_argument('--publish-wazuh', action='store_true', help='Send summaries after setup_wazuh.py has installed rules')
    p.add_argument('--publish-observations', action='store_true',
                   help='Also send normal/auth/HTTP observations as informational Wazuh events')
    p.add_argument('--summary-seconds', type=float, default=10,
                   help='Model summary interval; completed-flow availability still depends on sensor timeout')
    p.add_argument('--no-correlation', action='store_true')
    context = p.add_mutually_exclusive_group()
    context.add_argument('--context', dest='context', action='store_true', default=None,
                         help='Enable local shadow context indicators; does not alter model predictions')
    context.add_argument('--no-context', dest='context', action='store_false',
                         help='Disable the optional local context branch')
    p.add_argument('--correlation-config', type=Path)
    return p


def main():
    p = parser()
    a = p.parse_args()
    from live_ui import show_header, show_runtime, show_session, show_footer
    show_header()
    if a.interval < .1 or a.grace < 0 or a.heartbeat_seconds < 0:
        p.error('interval >= 0.1, grace >= 0 and heartbeat-seconds >= 0 required')
    import math
    if not math.isfinite(a.summary_seconds) or a.summary_seconds < .1:
        p.error('summary-seconds must be finite and >= 0.1')
    if a.publish_observations and not a.publish_wazuh:
        p.error('--publish-observations requires --publish-wazuh')
    a.resume = None
    a.from_start = False
    a.docker_command = 'docker'
    a.scenario_id = 'live-observe'
    collector = None
    try:
        from live_config import load_config
        a.runtime = load_config(a.config)
        a.sources = [(s['kind']+str(i), s['container'], s['path'], s['output']) for i, s in enumerate(a.runtime['sources'])]
        # Same normalizer/features/exported weights as offline prediction.
        from soc_ai.predict import Predictor
        predictor = Predictor(a.model.resolve(), 'cpu')
        print('MODEL_VERIFY_OK max_probability_difference=', predictor.verify(), flush=True)
        # Fail early if the sensor is not currently running; no blind restart.
        import subprocess
        if a.publish_wazuh:
            check = subprocess.run(['docker', 'exec', a.runtime['wazuh_manager'], 'cat',
                '/var/ossec/logs/soc-ai/bridge-ready.json'], capture_output=True, timeout=15)
            if check.returncode:
                raise RuntimeError('Wazuh bridge not installed. Run setup_wazuh.py first. '+check.stderr.decode(errors='replace'))
            ready = json.loads(check.stdout)
            if ready.get('version') != 'soc-ai-wazuh/0.1':
                raise ValueError('Unsupported Wazuh bridge installation')
            if not set(range(119201, 119212)).issubset(ready.get('rule_ids', [])):
                raise ValueError('Update bridge rules with setup_wazuh.py before publishing this release')
        sensors = {s['container'] for s in a.runtime['sources'] if s['kind'] == 'eve'}
        for sensor in sensors:
            check = subprocess.run(['docker', 'exec', sensor, 'pgrep', '-f',
                r'^([^[:space:]]*/)?suricata([[:space:]]|$)'], capture_output=True, timeout=15)
            if check.returncode:
                raise RuntimeError('Suricata not found in '+sensor+': '+check.stderr.decode(errors='replace'))
            from lab_recon import SENSOR_RULE_CHECK
            recon_check=subprocess.run(['docker','exec',sensor,'python3','-c',SENSOR_RULE_CHECK],
                                       capture_output=True,timeout=15)
            if recon_check.returncode:
                raise RuntimeError('Run setup_recon.py before Live: '+recon_check.stderr.decode(errors='replace')[:1000])
        show_runtime(a)
        collector = LiveCollector(a, predictor)
        show_session(collector.folder)
        result = collector.run()
        for source_file, container in collector.eve_sources:
            while collector.observer.consume(source_file, container):
                pass
        if collector.correlator:
            while collector.correlator.consume():
                pass
            collector.activities.correlation(collector.correlator)
        if collector.context:
            while collector.context.consume():
                pass
        collector.activities.flush(force=True)
        if collector.publisher:
            collector.publisher.flush()
        final_status = collector.write_status('completed' if result == 0 else 'degraded')
        print('AI_OUTPUT:', collector.observer.predictions, flush=True)
        if collector.correlator:
            print('CORRELATION_OUTPUT:', collector.correlator.snapshot, flush=True)
        print('ACTIVITY_OUTPUT:', collector.activities.path, flush=True)
        if collector.context:
            print('CONTEXT_SHADOW_OUTPUT:', collector.context.status, flush=True)
        if collector.publisher:
            print('WAZUH_PENDING:', collector.publisher.pending,
                  'LAST_ERROR:', collector.publisher.last_error, flush=True)
        show_footer()
        return 2 if result == 0 and not final_status['complete'] else result
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print('ERROR:', exc, file=sys.stderr, flush=True)
        if collector:
            collector.state['status'] = 'interrupted'
            collector.state['error'] = str(exc)
            try:
                collector.save()
                collector.write_status('failed', str(exc))
            except OSError as secondary:
                print('ERROR saving status:', secondary, file=sys.stderr)
        return 1
    finally:
        if collector and collector.lock_file:
            collector.lock_file.close()
        if collector and collector.publisher:
            collector.publisher.close()


if __name__ == '__main__':
    raise SystemExit(main())
