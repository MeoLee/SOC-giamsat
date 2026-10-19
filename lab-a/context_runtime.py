"""Read the durable live spool into a separate, local-only context journal."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from lab_context import ContextDetector
from lab_correlation import append
from soc_ai.common import write_json


class ContextJournal:
    def __init__(self, directory, sources, config=None):
        self.directory = Path(directory)
        self.detector = ContextDetector(config)
        self.sources = [s for s in sources if
                        s['kind'] == 'eve' and self.detector.config['port_enabled'] or
                        s['kind'] == 'web' and self.detector.config['http_enabled']]
        self.offsets = {s['output']: 0 for s in self.sources}
        self.pending = {s['output']: b'' for s in self.sources}
        self.counts = Counter()
        self.signals = self.directory / 'context-signals.jsonl'
        self.errors = self.directory / 'context-errors.jsonl'
        self.status = self.directory / 'context-status.json'
        for path in (self.signals, self.errors, self.status):
            if path.exists():
                raise ValueError('Context output exists; choose a new capture session')
        self.signals.touch(); self.errors.touch()
        self.write_status('running')

    def consume(self):
        updates, errors, more = [], [], False
        for source in self.sources:
            name = source['output']; path = self.directory / name
            if path.stat().st_size < self.offsets[name]:
                raise RuntimeError('Context raw input truncated: ' + name)
            with path.open('rb') as stream:
                stream.seek(self.offsets[name]); block = stream.read(4 * 1024**2)
            cursor = self.offsets[name] - len(self.pending[name])
            self.offsets[name] += len(block)
            combined = self.pending[name] + block; end = combined.rfind(b'\n') + 1
            self.pending[name] = combined[end:]
            if len(self.pending[name]) > 16 * 1024**2:
                raise RuntimeError('Context input line exceeds 16 MiB')
            for framed in combined[:end].splitlines(keepends=True):
                raw = framed.rstrip(b'\r\n')
                ref = {'source_file': name, 'source_container': source['container'],
                       'source_path': source['path'], 'byte_offset': cursor,
                       'raw_sha256': hashlib.sha256(raw).hexdigest()}
                cursor += len(framed)
                if not raw.strip():
                    continue
                try:
                    rejection_keys = ('invalid_flow_records', 'invalid_http_records', 'late_records_rejected',
                                      'event_capacity_drops', 'stream_capacity_drops')
                    before = {key: self.detector.counts[key] for key in rejection_keys}
                    if source['kind'] == 'eve':
                        event = json.loads(raw)
                        if not isinstance(event, dict):
                            raise ValueError('EVE must be an object')
                        signals = self.detector.observe_flow(event, name, source['container'])
                    else:
                        from lab_web import apache_tsv
                        event = apache_tsv(raw)
                        event['_soc_source_file'] = name
                        event['_soc_source_container'] = source['container']
                        signals = self.detector.observe_http(event)
                    losses = {key: self.detector.counts[key] - before[key] for key in rejection_keys
                              if self.detector.counts[key] != before[key]}
                    if losses:
                        self.counts['rejected_context_records'] += 1
                        errors.append({**ref, 'error': 'Context rejected observation', 'loss_counts': losses})
                    updates.extend({**signal, 'producer': 'soc-context-shadow',
                                    'trigger_raw_ref': ref, 'publication_enabled': False}
                                   for signal in signals)
                except (ValueError, TypeError, KeyError, OverflowError) as exc:
                    self.counts['invalid_input_records'] += 1
                    errors.append({**ref, 'error': str(exc)})
            more = path.stat().st_size > self.offsets[name] or more
        if updates:
            append(self.signals, updates)
            self.counts['signal_updates'] += len(updates)
        if errors:
            append(self.errors, errors)
        return more

    def write_status(self, status):
        snapshot = self.detector.snapshot()
        pending = [name for name, tail in self.pending.items() if tail]
        incomplete = bool(snapshot['quality']['incomplete'] or pending or self.counts['invalid_input_records']
                          or status in ('degraded', 'failed', 'interrupted'))
        quality = {**snapshot['quality'], 'incomplete': incomplete,
                   'runtime_invalid_records': self.counts['invalid_input_records'],
                   'unfinished_source_lines': pending}
        report = {**snapshot, 'quality': quality, 'runtime_status': status,
                  'complete': status == 'completed' and not incomplete,
                  'runtime_counts': dict(self.counts), 'unfinished_source_lines': pending,
                  'publication_enabled': False, 'model_predictions_modified': False,
                  'sources': self.sources, 'note': 'Shadow only. Trigger references point into durable host raw logs; replay recovers earlier evidence IDs.'}
        write_json(self.status, report)
        return report
