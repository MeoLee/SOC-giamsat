"""Bounded, event-time context indicators; these are shadow evidence, not labels.

Replay and live callers use exactly the same ContextDetector. No model, network,
publisher, wall clock, or learned state is involved. See docs/CONTEXT-VI.md.
"""
from bisect import insort
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json


DEFAULTS = {
    'port_enabled': True, 'port_window_seconds': 60, 'port_threshold': 20,
    'http_enabled': False, 'http_window_seconds': 60, 'http_threshold': 120,
    'allowed_lateness_seconds': 10, 'max_groups': 1000, 'max_events': 20000,
    'max_signals': 1000, 'max_evidence_ids': 16,
}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def validated_config(config=None):
    """Reject misspelled/unsupported settings and boolean-as-integer values."""
    if config is None:
        config = {}
    if not isinstance(config, dict) or set(config) - set(DEFAULTS):
        raise ValueError('Invalid context configuration or unknown setting')
    result = {**DEFAULTS, **config}
    for key in ('port_enabled', 'http_enabled'):
        if type(result[key]) is not bool:
            raise ValueError('Context ' + key + ' must be boolean')
    limits = {
        'port_window_seconds': (1, 3600), 'http_window_seconds': (1, 3600),
        'port_threshold': (2, 65536), 'http_threshold': (1, 1000000),
        'allowed_lateness_seconds': (0, 86400), 'max_groups': (1, 100000),
        'max_events': (1, 1000000), 'max_signals': (1, 100000),
        'max_evidence_ids': (1, 128),
    }
    for key, (low, high) in limits.items():
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError('Invalid context ' + key)
    return result


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _text(value, field, maximum=512):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 for c in value)):
        raise ValueError('Invalid context ' + field)
    return value


def _ip(value):
    # Scoped IPv6 needs an explicit interface identity; do not silently join it.
    if not isinstance(value, str) or '%' in value:
        raise ValueError('Invalid context IP address')
    return str(ipaddress.ip_address(value))


def _instant(value):
    _text(value, 'timestamp', 128)
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError('Context timestamp requires timezone')
    delta = result.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def _stamp(microseconds):
    return (_EPOCH + timedelta(microseconds=microseconds)).isoformat(
        timespec='microseconds').replace('+00:00', 'Z')


class ContextDetector:
    """Finite UTC windows, isolated sensor watermarks and bounded dedup state.

    observe_* returns newly created or updated signals, with stable signal_id and
    revision=accepted event count. A caller storing updates should upsert that ID.
    snapshot returns bounded signal history, state sizes and explicit data losses.
    """

    def __init__(self, config=None):
        self.config = validated_config(config)
        self.counts = Counter()
        self._groups = {}
        self._streams = {}
        self._signals = {}
        self._event_count = 0

    def observe_flow(self, event, source_file, source_container):
        """Observe a completed EVE flow using flow.end as event time.

        TCP only. This counts distinct destination ports, not SYN packets, packet
        counts, MLP decisions, or repeated connections to a single service.
        """
        self.counts['flow_records_received'] += 1
        try:
            if not isinstance(event, dict):
                raise ValueError('Flow must be an object')
            if event.get('event_type') != 'flow':
                self.counts['ignored_non_flow_records'] += 1
                return []
            from soc_ai.flow import normalize
            flow = normalize(event)
            source = _ip(flow['src_ip'])
            target = _ip(flow['dest_ip'])
            stream = ('port', _text(source_container, 'source_container', 256),
                      _text(source_file, 'source_file'))
            instant = _instant(flow['end_time'])
            if flow['protocol'] != 'TCP':
                self.counts['ignored_non_tcp_flows'] += 1
                return []
            if flow['dest_port'] is None or flow['src_port'] is None:
                raise ValueError('TCP flow requires source and destination ports')
            identity = {k: flow[k] for k in (
                'src_ip', 'src_port', 'dest_ip', 'dest_port', 'protocol',
                'start_time', 'end_time', 'pkts_toserver', 'pkts_toclient',
                'bytes_toserver', 'bytes_toclient', 'app_protocol', 'flow_state',
                'flow_reason')}
            record_id = 'flow-context:' + _digest([stream, identity])
        except (ValueError, TypeError, KeyError, OverflowError):
            self.counts['invalid_flow_records'] += 1
            return []
        if not self.config['port_enabled']:
            self.counts['port_disabled_records'] += 1
            return []
        return self._observe('port', stream, source, 'ip:' + target, None,
                             instant, record_id, flow['dest_port'], None,
                             target_ip=target, target_host=None)

    def observe_http(self, event):
        """Observe one normalized Apache request, never a network-flow count."""
        self.counts['http_records_received'] += 1
        try:
            if not isinstance(event, dict) or event.get('schema_version') != 'soc-http-event/0.1':
                raise ValueError('Expected soc-http-event/0.1')
            instant = _instant(event['event_time'])
            source = _ip(event['source_ip'])
            target_ip = _ip(event['target_ip']) if event.get('target_ip') else None
            host = _text(event['target_host'], 'target_host', 256) if event.get('target_host') else None
            if target_ip is None and host is None:
                raise ValueError('HTTP target identity required')
            target = 'ip:' + target_ip if target_ip is not None else 'host:' + host
            port = event.get('destination_port')
            if port is not None and (type(port) is not int or not 0 <= port <= 65535):
                raise ValueError('Invalid HTTP destination port')
            status = event['http_status']
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError('Invalid HTTP response status')
            record = _text(event['record_id'], 'HTTP record_id', 256)
            container = event.get('_soc_source_container') or event.get('source_container')
            filename = event.get('_soc_source_file') or event.get('source_file')
            missing_provenance = not container or not filename
            container = container or host or 'unspecified'
            filename = filename or event.get('evidence_provider') or 'unspecified'
            stream = ('http', _text(container, 'source_container', 256),
                      _text(filename, 'source_file'))
            record_id = 'http-context:' + _digest([stream, record])
        except (ValueError, TypeError, KeyError, OverflowError):
            self.counts['invalid_http_records'] += 1
            return []
        if not self.config['http_enabled']:
            self.counts['http_disabled_records'] += 1
            return []
        if missing_provenance:
            self.counts['http_records_without_explicit_provenance'] += 1
        return self._observe('http', stream, source, target, port, instant,
                             record_id, None, status, target_ip=target_ip,
                             target_host=host)

    def _observe(self, kind, stream, source, target, service, instant, record_id,
                 destination_port, status, target_ip, target_host):
        if stream not in self._streams and len(self._streams) >= self.config['max_groups']:
            self.counts['stream_capacity_drops'] += 1
            return []
        watermark = self._streams.get(stream, instant)
        lateness = self.config['allowed_lateness_seconds'] * 1000000
        if instant < watermark - lateness:
            self.counts['late_records_rejected'] += 1
            return []
        self._streams[stream] = max(watermark, instant)
        # Evict only windows that this same sensor stream can no longer update.
        cutoff = self._streams[stream] - lateness
        for key, group in list(self._groups.items()):
            if group['stream'] == stream and group['end'] <= cutoff:
                self._event_count -= len(group['events'])
                del self._groups[key]
                self.counts['expired_windows'] += 1
        width = self.config[kind + '_window_seconds'] * 1000000
        start = (instant // width) * width
        key = (kind, stream, source, target, service, start)
        group = self._groups.get(key)
        if group is not None and record_id in group['events']:
            self.counts['duplicate_records'] += 1
            return []
        if (group is None and len(self._groups) >= self.config['max_groups']) or self._event_count >= self.config['max_events']:
            self.counts['event_capacity_drops'] += 1
            return []
        if group is None:
            group = {'stream': stream, 'kind': kind, 'source_ip': source,
                     'target_ip': target_ip, 'target_host': target_host,
                     'service': service, 'start': start, 'end': start + width,
                     'events': set(), 'ports': set(), 'port_sample': [],
                     'statuses': Counter(), 'evidence_sample': [],
                     'first_seen': instant, 'last_seen': instant}
            self._groups[key] = group
        group['events'].add(record_id)
        # Keep only the lexicographically/numerically smallest K samples. These
        # are deterministic under reordering without sorting all events per poll.
        sample_limit = self.config['max_evidence_ids']
        insort(group['evidence_sample'], record_id)
        del group['evidence_sample'][sample_limit:]
        group['first_seen'] = min(group['first_seen'], instant)
        group['last_seen'] = max(group['last_seen'], instant)
        if destination_port is not None and destination_port not in group['ports']:
            group['ports'].add(destination_port)
            insort(group['port_sample'], destination_port)
            del group['port_sample'][sample_limit:]
        if status is not None:
            group['statuses'][status] += 1
        self._event_count += 1
        self.counts['accepted_' + kind + '_records'] += 1
        events = group['events']
        observed = len(group['ports']) if kind == 'port' else len(events)
        if observed < self.config[kind + '_threshold']:
            return []
        signal_id = 'context:' + _digest(['soc-context-signal/0.1', key, width])
        signal = {
            'schema_version': 'soc-context-signal/0.1', 'signal_id': signal_id,
            'kind': 'context.distinct_port_sweep' if kind == 'port' else 'context.http_request_rate',
            'mode': 'shadow', 'revision': len(events),
            'source_ip': source, 'target_ip': target_ip, 'target_host': target_host,
            'source_container': stream[1], 'source_file': stream[2],
            'window_start': _stamp(start), 'window_end': _stamp(start + width),
            'window_seconds': width // 1000000,
            'first_seen': _stamp(group['first_seen']), 'last_seen': _stamp(group['last_seen']),
            'event_count': len(events), 'threshold': self.config[kind + '_threshold'],
            'evidence_ids': list(group['evidence_sample']),
            'evidence_ids_truncated': len(events) > self.config['max_evidence_ids'],
            'confirmed_compromise': False, 'attack_proven': False, 'training_label': None,
            'threshold_is_locally_validated': False,
        }
        if kind == 'port':
            signal.update(protocol='TCP', distinct_destination_ports=len(group['ports']),
                          destination_port_sample=list(group['port_sample']),
                          explanation='Distinct destination ports observed in completed TCP flows. '
                          'Possible port sweep evidence; authorized scanning can produce the same pattern.')
        else:
            statuses = group['statuses']
            signal.update(destination_port=service, request_count=len(events),
                          http_status_counts={str(code): statuses[code] for code in sorted(statuses)},
                          http_4xx_count=sum(n for code, n in statuses.items() if 400 <= code < 500),
                          http_5xx_count=sum(n for code, n in statuses.items() if 500 <= code < 600),
                          mean_requests_per_window_second=len(events) / (width / 1000000),
                          explanation='Apache request count exceeds an experimental configured threshold. '
                          'Volume and HTTP status codes alone do not prove DoS, outage, or malicious intent.')
        self._signals[signal_id] = (stream, signal)
        if len(self._signals) > self.config['max_signals']:
            oldest = min(self._signals, key=lambda sid: (self._signals[sid][1]['window_start'], sid))
            del self._signals[oldest]
            self.counts['signal_history_evictions'] += 1
        # No caller can mutate internal state through a returned object.
        return [json.loads(json.dumps(signal, allow_nan=False))]

    def snapshot(self):
        signals = []
        for stream, signal in self._signals.values():
            item = dict(signal)
            closed = self._streams[stream] - self.config['allowed_lateness_seconds'] * 1000000 >= _instant(item['window_end'])
            item['window_status'] = 'closed' if closed else 'open'
            signals.append(item)
        losses = ('invalid_flow_records', 'invalid_http_records', 'late_records_rejected',
                  'event_capacity_drops', 'stream_capacity_drops')
        result = {
            'schema_version': 'soc-context-state/0.1', 'mode': 'shadow',
            'config': dict(self.config),
            'signals': sorted(signals, key=lambda s: (s['window_start'], s['signal_id'])),
            'quality': {
                'counts': dict(sorted(self.counts.items())),
                'incomplete': any(self.counts[k] for k in losses),
                'signal_history_truncated': bool(self.counts['signal_history_evictions']),
                'retained_events': self._event_count, 'retained_groups': len(self._groups),
                'retained_streams': len(self._streams), 'retained_signals': len(self._signals),
                'window_policy': 'UTC-aligned tumbling, half-open [start,end)',
                'late_policy': 'reject event_time < per-sensor maximum event_time - allowed_lateness_seconds',
                'watermarks': [
                    {'kind': stream[0], 'source_container': stream[1],
                     'source_file': stream[2], 'maximum_event_time': _stamp(value)}
                    for stream, value in sorted(self._streams.items())],
            },
        }
        return json.loads(json.dumps(result, allow_nan=False))
