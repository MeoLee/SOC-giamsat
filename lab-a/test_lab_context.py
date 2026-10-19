from datetime import datetime, timedelta, timezone
import json
import unittest

from lab_context import ContextDetector, DEFAULTS, validated_config


BASE = datetime(2026, 10, 19, 0, 0, tzinfo=timezone.utc)


def stamp(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def flow(port=22, second=1, source='192.0.2.10', target='192.0.2.20', serial=1):
    return {'timestamp': stamp(second + 1), 'event_type': 'flow', 'flow_id': serial,
            'src_ip': source, 'dest_ip': target, 'src_port': 40000 + serial,
            'dest_port': port, 'proto': 'TCP', 'app_proto': 'other',
            'flow': {'start': stamp(second - 0.1), 'end': stamp(second),
                     'pkts_toserver': 1, 'pkts_toclient': 0,
                     'bytes_toserver': 60, 'bytes_toclient': 0,
                     'state': 'new', 'reason': 'timeout'}}


def http(second=1, serial=1, status=200, source='192.0.2.10', target='192.0.2.20'):
    return {'schema_version': 'soc-http-event/0.1', 'event_time': stamp(second),
            'record_id': 'http:' + str(serial), 'source_ip': source,
            'target_ip': target, 'destination_port': 80, 'http_status': status,
            'source_container': 'endpoint', 'source_file': 'apache.tsv'}


class ContextTests(unittest.TestCase):
    def observe(self, detector, item):
        return detector.observe_flow(item, 'eve.json', 'sensor')

    def test_distinct_ports_positive_and_repeated_service_negative(self):
        distinct = ContextDetector({'port_threshold': 3})
        repeated = ContextDetector({'port_threshold': 3})
        for serial, port in enumerate((22, 80, 443), 1):
            self.observe(distinct, flow(port, serial=serial))
            self.observe(repeated, flow(22, serial=serial))
        signal = distinct.snapshot()['signals'][0]
        self.assertEqual(signal['distinct_destination_ports'], 3)
        self.assertEqual(signal['destination_port_sample'], [22, 80, 443])
        self.assertEqual(repeated.snapshot()['signals'], [])
        self.assertFalse(signal['attack_proven'])
        self.assertFalse(signal['confirmed_compromise'])
        self.assertIsNone(signal['training_label'])
        self.assertEqual(signal['mode'], 'shadow')

    def test_poll_boundaries_do_not_reset_state(self):
        rows = [flow(port, second=i + 10, serial=i + 1) for i, port in enumerate((22, 80, 443))]
        once = ContextDetector({'port_threshold': 3})
        polls = ContextDetector({'port_threshold': 3})
        for row in rows:
            self.observe(once, row)
        self.observe(polls, rows[0])
        polls.snapshot()  # UI polling must not consume/reset detection state.
        for row in rows[1:]:
            self.observe(polls, row)
        self.assertEqual(once.snapshot(), polls.snapshot())

    def test_targets_sources_sensors_and_http_services_do_not_merge(self):
        detector = ContextDetector({'port_threshold': 2, 'http_enabled': True, 'http_threshold': 2})
        self.observe(detector, flow(22))
        self.observe(detector, flow(80, target='192.0.2.30'))
        self.observe(detector, flow(80, source='192.0.2.11'))
        detector.observe_flow(flow(80), 'eve.json', 'different-sensor')
        detector.observe_http(http())
        detector.observe_http({**http(serial=2), 'destination_port': 8080})
        self.assertEqual(detector.snapshot()['signals'], [])

    def test_duplicate_flow_and_http_do_not_inflate_counts(self):
        detector = ContextDetector({'port_threshold': 2, 'http_enabled': True, 'http_threshold': 2})
        one = flow()
        self.observe(detector, one)
        # EVE/Wazuh wrapping order and a regenerated native flow ID are irrelevant.
        self.observe(detector, {**one, 'flow_id': 999, 'timestamp': stamp(3)})
        detector.observe_http(http())
        detector.observe_http(http())
        self.assertEqual(detector.snapshot()['signals'], [])
        self.assertEqual(detector.snapshot()['quality']['counts']['duplicate_records'], 2)

    def test_late_within_tolerance_updates_same_id_outside_is_reported(self):
        detector = ContextDetector({'port_threshold': 2, 'allowed_lateness_seconds': 10})
        self.observe(detector, flow(22, second=20))
        self.observe(detector, flow(80, second=15, serial=2))
        before = detector.snapshot()['signals'][0]
        self.observe(detector, flow(443, second=18, serial=3))
        after = detector.snapshot()['signals'][0]
        self.assertEqual(before['signal_id'], after['signal_id'])
        self.assertEqual(after['revision'], 3)
        self.assertEqual(after['first_seen'], '2026-10-19T00:00:15.000000Z')
        self.observe(detector, flow(445, second=9, serial=4))
        state = detector.snapshot()
        self.assertEqual(state['signals'][0]['distinct_destination_ports'], 3)
        self.assertEqual(state['quality']['counts']['late_records_rejected'], 1)
        self.assertTrue(state['quality']['incomplete'])

    def test_signal_and_evidence_order_deterministic_for_accepted_reordering(self):
        rows = [flow(22, second=20), flow(80, second=15, serial=2), flow(443, second=18, serial=3)]
        left = ContextDetector({'port_threshold': 2})
        right = ContextDetector({'port_threshold': 2})
        for row in rows:
            self.observe(left, row)
        for row in reversed(rows):
            self.observe(right, row)
        self.assertEqual(left.snapshot()['signals'], right.snapshot()['signals'])

    def test_fixed_window_boundary_is_explicit_and_half_open(self):
        detector = ContextDetector({'port_threshold': 2, 'allowed_lateness_seconds': 10})
        self.observe(detector, flow(22, second=59.999999))
        self.observe(detector, flow(80, second=60))
        self.assertEqual(detector.snapshot()['signals'], [])
        self.assertIn('half-open', detector.snapshot()['quality']['window_policy'])

    def test_ipv6_is_canonical_and_timezone_is_not_assumed(self):
        detector = ContextDetector({'port_threshold': 2})
        self.observe(detector, flow(22, source='2001:0db8:0:0::10', target='2001:db8::20'))
        other = flow(80, source='2001:db8::10', target='2001:db8::20', serial=2)
        other['flow']['end'] = '2026-10-19T07:00:01+07:00'
        self.observe(detector, other)
        self.assertEqual(detector.snapshot()['signals'][0]['source_ip'], '2001:db8::10')
        self.assertEqual(detector.snapshot()['signals'][0]['first_seen'], '2026-10-19T00:00:01.000000Z')
        bad = flow(443, serial=3)
        bad['flow']['end'] = '2026-10-19T00:00:01'
        self.observe(detector, bad)
        self.assertEqual(detector.snapshot()['quality']['counts']['invalid_flow_records'], 1)

    def test_http_counts_requests_and_statuses_not_network_packets(self):
        detector = ContextDetector({'http_enabled': True, 'http_threshold': 3})
        for serial, status in enumerate((200, 404, 503), 1):
            detector.observe_http(http(serial=serial, status=status))
        signal = detector.snapshot()['signals'][0]
        self.assertEqual(signal['kind'], 'context.http_request_rate')
        self.assertEqual(signal['request_count'], 3)
        self.assertEqual(signal['http_status_counts'], {'200': 1, '404': 1, '503': 1})
        self.assertEqual(signal['http_4xx_count'], 1)
        self.assertEqual(signal['http_5xx_count'], 1)
        self.assertFalse(signal['attack_proven'])
        self.assertFalse(signal['threshold_is_locally_validated'])
        self.assertIsNone(signal['training_label'])

    def test_http_disabled_without_local_baseline_by_default(self):
        detector = ContextDetector()
        for serial in range(130):
            detector.observe_http(http(serial=serial))
        self.assertEqual(detector.snapshot()['signals'], [])
        self.assertEqual(detector.snapshot()['quality']['retained_events'], 0)
        self.assertEqual(detector.snapshot()['quality']['counts']['http_disabled_records'], 130)

    def test_normal_http_below_threshold_and_separate_views_not_summed(self):
        detector = ContextDetector({'http_enabled': True, 'http_threshold': 3})
        for serial in (1, 2):
            detector.observe_http(http(serial=serial))
            detector.observe_http({**http(serial=serial), 'source_file': 'wazuh.json'})
        self.assertEqual(detector.snapshot()['signals'], [])

    def test_flow_end_and_not_log_emission_controls_window(self):
        detector = ContextDetector({'port_threshold': 2})
        one = flow(22, second=5)
        two = flow(80, second=6, serial=2)
        two['timestamp'] = stamp(120)
        self.observe(detector, one)
        self.observe(detector, two)
        self.assertEqual(detector.snapshot()['signals'][0]['window_start'], '2026-10-19T00:00:00.000000Z')

    def test_non_tcp_and_non_flow_not_counted_as_port_sweep(self):
        detector = ContextDetector({'port_threshold': 2})
        self.observe(detector, {**flow(22), 'proto': 'UDP'})
        self.observe(detector, {'event_type': 'alert'})
        self.assertEqual(detector.snapshot()['quality']['retained_events'], 0)
        self.assertFalse(detector.snapshot()['quality']['incomplete'])

    def test_capacity_limits_are_enforced_and_loss_is_visible(self):
        detector = ContextDetector({'max_groups': 1, 'max_events': 2, 'port_threshold': 2})
        self.observe(detector, flow(22))
        self.observe(detector, flow(80, serial=2))
        self.observe(detector, flow(443, serial=3))
        detector.observe_flow(flow(445), 'eve.json', 'other-sensor')
        state = detector.snapshot()
        self.assertEqual(state['quality']['retained_events'], 2)
        self.assertEqual(state['quality']['retained_groups'], 1)
        self.assertEqual(state['quality']['retained_streams'], 1)
        self.assertEqual(state['quality']['counts']['event_capacity_drops'], 1)
        self.assertEqual(state['quality']['counts']['stream_capacity_drops'], 1)
        self.assertTrue(state['quality']['incomplete'])

    def test_old_window_expires_and_capacity_becomes_available(self):
        detector = ContextDetector({'max_groups': 1, 'max_events': 2, 'port_threshold': 2})
        self.observe(detector, flow(22))
        self.observe(detector, flow(80, serial=2))
        self.observe(detector, flow(443, second=71, serial=3))
        state = detector.snapshot()
        self.assertEqual(state['quality']['retained_events'], 1)
        self.assertEqual(state['signals'][0]['window_status'], 'closed')
        self.assertEqual(state['quality']['counts']['expired_windows'], 1)

    def test_history_and_evidence_are_bounded_and_outputs_are_copies(self):
        detector = ContextDetector({'port_threshold': 2, 'max_signals': 1, 'max_evidence_ids': 1})
        for second in (1, 71):
            self.observe(detector, flow(22, second=second))
            update = self.observe(detector, flow(80, second=second, serial=2))[0]
            update['evidence_ids'].append('caller-mutation')
        state = detector.snapshot()
        self.assertEqual(len(state['signals']), 1)
        self.assertEqual(len(state['signals'][0]['evidence_ids']), 1)
        self.assertTrue(state['signals'][0]['evidence_ids_truncated'])
        self.assertTrue(state['quality']['signal_history_truncated'])
        state['signals'][0]['evidence_ids'].append('caller-mutation')
        self.assertEqual(len(detector.snapshot()['signals'][0]['evidence_ids']), 1)

    def test_stream_watermarks_do_not_make_another_sensor_late(self):
        detector = ContextDetector({'port_threshold': 2})
        self.observe(detector, flow(22, second=1000))
        detector.observe_flow(flow(22), 'eve.json', 'second-sensor')
        detector.observe_flow(flow(80, serial=2), 'eve.json', 'second-sensor')
        self.assertEqual(len(detector.snapshot()['signals']), 1)
        self.assertNotIn('late_records_rejected', detector.snapshot()['quality']['counts'])

    def test_http_host_identity_without_target_ip_and_provenance_warning(self):
        detector = ContextDetector({'http_enabled': True, 'http_threshold': 1})
        event = http(target=None)
        event.pop('source_container')
        event.pop('source_file')
        event['target_host'] = 'endpoint'
        detector.observe_http(event)
        self.assertEqual(detector.snapshot()['signals'][0]['target_host'], 'endpoint')
        self.assertEqual(detector.snapshot()['quality']['counts']['http_records_without_explicit_provenance'], 1)

    def test_invalid_input_does_not_silently_become_zero(self):
        detector = ContextDetector({'http_enabled': True, 'http_threshold': 1})
        for bad in ({**http(), 'http_status': True}, {**http(), 'event_time': '2026-10-19T00:00:01'},
                    {**http(), 'source_ip': '999.1.1.1'}, {**http(), 'record_id': ''}):
            detector.observe_http(bad)
        self.assertEqual(detector.snapshot()['quality']['counts']['invalid_http_records'], 4)
        self.assertEqual(detector.snapshot()['signals'], [])

    def test_configuration_validation_and_json_serializability(self):
        self.assertEqual(validated_config(), DEFAULTS)
        for config in ({'port_threshold': True}, {'http_enabled': 1}, {'typo': 1},
                       {'port_window_seconds': 0}, {'max_events': 1000001}, []):
            with self.assertRaises(ValueError):
                ContextDetector(config)
        json.dumps(ContextDetector().snapshot(), allow_nan=False)


if __name__ == '__main__':
    unittest.main()
