import unittest

from diagnose_recon import summarize


def observations(source, ports):
    return [{'event_type': 'alert', 'src_ip': source, 'flow_id': i,
             'src_port': 32000 + i, 'dest_port': port,
             'alert': {'signature_id': 9900003, 'source': 'packet'}}
            for i, port in enumerate(ports)]


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.events = (observations('198.51.100.20', range(1, 33))
                       + observations('198.51.100.30', [80] * 33)
                       + observations('198.51.100.40', [22] * 24))

    def test_exact_capture_counts_pass(self):
        self.assertTrue(summarize(self.events)['all_counts_and_ports_match'])

    def test_duplicate_output_is_distinguished_from_extra_connections(self):
        report = summarize(self.events + self.events)
        self.assertFalse(report['all_counts_and_ports_match'])
        group = report['groups']['198.51.100.30']
        self.assertEqual(group['observed_alert_records'], 66)
        self.assertEqual(group['unique_connections'], 33)
        self.assertEqual(group['repeated_connections'][0]['alert_records'], 2)

    def test_missing_same_service_connection_is_not_hidden_by_port_coverage(self):
        report = summarize(self.events[:-1])
        group = report['groups']['198.51.100.40']
        self.assertEqual(group['missing_destination_ports'], [])
        self.assertEqual(group['unique_connections'], 23)
        self.assertFalse(report['all_counts_and_ports_match'])

    def test_missing_scan_port_is_reported(self):
        report = summarize(self.events[1:])
        self.assertEqual(report['groups']['198.51.100.20']['missing_destination_ports'], [1])


if __name__ == '__main__':
    unittest.main()
