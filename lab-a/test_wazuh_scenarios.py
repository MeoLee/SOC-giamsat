import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

import wazuh_scenarios as scenarios


def result(code, stderr=b''):
    return SimpleNamespace(returncode=code, stdout=b'', stderr=stderr)


class PasswordRejectionTests(unittest.TestCase):
    def test_one_prompt_openssh_denial_is_expected(self):
        for methods in ('password', 'publickey,password'):
            stderr = (f'Warning: known host added.\r\n'
                      f'soctest@172.20.0.3: Permission denied ({methods}).\r\n').encode()
            self.assertTrue(scenarios.expected_password_rejection(
                result(255, stderr), '172.20.0.3', 'soctest'))
        self.assertTrue(scenarios.expected_password_rejection(
            result(5), '172.20.0.3', 'soctest'))

    def test_transport_timeout_policy_and_wrong_entity_are_not_password_results(self):
        denied = b'soctest@172.20.0.3: Permission denied (password).\n'
        cases = [(0, denied), (124, denied), (126, denied),
                 (255, b'ssh: connect to host 172.20.0.3 port 22: Connection refused\n'),
                 (255, b'Connection closed by 172.20.0.3 port 22\n'),
                 (255, b'Host key verification failed.\n'),
                 (255, b'other@172.20.0.3: Permission denied (password).\n'),
                 (255, b'soctest@172.20.0.99: Permission denied (password).\n'),
                 (255, b'soctest@172.20.0.3: Permission denied (publickey).\n'),
                 (255, b'/usr/bin/ssh: Permission denied\n')]
        for code, stderr in cases:
            with self.subTest(code=code, stderr=stderr):
                self.assertFalse(scenarios.expected_password_rejection(
                    result(code, stderr), '172.20.0.3', 'soctest'))

    def run_chain(self, root, rejection):
        capture = root / 'capture'; capture.mkdir()
        output = root / 'evidence'
        argv = ['wazuh_scenarios.py', 'run', '--scenario', 'chain',
                '--capture', str(capture), '--output', str(output)]
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if 'sshpass' in command and 'ssh' in command:
                return rejection
            if command[:3] == ['docker', 'exec', '-it']:
                self.assertFalse(kwargs['capture_output'])
            return result(0)

        scope = {'source_ip': '172.20.0.4', 'target_ip': '172.20.0.3'}
        with patch.object(sys, 'argv', argv), \
                patch.object(scenarios, 'validate_capture', return_value=(
                    {'session_id': 'test-session'}, {'model_weights_sha256': 'test-model'})), \
                patch.object(scenarios, 'lab_scope', return_value=scope), \
                patch.object(scenarios.subprocess, 'run', side_effect=runner), \
                contextlib.redirect_stdout(io.StringIO()) as console:
            code = scenarios.main()
        return code, json.loads((output / 'operator.json').read_text()), calls, console.getvalue()

    def test_chain_continues_after_eight_explicit_denials_then_correct_login(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report, calls, console = self.run_chain(Path(directory), result(
                255, b'soctest@172.20.0.3: Permission denied (publickey,password).\n'))
        self.assertEqual(code, 0)
        self.assertTrue(report['complete'])
        self.assertEqual(report['failure_attempts'], 8)
        self.assertEqual(sum(step.get('client_outcome') == 'password_rejected'
                             for step in report['steps']), 8)
        self.assertEqual(sum('sshpass' in c and 'ssh' in c for c in calls), 8)
        self.assertEqual(sum(c[:3] == ['docker', 'exec', '-it'] for c in calls), 1)
        self.assertEqual(console.count('EXPECTED_PASSWORD_REJECTION: exit=255'), 8)
        self.assertIsNone(report['training_label'])

    def test_chain_stops_and_displays_transport_error_before_more_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report, calls, console = self.run_chain(Path(directory), result(
                255, b'ssh: connect to host 172.20.0.3 port 22: Connection refused\n'))
        self.assertEqual(code, 2)
        self.assertFalse(report['complete'])
        self.assertEqual(report['steps'][-1]['client_outcome'], 'unexpected_result')
        self.assertEqual(sum('sshpass' in c and 'ssh' in c for c in calls), 1)
        self.assertFalse(any(c[:3] == ['docker', 'exec', '-it'] for c in calls))
        self.assertIn('exit 255', console)
        self.assertIn('Connection refused', console)


if __name__ == '__main__':
    unittest.main()
