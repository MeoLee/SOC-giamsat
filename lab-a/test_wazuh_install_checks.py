"""Regression coverage for offline candidates, modern IPC and installer rollback."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import sys
import types
import unittest
from unittest.mock import patch

import wazuh_install_checks as checks
import setup_wazuh
import setup_scenario_rules

READY = '\n'.join(name + ' is running...' for name in checks.CORE)
MATCH = "**Phase 3: Completed filtering (rules).\n       Rule id: '119201'\n"


class InstallationChecks(unittest.TestCase):
    def test_offline_candidates_do_not_need_running_analysisd(self):
        checker = checks.RuleCheck('fixture\n', [119201])
        with patch.object(checks.os, 'access', return_value=True), patch.object(
                checks, '_invoke', side_effect=[(0, MATCH), (0, READY)]) as invoke:
            checker.before_restart()
            self.assertEqual(invoke.call_args_list[0].args[0], [checks.BIN+'wazuh-logtest-legacy'])
            self.assertEqual(invoke.call_count, 1)
            result = checker.after_restart()
            self.assertEqual(result['rule_test_backend'], 'legacy-offline')
            self.assertFalse(result['modern_logtest_verified'])
            self.assertFalse(result['live_delivery_verified'])
            self.assertNotIn([checks.BIN+'wazuh-logtest'], [c.args[0] for c in invoke.call_args_list])

    def test_modern_deferred_then_bounded_startup_retry(self):
        checker = checks.RuleCheck('fixture\n', [119201])
        with patch.object(checks.os, 'access', side_effect=lambda p, mode: not p.endswith('-legacy')), \
                patch.object(checks, '_invoke', side_effect=[(0, READY),
                    (0, 'Wazuh-logtest error when connecting with wazuh-analysisd'), (0, MATCH)]) as invoke, \
                patch.object(checks.time, 'sleep') as sleep:
            checker.before_restart()
            invoke.assert_not_called()
            result = checker.after_restart()
            self.assertTrue(result['modern_logtest_verified'])
            self.assertEqual(invoke.call_args_list[0].args[0], [checks.BIN+'wazuh-control', 'status'])
            sleep.assert_called_once_with(2)

    def test_persistent_ipc_failure_is_not_rule_success(self):
        checker = checks.RuleCheck('fixture', [119201]); checker.backend = 'modern-after-restart'
        with patch.object(checks, '_invoke', side_effect=[(0, READY)] +
                    [(0, 'error when connecting with wazuh-analysisd')]*3) as invoke, \
                patch.object(checks.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'cannot connect'):
                checker.after_restart()
            self.assertEqual(invoke.call_count, 4)
            self.assertFalse(checker.validated)

    def test_rule_mismatch_is_not_retried_or_switched_to_modern(self):
        checker = checks.RuleCheck('fixture', [119201])
        with patch.object(checks.os, 'access', return_value=True), \
                patch.object(checks, '_invoke', return_value=(0, "**Phase 3: Completed filtering (rules).\n       Rule id: '119202'")) as invoke:
            with self.assertRaisesRegex(RuntimeError, 'fixture mismatch'):
                checker.before_restart()
            self.assertEqual(invoke.call_count, 1)

    def test_modern_wrong_rule_fails_without_retry(self):
        checker = checks.RuleCheck('fixture', [119201]); checker.backend = 'modern-after-restart'
        with patch.object(checks, '_invoke', side_effect=[(0, READY), (0, "**Phase 3: Completed filtering (rules).\n       Rule id: '119202'")]) as invoke:
            with self.assertRaisesRegex(RuntimeError, 'fixture mismatch'):
                checker.after_restart()
            self.assertEqual(invoke.call_count, 2)

    def test_legacy_signature_id_and_decoded_id_are_not_rule_ids(self):
        output=("**Phase 2: Completed decoding.\n"
                "       signature_id: '9900101'\n"
                "       event_id: '123456'\n"
                "       id: '777'\n"
                "**Phase 3: Completed filtering (rules).\n"
                "       Rule id: '119215'\n"
                "       Description: 'id: 9900101'\n")
        self.assertEqual(checks.matched_rule_ids(output),['119215'])
        checker=checks.RuleCheck('fixture',[119215]);checker._match(output)
        self.assertTrue(checker.validated)

    def test_modern_phase_three_id_and_crlf_are_supported(self):
        output=("**Phase 2: Completed decoding.\r\n       id: '9900101'\r\n"
                "**Phase 3: Completed filtering (rules).\r\n       id: '119215'\r\n"
                "**Phase 1: Completed pre-decoding.\r\n"
                "**Phase 2: Completed decoding.\r\n       rule_id: '888'\r\n"
                "**Phase 3: Completed filtering (rules).\r\n       id: '87105'\r\n")
        self.assertEqual(checks.matched_rule_ids(output),['119215','87105'])

    def test_no_phase_three_cannot_fake_success_with_decoded_fields(self):
        output="**Phase 2: Completed decoding.\n       id: '119201'\n       signature_id: '119201'\n"
        self.assertEqual(checks.matched_rule_ids(output),[])
        with self.assertRaisesRegex(RuntimeError,'fixture mismatch'):
            checks.RuleCheck('fixture',[119201])._match(output)

    def test_extra_real_phase_three_rule_is_not_silently_ignored(self):
        output=MATCH+"**Phase 3: Completed filtering (rules).\n       Rule id: '119215'\n"
        with self.assertRaisesRegex(RuntimeError,'fixture mismatch'):
            checks.RuleCheck('fixture',[119201])._match(output)

    def test_stopped_analysisd_fails_readiness(self):
        status = READY.replace('wazuh-analysisd is running', 'wazuh-analysisd is not running')
        with patch.object(checks, '_invoke', return_value=(1, status)):
            with self.assertRaisesRegex(RuntimeError, 'wazuh-analysisd'):
                checks.wait_manager_ready(timeout=0)

    def test_remote_payloads_embed_dependency_within_windows_limit(self):
        for module in (setup_wazuh, setup_scenario_rules):
            script = module.remote_script()
            compile(script, 'remote', 'exec')
            self.assertTrue(script.endswith('install_remote(json.load(sys.stdin))\n'))
            self.assertIn("sys.modules['wazuh_install_checks']", script)
            cmdline = subprocess.list2cmdline(['docker', 'exec', '-i', '--user', '0',
                'single-node-wazuh.manager-1', 'sh', '-c', 'launcher', 'setup', '-c', script])
            self.assertLess(len(cmdline), 32767)
            namespace = {}
            # Exercise the embedded support in a fresh namespace without installer execution.
            with patch.dict(sys.modules):
                exec(script.rsplit('\ninstall_remote(', 1)[0], namespace)
            self.assertTrue(callable(namespace['install_remote']))

    def test_bridge_health_failure_restores_files_and_original_error(self):
        self._rollback(setup_wazuh)

    def test_scenario_health_failure_restores_files_and_original_error(self):
        self._rollback(setup_scenario_rules)

    def _rollback(self, module):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'var/ossec'
            (root/'etc/rules').mkdir(parents=True)
            (root/'logs/soc-ai').mkdir(parents=True)
            config = root/'etc/ossec.conf'; config.write_text('<ossec_config/>')
            # Use explicit closing tag for bridge insertion.
            config.write_text('<ossec_config></ossec_config>')
            rules = root/'etc/rules'/Path(module.RULE_PATH).name
            rules.write_text(module.MARKER+' previous managed rules')
            marker = root/'logs/soc-ai/bridge-ready.json'; marker.write_text('old marker')
            originals = {p: p.read_bytes() for p in (config, rules, marker)}
            source = Path(module.__file__).read_text().replace('/var/ossec', root.as_posix())
            namespace = {'__name__': 'isolated_installer'}; exec(compile(source, 'test-installer', 'exec'), namespace)
            class Candidate:
                def __init__(self, *args): pass
                def before_restart(self): pass
                def after_restart(self): raise RuntimeError('ORIGINAL core not ready')
            commands = []
            def run(argv, **kwargs):
                commands.append(argv)
                if argv[-1] == 'restart' and len([c for c in commands if c[-1]=='restart']) == 2:
                    return subprocess.CompletedProcess(argv, 1, b'', b'rollback restart failed')
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            namespace['RuleCheck'] = Candidate
            namespace['ensure_no_restart_in_progress'] = lambda: None
            def restart():
                result=run([str(root/'bin/wazuh-control'),'restart'])
                if result.returncode:raise RuntimeError('rollback restart failed')
            namespace['restart_manager'] = restart
            output = io.StringIO()
            payload = {'rules': Path(module.__file__).with_name(
                'soc_ai_bridge_rules.xml' if module is setup_wazuh else 'soc_scenario_rules.xml').read_text()}
            group_module = types.SimpleNamespace(getgrnam=lambda name: types.SimpleNamespace(gr_gid=0))
            with patch.dict(sys.modules, {'grp': group_module}), \
                    patch.object(os, 'chown', create=True), patch.object(subprocess, 'run', side_effect=run), \
                    contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, 'ORIGINAL core not ready'):
                    namespace['install_remote'](payload)
            for path, data in originals.items():
                self.assertEqual(path.read_bytes(), data)
            self.assertIn('ROLLBACK_RESTART_FAILED', output.getvalue())
            self.assertEqual(len([c for c in commands if c[-1]=='restart']), 2)


if __name__ == '__main__':
    unittest.main()
