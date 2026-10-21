"""Restart completion is control PID exit, not EOF inherited by daemons."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import wazuh_install_checks as checks
import setup_virustotal as vt


class RestartControlTests(unittest.TestCase):
    def test_restart_uses_regular_file_redacts_and_never_communicates(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);key='a'*64
            process=Mock(pid=123,returncode=0);process.poll.return_value=0
            def spawn(argv,**kwargs):
                self.assertEqual(argv,[str(root/'bin/wazuh-control'),'restart'])
                self.assertNotEqual(kwargs['stdout'],subprocess.PIPE)
                self.assertEqual(kwargs['stderr'],subprocess.STDOUT)
                kwargs['stdout'].write((key+'\nCompleted.\n').encode())
                return process
            output=io.StringIO()
            with patch.object(checks,'BIN',str(root/'bin')+'/'),patch.object(checks.subprocess,'Popen',side_effect=spawn),contextlib.redirect_stdout(output):
                checks.restart_manager(redactions=(key,))
            self.assertNotIn(key,output.getvalue());self.assertIn('[REDACTED]',output.getvalue())
            self.assertIn('WAZUH_RESTART_COMPLETED',output.getvalue())
            process.communicate.assert_not_called();process.kill.assert_not_called()
            logs=list((root/'logs').glob('soc-setup-restart-*.log'));self.assertEqual(len(logs),1)
            if os.name!='nt':self.assertEqual(logs[0].stat().st_mode & 0o777,0o600)

    def test_true_timeout_leaves_control_alive_and_does_not_start_second_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            clock=[0];process=Mock(pid=123,returncode=None);process.poll.return_value=None
            def sleep(seconds):clock[0]+=seconds
            with patch.object(checks,'BIN',str(Path(folder)/'bin')+'/'),patch.object(checks.subprocess,'Popen',return_value=process) as spawn, \
                    patch.object(checks.time,'monotonic',side_effect=lambda:clock[0]),patch.object(checks.time,'sleep',side_effect=sleep),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(checks.ManagerRestartInProgress,'no rollback or second restart'):
                    checks.restart_manager(timeout=3)
            self.assertEqual(spawn.call_count,1);process.kill.assert_not_called();process.terminate.assert_not_called()

    def test_interrupt_with_running_control_is_pending_not_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            process=Mock(pid=123,returncode=None);process.poll.side_effect=[KeyboardInterrupt(),None]
            with patch.object(checks,'BIN',str(Path(folder)/'bin')+'/'),patch.object(checks.subprocess,'Popen',return_value=process),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(checks.ManagerRestartInProgress,'interrupted'):
                    checks.restart_manager()
            process.kill.assert_not_called()

    def test_existing_live_control_lock_prevents_mutation_and_spawn(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);lock=root/'var/start-script-lock/pid';lock.parent.mkdir(parents=True);lock.write_text('123')
            with patch.object(checks,'BIN',str(root/'bin')+'/'),patch.object(checks.os,'kill'),patch.object(checks.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(checks.ManagerRestartInProgress,'still running'):
                    checks.restart_manager()
            spawn.assert_not_called();self.assertFalse((root/'logs').exists())

    def test_stale_native_control_lock_is_left_for_wazuh_to_handle(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);lock=root/'var/start-script-lock/pid';lock.parent.mkdir(parents=True);lock.write_text('123')
            with patch.object(checks,'BIN',str(root/'bin')+'/'),patch.object(checks.os,'kill',side_effect=ProcessLookupError):
                checks.ensure_no_restart_in_progress()
            self.assertEqual(lock.read_text(),'123')

    @unittest.skipIf(os.name=='nt','POSIX inherited daemon stdout fixture')
    def test_control_exit_is_not_delayed_by_child_holding_stdout(self):
        # A daemon-like child holds stdout for five seconds after its parent
        # exits. subprocess.run(capture_output=True) would wait for that EOF.
        real_popen=subprocess.Popen
        command=[sys.executable,'-c',
                 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(5)"],stdout=sys.stdout,stderr=sys.stderr); print("Completed",flush=True)']
        with tempfile.TemporaryDirectory() as folder:
            def spawn(argv,**kwargs):return real_popen(command,**kwargs)
            with patch.object(checks,'BIN',str(Path(folder)/'bin')+'/'),patch.object(checks.subprocess,'Popen',side_effect=spawn),contextlib.redirect_stdout(io.StringIO()):
                started=time.monotonic();checks.restart_manager(timeout=10);elapsed=time.monotonic()-started
            self.assertLess(elapsed,3,'Waited for daemon-held stdout instead of control PID')

    def test_vt_true_timeout_keeps_candidate_and_does_not_claim_success(self):
        self._vt_install(pending=True)

    def test_vt_completed_restart_then_validation_failure_restores_original(self):
        self._vt_install(pending=False)

    def _vt_install(self,pending):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'var/ossec';(root/'etc/rules').mkdir(parents=True);(root/'integrations').mkdir()
            config=root/'etc/ossec.conf';old=b'<ossec_config><global/></ossec_config>';config.write_bytes(old)
            (root/'etc/rules/soc_scenario_rules.xml').write_text('SOC-SCENARIO MANAGED <rule id="119253"/>')
            for name in ('virustotal','virustotal.py'):(root/'integrations'/name).touch()
            source=Path(vt.__file__).read_text().replace('/var/ossec',root.as_posix())
            namespace={'__name__':'isolated_vt'};exec(source,namespace)
            candidate=Mock();candidate.after_restart.side_effect=RuntimeError('CORE_VALIDATION_FAILED')
            namespace['RuleCheck']=Mock(return_value=candidate)
            namespace['ensure_no_restart_in_progress']=lambda:None
            restart=Mock(side_effect=checks.ManagerRestartInProgress('still running')) if pending else Mock(side_effect=[None,RuntimeError('rollback failed')])
            namespace['restart_manager']=restart
            key='a'*64;output=io.StringIO()
            with patch.object(vt.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')), \
                    patch.object(os,'chown',create=True),patch.dict(sys.modules,{'requests':SimpleNamespace()}),contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError,'still running' if pending else 'CORE_VALIDATION_FAILED'):
                    namespace['install_remote']({'api_key':key})
            self.assertEqual(restart.call_count,1 if pending else 2)
            self.assertEqual(config.read_bytes()==old,not pending)
            self.assertNotIn(key,output.getvalue());self.assertNotIn('VIRUSTOTAL_CONFIGURED',output.getvalue())
            if pending:self.assertIn(key,config.read_text());candidate.after_restart.assert_not_called()
            else:self.assertIn('ROLLBACK_RESTART_FAILED',output.getvalue())


if __name__=='__main__':unittest.main()
