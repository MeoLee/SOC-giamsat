"""Candidate rule checks and bounded manager readiness checks for installers.

Modern wazuh-logtest is an IPC client: it must never validate candidate rules
against the old, running analysisd before a restart. Legacy loads files offline.
"""
import os
from pathlib import Path
import re
import subprocess
import time

BIN = '/var/ossec/bin/'
CORE = ('wazuh-db', 'wazuh-analysisd', 'wazuh-logcollector')


def _invoke(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, timeout=60, **kwargs)
    output = (result.stdout + result.stderr).decode(errors='replace')
    print(output, flush=True)
    return result.returncode, output


def wait_manager_ready(timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        _, output = _invoke([BIN + 'wazuh-control', 'status'])
        missing = [name for name in CORE if not re.search(
            r'^' + re.escape(name) + r'\s+is running\b', output, re.MULTILINE)]
        if not missing:
            print('WAZUH_CORE_READY: ' + ', '.join(CORE), flush=True)
            return list(CORE)
        if time.monotonic() >= deadline:
            raise RuntimeError('Manager not ready after restart: ' + ', '.join(missing)
                               + '. Inspect wazuh-control status and logs/ossec.log.')
        time.sleep(min(2, max(0, deadline - time.monotonic())))


class RuleCheck:
    def __init__(self, lines, expected_ids):
        self.lines = lines.encode() if isinstance(lines, str) else lines
        self.expected = [str(value) for value in expected_ids]
        self.backend = None
        self.validated = False

    def _match(self, output):
        matched = re.findall(r"id:\s*'(\d+)'", output)
        if matched != self.expected:
            raise RuntimeError('Rule fixture mismatch: expected ' + ','.join(self.expected)
                               + '; matched ' + ','.join(matched)
                               + '. Candidate rules were not accepted.')
        self.validated = True

    def before_restart(self):
        legacy = BIN + 'wazuh-logtest-legacy'
        if os.access(legacy, os.X_OK):
            self.backend = 'legacy-offline'
            code, output = _invoke([legacy], input=self.lines)
            if code:
                raise RuntimeError('Offline candidate rule validation failed.')
            self._match(output)
            print('CANDIDATE_RULES_VERIFIED_OFFLINE', flush=True)
        elif os.access(BIN + 'wazuh-logtest', os.X_OK):
            self.backend = 'modern-after-restart'
            print('Modern logtest requires running analysisd; fixture check deferred until restart.', flush=True)
        else:
            raise RuntimeError('No executable Wazuh rule test binary found.')

    def after_restart(self):
        if self.backend is None:
            raise RuntimeError('Candidate validation was not prepared.')
        ready = wait_manager_ready()
        if self.backend == 'modern-after-restart':
            for attempt in range(3):
                code, output = _invoke([BIN + 'wazuh-logtest'], input=self.lines)
                ipc_error = any(value in output.lower() for value in (
                    'connecting with wazuh-analysisd', 'could not connect',
                    'connection refused', 'error connecting', 'unable to connect'))
                if ipc_error:
                    if attempt < 2:
                        time.sleep(2)
                        continue
                    raise RuntimeError('Modern logtest cannot connect to analysisd after restart. '
                                       'Inspect rule_test configuration and logs/ossec.log; '
                                       'rule validation was not skipped.')
                if code:
                    raise RuntimeError('Modern rule validation failed after restart.')
                self._match(output)
                break
        if not self.validated:
            raise RuntimeError('Rule fixtures were not validated.')
        return {'rule_test_backend': self.backend, 'candidate_rules_verified': True,
                'core_processes_ready': ready,
                'modern_logtest_verified': self.backend == 'modern-after-restart',
                'live_delivery_verified': False}


def embedded_support():
    """Embed this dependency in docker exec's Python payload; no remote install."""
    source = Path(__file__).read_text(encoding='utf-8')
    return ("import sys, types\n"
            "_checks = types.ModuleType('wazuh_install_checks')\n"
            'exec(' + repr(source) + ", _checks.__dict__)\n"
            "sys.modules['wazuh_install_checks'] = _checks\n")
