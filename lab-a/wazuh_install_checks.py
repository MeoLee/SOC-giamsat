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


class ManagerRestartInProgress(RuntimeError):
    """Do not restore configuration or start a second control process yet."""


def ensure_no_restart_in_progress():
    lock=Path(BIN).parent/'var/start-script-lock/pid'
    if not lock.is_file():return
    try:pid=int(lock.read_text().strip())
    except (ValueError,OSError) as error:
        raise RuntimeError('Cannot inspect Wazuh control lock; inspect '+str(lock)) from error
    if pid<=0:raise RuntimeError('Invalid Wazuh control lock PID.')
    try:os.kill(pid,0)
    except ProcessLookupError:return
    except PermissionError:pass
    raise ManagerRestartInProgress('Wazuh control is still running (PID '+str(pid)+'). '
                                   'No configuration change or second restart is allowed until it exits.')


def restart_manager(timeout=240,redactions=()):
    """Wait for the control PID, not EOF on pipes inherited by daemon children.

    A private regular file captures output. A true timeout leaves the validated
    candidate in place: restoring files while the first restart is still active
    could make that process read a mixture of old/new configuration.
    """
    import tempfile
    ensure_no_restart_in_progress()
    folder=Path(BIN).parent/'logs';folder.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='soc-setup-restart-',suffix='.log',dir=folder)
    log=Path(name)
    def show_output():
        with log.open('rb') as reader:output=reader.read(256*1024).decode(errors='replace')
        for value in redactions:
            if value:output=output.replace(value,'[REDACTED]')
        print(output,flush=True)
    print('WAZUH_RESTART_BEGIN: timeout='+str(timeout)+'s; private output='+str(log),flush=True)
    with os.fdopen(fd,'wb',buffering=0) as writer:
        process=subprocess.Popen([BIN+'wazuh-control','restart'],stdin=subprocess.DEVNULL,
                                 stdout=writer,stderr=subprocess.STDOUT)
        started=time.monotonic();next_notice=started+10
        try:
            while process.poll() is None:
                elapsed=time.monotonic()-started
                if elapsed>=timeout:
                    show_output()
                    raise ManagerRestartInProgress('Restart control PID '+str(process.pid)+' is still running after '
                        +str(timeout)+'s. Candidate configuration retained; no rollback or second restart was launched. '
                        'Inspect control status and private log '+str(log))
                if time.monotonic()>=next_notice:
                    print('WAZUH_RESTART_WAITING: '+str(int(elapsed))+'s / '+str(timeout)+'s',flush=True)
                    next_notice=time.monotonic()+10
                time.sleep(min(1,max(0,timeout-elapsed)))
        except BaseException as error:
            if process.poll() is None and not isinstance(error,ManagerRestartInProgress):
                raise ManagerRestartInProgress('Restart interrupted while control PID '+str(process.pid)
                    +' is still running. Candidate retained; no second restart launched. Private log '+str(log)) from error
            raise
        show_output()
        if process.returncode:
            raise RuntimeError('wazuh-control restart exited with '+str(process.returncode)+'; private log '+str(log))
    print('WAZUH_RESTART_COMPLETED',flush=True)


def matched_rule_ids(output):
    """Read selected rules only from Phase 3, never decoded JSON field names.

    Legacy prints ``Rule id``; modern logtest prints ``id``. Searching for an
    unanchored ``id:`` also matches signature_id, event_id and Phase 2's id.
    """
    phase=None
    matched=[]
    for line in output.splitlines():
        header=re.match(r'\s*\*\*Phase\s+(\d+):',line)
        if header:
            phase=int(header.group(1))
            continue
        if phase==3:
            rule=re.fullmatch(r"\s*(?:Rule\s+)?id:\s*'(\d+)'\s*",line)
            if rule:matched.append(rule.group(1))
    return matched


class RuleCheck:
    def __init__(self, lines, expected_ids):
        self.lines = lines.encode() if isinstance(lines, str) else lines
        self.expected = [str(value) for value in expected_ids]
        self.backend = None
        self.validated = False

    def _match(self, output):
        matched = matched_rule_ids(output)
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
