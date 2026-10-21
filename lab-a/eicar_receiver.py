"""Receive only the standard 68-byte EICAR test file over an actual SSH stream.

Controlled exercise instrumentation, not general SCP auditing or malware execution.
The root-owned receiver records SSH_CONNECTION and verifies bytes before writing.
"""
import argparse
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys

from endpoint_probe import ssh_context, now, record, LOG_PATH
from vt_lab_artifact import EICAR_SHA256, EICAR_MD5

DIRECTORY = '/var/lib/soc-lab/fim'


def receive(token, stream, log_path=LOG_PATH, directory=DIRECTORY):
    context = ssh_context(token)
    started = now()
    payload = stream.read(69)
    if len(payload) != 68 or hashlib.sha256(payload).hexdigest() != EICAR_SHA256:
        raise ValueError('Only the exact 68-byte standard EICAR test file is accepted')
    folder = Path(directory)
    if any(p.is_symlink() for p in (folder, *folder.parents)):
        raise ValueError('Symlink receiver directory refused')
    dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(dfd).st_uid != 0:
            raise ValueError('The FIM directory must be root-owned; run setup_scenario_fim.py')
        name = 'vt-eicar-' + token + '.txt'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o640, dir_fd=dfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('Regular destination required')
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(payload); output.flush(); os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    event = {**context, 'kind': 'file.eicar_received', 'started_at': started,
        'event_time': now(), 'returncode': 0, 'artifact_path': str(folder / name),
        'artifact_bytes': 68, 'artifact_sha256': EICAR_SHA256, 'artifact_md5': EICAR_MD5,
        'payload_verified': True, 'transfer_method': 'ssh_stdin_fixed_eicar_receiver',
        'test_artifact': True, 'executed': False}
    record(log_path, event)
    print('EICAR_RECEIVED_VERIFIED path=' + event['artifact_path'] + ' sha256=' + EICAR_SHA256)
    return event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    # EOF is required to reject extra bytes. Bound a stalled SSH sender.
    signal.signal(signal.SIGALRM, lambda *_: sys.exit('Receiver timed out; inspect raw evidence'))
    signal.alarm(15)
    receive(args.token, sys.stdin.buffer)
    signal.alarm(0)


if __name__ == '__main__': main()
