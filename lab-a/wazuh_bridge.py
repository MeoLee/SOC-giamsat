"""Durable, bounded delivery of summaries to a manager-local JSON log.

Delivery acknowledgement means appended to the manager log, not indexed.
Retries use a stable event_id. Transport is at-least-once; an ambiguous timeout
can cause a duplicate. Never use the output as a training label.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time

LOG_PATH = '/var/ossec/logs/soc-ai/events.jsonl'
WRITE_SCRIPT = r'''
set -eu
test -f /var/ossec/logs/soc-ai/bridge-ready.json
test -f /var/ossec/logs/soc-ai/events.jsonl
line=$(cat)
if ! grep -Fq -- "\"event_id\":\"$1\"" /var/ossec/logs/soc-ai/events.jsonl; then
    printf '%s\n' "$line" >> /var/ossec/logs/soc-ai/events.jsonl
fi
printf 'SOC_AI_APPENDED:%s\n' "$1"
'''


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))


def event_id(identity):
    return hashlib.sha256(encoded(identity).encode()).hexdigest()


def make_event(kind, identity, **fields):
    return {'soc_ai_producer': 'soc-ai-live', 'schema_version': 'soc-ai-wazuh/0.1',
            'event_id': event_id(identity), 'soc_ai_kind': kind,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'experimental': True, 'prediction_is_not_ground_truth': True, **fields}


class Publisher:
    def __init__(self, path, manager, sender=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = self.path.with_suffix('.lock').open('a+b')
        self.lock.seek(0)
        try:
            import os
            if os.name == 'nt':
                import msvcrt
                self.lock.write(b'0'); self.lock.flush(); self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            raise RuntimeError('Another Wazuh publisher uses this outbox; stop the previous watcher') from exc
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS delivery (id TEXT PRIMARY KEY, manager TEXT NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)')
        self.db.commit()
        self.manager = manager
        self.sender = sender or self.send
        self.last_error = None
        self.next_retry = 0

    def enqueue(self, event):
        if self.pending >= 10000:
            raise RuntimeError('Wazuh outbox has 10000 pending summaries. Raw logs and activities preserved; repair delivery before continuing.')
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO delivery(id,manager,payload) VALUES (?,?,?)',
                            (event['event_id'], self.manager, encoded(event)))

    @property
    def pending(self):
        return self.db.execute('SELECT COUNT(*) FROM delivery WHERE delivered=0').fetchone()[0]

    def send(self, manager, payload, eid):
        # Program and paths are fixed. JSON is stdin, never interpolated as code.
        result = subprocess.run(['docker', 'exec', '-i', '--user', '0', manager, 'sh', '-c', WRITE_SCRIPT,
                                 'soc-ai-write', eid], input=(payload+'\n').encode(),
                                capture_output=True, timeout=5)
        if result.returncode or result.stdout.strip() != ('SOC_AI_APPENDED:'+eid).encode():
            raise RuntimeError('Manager append failed: '+result.stderr.decode(errors='replace')[:500])

    def flush(self, limit=4, force=False):
        if not force and time.monotonic() < self.next_retry:
            return
        for eid, manager, payload in self.db.execute(
                'SELECT id,manager,payload FROM delivery WHERE delivered=0 ORDER BY rowid LIMIT ?', (limit,)).fetchall():
            try:
                self.sender(manager, payload, eid)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                self.last_error = str(exc)
                self.next_retry = time.monotonic()+15
                return
            with self.db:
                self.db.execute('UPDATE delivery SET delivered=1 WHERE id=?', (eid,))
            self.last_error = None

    def close(self):
        self.db.close()
        self.lock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--outbox', type=Path, required=True)
    p.add_argument('--manager', default='single-node-wazuh.manager-1')
    p.add_argument('--smoke-test', action='store_true')
    p.add_argument('--verify-alert', action='store_true', help='Wait up to 30 seconds for the smoke event in alerts.json')
    a = p.parse_args()
    if a.verify_alert and not a.smoke_test:
        p.error('--verify-alert requires --smoke-test')
    pub = Publisher(a.outbox, a.manager)
    try:
        if a.smoke_test:
            smoke = make_event('connection_test', ['connection_test', time.time_ns()],
                               activity='AI to Wazuh connection test')
            pub.enqueue(smoke)
        while pub.pending:
            before = pub.pending
            pub.flush(limit=10, force=True)
            if pub.pending == before:
                print('PENDING:', pub.pending, 'ERROR:', pub.last_error)
                return 1
        print('WAZUH_LOG_APPEND_OK; verify the generated rule in manager alerts.json')
        if a.verify_alert:
            deadline = time.monotonic()+30
            while time.monotonic() < deadline:
                result = subprocess.run(['docker', 'exec', a.manager, 'tail', '-n', '3000',
                    '/var/ossec/logs/alerts/alerts.json'], capture_output=True, timeout=5)
                if result.returncode:
                    print('Cannot read manager alerts:', result.stderr.decode(errors='replace'))
                    return 1
                for line in result.stdout.splitlines():
                    try: alert = json.loads(line)
                    except (ValueError, TypeError): continue
                    if alert.get('data', {}).get('event_id') == smoke['event_id']:
                        if str(alert.get('rule', {}).get('id')) != '119201':
                            print('Unexpected rule:', alert.get('rule'))
                            return 1
                        print('WAZUH_ALERT_VERIFIED rule.id=119201 event_id='+smoke['event_id'])
                        return 0
                time.sleep(2)
            print('NOT VERIFIED: event appended, but rule 119201 was not found within 30 seconds.')
            return 1
        return 0
    finally:
        pub.close()


if __name__ == '__main__':
    raise SystemExit(main())
