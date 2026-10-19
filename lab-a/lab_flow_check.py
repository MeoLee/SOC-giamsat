"""Small, read-only lab capture adapter for the existing SOC-AI-v0.2 predictor.

Run from the project directory. Does not change sensors, training, or weights.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

EVE = '/var/log/suricata/eve.json'


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, check=False)
    if result.returncode:
        error = result.stderr.decode('utf-8', errors='replace').strip()
        output = result.stdout.decode('utf-8', errors='replace').strip()
        command = subprocess.list2cmdline(['docker', *args])
        raise RuntimeError(f'Docker command failed\nCOMMAND: {command}\n'
                           f'EXIT CODE: {result.returncode}\n'
                           f'STDERR: {error or "(empty)"}\n'
                           f'STDOUT: {output or "(empty)"}')
    return result.stdout


def identity(container):
    state = json.loads(docker('inspect', container, '--format', '{{json .State}}'))
    if not state.get('Running'):
        raise RuntimeError('Ubuntu container is not running')
    return state['StartedAt']


def file_stat(container):
    inode, size = docker('exec', container, 'stat', '-Lc', '%i %s', EVE).split()
    return int(inode), int(size)


def time_value(value):
    t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if t.tzinfo is None:
        raise ValueError('Timestamp has no timezone')
    return t.astimezone(timezone.utc)


def write_json(path, value):
    # Unique session/result directories: no concurrent dashboard status writes.
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def start(a):
    root = a.session.resolve()
    if root.exists():
        raise ValueError('Session directory already exists; choose a new name')
    started = identity(a.container)
    # Linux comm may be a renamed main-thread name. Match argv[0] instead,
    # anchored so an unrelated shell/grep command cannot count as the sensor.
    docker('exec', a.container, 'pgrep', '-f',
           r'^([^[:space:]]*/)?suricata([[:space:]]|$)')
    sensor_second = int(docker('exec', a.container, 'date', '-u', '+%s').strip())
    inode, size = file_stat(a.container)
    boundary = True
    if size:
        byte = docker('exec', a.container, 'dd', 'if=' + EVE, 'bs=1',
                      'skip=' + str(size - 1), 'count=1', 'status=none')
        if len(byte) != 1:
            raise RuntimeError('Log changed during start; try again')
        boundary = byte == b'\n'
    if identity(a.container) != started or file_stat(a.container)[0] != inode:
        raise RuntimeError('Container/log changed during start; try again')
    root.mkdir(parents=True)
    marker = {'version': 'lab-flow-check/0.1', 'container': a.container,
              'container_started_at': started, 'path': EVE, 'inode': inode,
              'offset': size, 'at_line_boundary': boundary,
              'start_time': datetime.fromtimestamp(sensor_second, timezone.utc).isoformat(),
              'context': a.context, 'endpoints': a.endpoints,
              'context_is_not_a_training_label': True}
    write_json(root / 'session.json', marker)
    print('READY: run ONLY the intended lab activity now.', flush=True)
    print('Session:', root, flush=True)
    print('Close SSH sessions, then wait for flow timeout before finish.', flush=True)


def capture(marker, target):
    container = marker['container']
    if identity(container) != marker['container_started_at']:
        raise RuntimeError('Container restarted; start a new session')
    inode, size = file_stat(container)
    if inode != marker['inode'] or size < marker['offset']:
        raise RuntimeError('Log rotated/truncated; start a new session')
    expected = size - marker['offset']
    with target.open('xb') as out, target.with_suffix('.stderr').open('xb') as err:
        result = subprocess.run([
            'docker', 'exec', container, 'dd', 'if=' + EVE,
            'iflag=skip_bytes,count_bytes', 'bs=1048576',
            'skip=' + str(marker['offset']), 'count=' + str(expected), 'status=none'
        ], stdout=out, stderr=err, check=False)
    if result.returncode:
        raise RuntimeError('Snapshot failed: ' + target.with_suffix('.stderr').read_text(errors='replace'))
    after_inode, after_size = file_stat(container)
    if (identity(container) != marker['container_started_at'] or
            inode != after_inode or after_size < size or target.stat().st_size != expected):
        raise RuntimeError('Snapshot changed or incomplete; start a new session')


def select_flows(snapshot, output, marker):
    counts = Counter()
    endpoints = set(marker['endpoints'])
    since = time_value(marker['start_time'])
    with snapshot.open('rb') as source, output.open('x', encoding='utf-8', newline='\n') as out:
        for number, line in enumerate(source, 1):
            if number == 1 and not marker['at_line_boundary']:
                counts['initial_fragment_excluded'] += 1
                continue
            if not line.endswith(b'\n'):
                counts['unfinished_last_line_excluded'] += 1
                continue
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if event.get('event_type') != 'flow':
                    counts['non_flow_events'] += 1
                    continue
                if {event.get('src_ip'), event.get('dest_ip')} != endpoints:
                    counts['other_endpoints'] += 1
                    continue
                if time_value(event['flow']['start']) < since:
                    counts['flows_started_before_session'] += 1
                    continue
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f'Invalid complete event at snapshot line {number}: {exc}') from exc
            event['record_id'] = f"lab:{output.parent.parent.name}:{number}"
            out.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + '\n')
            counts['selected_flows'] += 1
    return counts


def summarize(path):
    decisions, labels, reasons = Counter(), Counter(), Counter()
    with path.open(encoding='utf-8') as source:
        for line in source:
            item = json.loads(line)
            decisions[item['decision']] += 1
            if 'predicted_label' in item:
                labels[item['predicted_label']] += 1
            if 'reason' in item:
                reasons[item['reason']] += 1
    total = sum(decisions.values())
    eligible = total - decisions['out_of_training_scope']
    return {'decisions': dict(decisions), 'predicted_labels': dict(labels),
            'out_of_scope_reasons': dict(reasons), 'total_flows': total,
            'in_scope_flows': eligible,
            'coverage_fraction': eligible / total if total else None,
            'possible_attack_fraction_in_scope': decisions['possible_attack'] / eligible if eligible else None,
            'accuracy_not_computed': 'Session context is not a verified label for every flow'}


def finish(a):
    root = a.session.resolve()
    marker = json.loads((root / 'session.json').read_text(encoding='utf-8'))
    model = a.model.resolve()
    project = Path(__file__).resolve().parent
    if not (project / 'soc_ai' / 'predict.py').is_file():
        raise ValueError('Place lab_flow_check.py in the SOC-AI-v0.2 project directory')
    run = root / ('capture-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    run.mkdir()
    snapshot = run / 'eve-slice.jsonl'
    capture(marker, snapshot)
    counts = select_flows(snapshot, run / 'flows.jsonl', marker)
    print('CAPTURE:', dict(counts), flush=True)
    if not counts['selected_flows']:
        print('NO_FLOWS: check eve.json flow output, close SSH, wait longer, then repeat finish.')
        print('No model prediction or accuracy claim was made.')
        return 2
    command = [sys.executable, '-m', 'soc_ai', 'predict', '--model', str(model),
               '--input', str(run / 'flows.jsonl'), '--output', str(run / 'predictions.jsonl'),
               '--device', 'cpu']
    result = subprocess.run(command, cwd=project, check=False)
    if result.returncode:
        raise RuntimeError('Existing predictor failed; inspect its error above')
    report = {'version': 'lab-flow-check/0.1', 'complete': True,
              'session': marker, 'model_directory': str(model),
              'capture_counts': dict(counts), **summarize(run / 'predictions.jsonl')}
    write_json(run / 'summary.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print('RESULT:', run, flush=True)
    print('Repeated finish re-reads this session. Do not merge captures as independent samples.')
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    begin = sub.add_parser('start')
    begin.add_argument('--session', type=Path, required=True)
    begin.add_argument('--container', default='ubuntu-endpoint')
    begin.add_argument('--context', default='normal-ssh')
    begin.add_argument('--endpoints', nargs=2, default=['172.20.0.3', '172.20.0.4'])
    end = sub.add_parser('finish')
    end.add_argument('--session', type=Path, required=True)
    end.add_argument('--model', type=Path, required=True)
    a = p.parse_args()
    try:
        if a.command == 'start':
            start(a)
            return 0
        return finish(a)
    except (OSError, ValueError, RuntimeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
