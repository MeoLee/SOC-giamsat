"""Read-only diagnosis of the recon installer's isolated PCAP validation.

Requires the installed 0.4.4 source beside this file. Never replaces the live
rule file, signals Suricata, restarts containers, or generates network traffic.
The JSON is diagnostic evidence, not an installation or live-capture verdict.
"""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def summarize(events):
    groups = {}
    for source, expected, ports in (
        ('198.51.100.20', 32, set(range(1, 33))),
        ('198.51.100.30', 33, {80}),
        ('198.51.100.40', 24, {22}),
    ):
        rows = [e for e in events if e.get('event_type') == 'alert'
                and str(e.get('alert', {}).get('signature_id')) == '9900003'
                and e.get('src_ip') == source]
        connections = Counter((str(e.get('flow_id')), e.get('src_port'),
                               e.get('dest_port')) for e in rows)
        actual_ports = {e.get('dest_port') for e in rows}
        groups[source] = {
            'expected_connections': expected,
            'observed_alert_records': len(rows),
            'unique_connections': len(connections),
            'destination_ports': sorted(p for p in actual_ports if isinstance(p, int)),
            'missing_destination_ports': sorted(ports - actual_ports),
            'alert_sources': dict(Counter(str(e['alert'].get('source')) for e in rows)),
            'count_and_ports_match': len(rows) == expected and actual_ports == ports,
            'repeated_connections': [
                {'flow_id': key[0], 'source_port': key[1],
                 'destination_port': key[2], 'alert_records': count}
                for key, count in connections.most_common(5) if count > 1],
            'sample_alerts': [{key: e.get(key) for key in
                               ('timestamp', 'flow_id', 'src_port', 'dest_port', 'pcap_cnt')}
                              for e in rows[:3]],
        }
    return {
        'schema_version': 'soc-recon-pcap-diagnostic/0.1',
        'groups': groups,
        'all_counts_and_ports_match': all(g['count_and_ports_match'] for g in groups.values()),
        'alert_rule_counts': dict(Counter(str(e['alert'].get('signature_id'))
                                         for e in events if e.get('event_type') == 'alert')),
    }


def remote_diagnose(payload):
    if os.geteuid() != 0:
        raise RuntimeError('Run diagnostic as root inside the sensor container')
    processes = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            args = [os.fsdecode(x) for x in path.read_bytes().split(b'\0') if x]
        except OSError:
            continue
        if args and Path(args[0]).name == 'suricata':
            processes.append(args)
    if len(processes) != 1:
        raise RuntimeError('Expected exactly one live Suricata process')
    args = processes[0]
    if '-S' not in args or '-c' not in args:
        raise RuntimeError('Expected existing -S rules and -c YAML startup options')
    rules = Path(args[args.index('-S') + 1]); yaml = args[args.index('-c') + 1]
    before = rules.read_bytes()
    namespace = {}
    exec(compile(payload['installer'], 'setup_recon.py', 'exec'), namespace)
    candidate_text = namespace['merge_rules'](before.decode('utf-8'), payload['rules'])
    with tempfile.TemporaryDirectory(prefix='soc-recon-diagnostic-') as folder:
        root = Path(folder)
        candidate = root / 'candidate.rules'; candidate.write_text(candidate_text)
        pcap = root / 'controls.pcap'; pcap.write_bytes(base64.b64decode(payload['pcap'], validate=True))
        commands = []
        for extra in (['-T'], ['--runmode', 'single', '-r', str(pcap), '-k', 'none',
                               '--set', 'unix-command.enabled=no']):
            result = subprocess.run([args[0], '--init-errors-fatal', '-c', yaml,
                                     '-S', str(candidate), '-l', str(root), *extra],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            commands.append({'returncode': result.returncode,
                             'engine_output': result.stdout.decode(errors='replace')[-6000:]})
            if result.returncode:
                break
        events = []; outputs = {}; invalid = 0
        for path in sorted(root.glob('eve*.json')):
            rows = []
            for line in path.read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    invalid += 1
            events.extend(rows)
            outputs[path.name] = dict(Counter(str(e['alert'].get('signature_id'))
                                               for e in rows if e.get('event_type') == 'alert'))
        report = summarize(events)
        report.update({'commands': commands, 'eve_files_alert_counts': outputs,
                       'invalid_json_lines': invalid, 'live_rule_sha256': hashlib.sha256(before).hexdigest(),
                       'live_rules_unchanged': rules.read_bytes() == before,
                       'reload_requested': False, 'diagnostic_only': True})
        print('RECON_DIAGNOSTIC_JSON:' + json.dumps(report, sort_keys=True), flush=True)
        if not report['live_rules_unchanged']:
            raise RuntimeError('Live rule file changed concurrently during the diagnostic')
        if len(commands) != 2 or any(c['returncode'] for c in commands):
            raise RuntimeError('Suricata diagnostic command failed; inspect the JSON report')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', default='ubuntu-endpoint')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    from live_config import container_name
    from setup_recon import test_pcap
    container_name(args.container)
    root = Path(__file__).resolve().parent
    installer = (root / 'setup_recon.py').read_text().rsplit("\nif __name__=='__main__':", 1)[0]
    payload = {'installer': installer, 'rules': (root / 'soc-recon.rules').read_text(),
               'pcap': base64.b64encode(test_pcap()).decode('ascii')}
    script = Path(__file__).read_text().rsplit("\nif __name__ == '__main__':", 1)[0]
    script += '\nremote_diagnose(json.load(sys.stdin))\n'
    result = subprocess.run(['docker', 'exec', '-i', '--user', '0', args.container,
                             'python3', '-c', script], input=json.dumps(payload).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
    output = result.stdout.decode(errors='replace')
    marker = 'RECON_DIAGNOSTIC_JSON:'
    reports = [line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    if reports:
        report = json.loads(reports[-1])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        print('REPORT:', args.output)
    else:
        print(output)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
