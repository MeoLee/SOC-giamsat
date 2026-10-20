"""Read-only checks for the selected Lab A configuration and model bundle."""
import argparse
import json
from pathlib import Path
import stat
import subprocess
import sys

from live_config import load_config


def diagnose(config_path, model=None, runtime=False, bridge=False, runner=None):
    runner = runner or subprocess.run
    checks = []

    def check(name, action):
        try:
            detail = action()
            checks.append({'name': name, 'passed': True, 'detail': detail})
            return detail
        except (OSError, ValueError, RuntimeError, TypeError, KeyError,
                subprocess.SubprocessError, ImportError) as exc:
            checks.append({'name': name, 'passed': False, 'error': str(exc)})
            return None

    config = check('configuration', lambda: load_config(config_path))
    if config is not None:
        # Report only the configuration summary, not arbitrary user fields.
        checks[-1]['detail'] = {'source_count': len(config['sources']),
                               'asset_count': len(config['correlation']['assets']),
                               'wazuh_manager': config['wazuh_manager']}

    def verify_model():
        from soc_ai.predict import Predictor
        predictor = Predictor(model, 'cpu')
        return {'directory': str(Path(model).resolve()),
                'weights_sha256': predictor.metadata['weights_sha256'],
                'feature_hash': predictor.metadata['feature_hash'],
                'max_probability_difference': predictor.verify(),
                'accuracy_established_by_this_check': False}

    if model is not None:
        check('model_bundle_and_golden_vectors', verify_model)

    def docker(arguments):
        result = runner(['docker', *arguments], capture_output=True, timeout=15)
        if result.returncode:
            message = result.stderr.decode(errors='replace').strip()
            raise RuntimeError(message or f'Docker exited {result.returncode}')
        return result.stdout.decode(errors='replace').strip()

    if config is not None and runtime:
        for source in config['sources']:
            def source_stat(source=source):
                # GNU stat calls zero-byte files "regular empty file" in %F.
                # Use the numeric inode mode, independent of size and locale.
                value = docker(['exec', source['container'], 'stat', '-Lc', '%f|%d|%i|%s', '--', source['path']])
                mode, device, inode, size = value.split('|')
                if not stat.S_ISREG(int(mode, 16)):
                    raise ValueError('Log source is not a regular file')
                return {'container': source['container'], 'path': source['path'],
                        'device': device, 'inode': inode, 'bytes': int(size),
                        'activity_or_capture_coverage_established': False}
            check('source:' + source['output'], source_stat)
        for sensor in sorted({s['container'] for s in config['sources'] if s['kind'] == 'eve'}):
            check('suricata_process:' + sensor, lambda sensor=sensor:
                  docker(['exec', sensor, 'pgrep', '-f', r'^([^[:space:]]*/)?suricata([[:space:]]|$)']))
            from lab_recon import SENSOR_RULE_CHECK
            check('recon_collection_rule:' + sensor,lambda sensor=sensor:
                  json.loads(docker(['exec',sensor,'python3','-c',SENSOR_RULE_CHECK])))
        if bridge:
            def bridge_ready():
                ready = json.loads(docker(['exec', config['wazuh_manager'], 'cat',
                                          '/var/ossec/logs/soc-ai/bridge-ready.json']))
                if not isinstance(ready, dict) or ready.get('version') != 'soc-ai-wazuh/0.1':
                    raise ValueError('Unsupported bridge installation')
                if config['correlation'].get('attack_chain_enabled') and not {119212,119213,119214} <= set(ready.get('rule_ids',[])):
                    raise ValueError('Install the 0.4.8 bridge rules before starting chain Live: python setup_wazuh.py --manager '+config['wazuh_manager'])
                return {'installation_version': ready['version'],
                        'append_alert_index_delivery_established': False}
            check('bridge_installation_marker', bridge_ready)
    report = {'schema_version': 'soc-lab-doctor/0.1',
              'requested': {'model': model is not None, 'runtime': runtime, 'bridge': bridge},
              'checks_passed': bool(checks) and all(c['passed'] for c in checks),
              'lab_end_to_end_verified': False, 'checks': checks}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('live-config.json'))
    parser.add_argument('--model', type=Path)
    parser.add_argument('--runtime', action='store_true', help='Read Docker files/processes; does not install or restart services')
    parser.add_argument('--bridge', action='store_true', help='Read bridge marker; requires --runtime')
    parser.add_argument('--output', type=Path, help='Optional local JSON report')
    args = parser.parse_args()
    if args.bridge and not args.runtime:
        parser.error('--bridge requires --runtime')
    report = diagnose(args.config, args.model, args.runtime, args.bridge)
    if args.output:
        from soc_ai.common import write_json
        write_json(args.output, report)
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if report['checks_passed'] else 2


if __name__ == '__main__':
    sys.exit(main())
