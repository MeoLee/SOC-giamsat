"""Package all tracked Lab A files, including HTML assets, and optional repair ZIP.

Stage new source files first. Never select application assets by suffix: omitting
dashboard.html previously broke the installed dashboard while checkout tests passed.
"""
import argparse
from datetime import date
import hashlib
from pathlib import Path
import subprocess
import zipfile


REQUIRED = {'syn_load_detection.py','test_syn_load.py','docs/SYN-HTTP-FLOOD-0413-VI.md','dvwa_web_flood.py','http_load_detection.py','test_web_flood.py','docs/WEB-FLOOD-DVWA-0412-VI.md','docs/validation-0412.json',
            'eicar_receiver.py','lab_file_chain.py','test_file_chain.py','docs/EICAR-CHAIN-0411-VI.md','docs/validation-0411.json',
            'test_restart_control.py', 'docs/VT-RESTART-FIX-04102-VI.md',
            'docs/validation-04102.json', 'docs/WAZUH-LOGTEST-PARSER-FIX-04101-VI.md', 'docs/validation-04101.json', 'setup_virustotal.py', 'vt_lab_artifact.py', 'test_severity_virustotal.py',
            'docs/SEVERITY-POLICY-0410-VI.md', 'docs/VIRUSTOTAL-01-VI.md', 'docs/validation-0410.json', 'test_chain_retention.py', 'docs/CHAIN-RETENTION-0492-VI.md',
            'docs/validation-0492.json', 'wazuh_install_checks.py', 'test_wazuh_install_checks.py',
            'docs/WAZUH-INSTALLER-FIX-0491-VI.md', 'docs/validation-0491.json', 'soc_ai/web/dashboard.html', 'soc_ai/predict.py', 'soc_ai/train.py',
            'run_checks.py', 'Setup-AI.ps1', 'test_context_runtime.py',
            'lab_recon.py', 'setup_recon.py', 'soc-recon.rules', 'test_lab_recon.py',
            'chain_dashboard.py', 'test_chain_dashboard.py',
            'chain_profile.py', 'test_chain_profile.py', 'docs/CHAIN-PROFILE-VI.md',
            'dashboards/soc-ai-attack-chain.ndjson',
            'dashboards/soc-ai-chain-investigation.ndjson',
            'dashboards/soc-ai-chain-investigation-shard-fix.ndjson',
            'endpoint_probe.py', 'lab_endpoint.py', 'lab_transfer_server.py',
            'setup_chain_telemetry.py', 'chain_exercise.py', 'test_lab_endpoint.py',
            'lab_campaign.py', 'bounded_http_load.py', 'chain_scenarios.py', 'chain_trace.py',
            'chain_unified.py', 'setup_attack_chains.py', 'manage_chain_dashboards.py',
            'test_lab_campaign.py', 'test_chain_unified.py',
            'lab_chain_episode.py', 'chain_graph.py', 'manual_chain_review.py',
            'Start-SOC-Monitor.ps1', 'Install-Kali-Tools.ps1', 'dvwa_cli.py',
            'setup_scenario_fim.py', 'setup_scenario_rules.py', 'soc_scenario_rules.xml',
            'scenario_readiness.py', 'scenario_artifact.py', 'test_chain_episodes.py',
            'test_scenario_research.py', 'test_dvwa_cli.py',
            'docs/SCENARIO-RESEARCH-049-VI.md', 'docs/scenarios-049/00-PREPARE-VI.md',
            'docs/scenarios-049/01-SINGLE-ACTIONS-VI.md', 'docs/scenarios-049/02-ATTACK-CHAINS-VI.md',
            'docs/scenarios-049/validation.json', 'docs/scenarios-049/graph-validation.png',
            'docs/ATTACK-CHAINS-048-VI.md', 'docs/validation-048.json', 'dashboards/soc-ai-attack-chain-unified.ndjson'}


def tracked_source(repo):
    data = subprocess.check_output(['git', 'ls-files', '-z', '--', 'lab-a'], cwd=repo)
    root = repo / 'lab-a'; files = {}
    for raw in data.decode('utf-8').split('\0'):
        if not raw:
            continue
        path = repo / raw; relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing/non-regular tracked source: ' + raw)
        if path.suffix in ('.pyc', '.npz', '.pt', '.sqlite', '.pem', '.key', '.jsonl', '.rar', '.zip'):
            raise ValueError('Runtime/private artifact tracked as source: ' + raw)
        if set(path.relative_to(root).parts) & {'__pycache__', '.venv', 'raw', 'runs', 'evidence', 'reviewed', 'benchmarks'}:
            raise ValueError('Runtime directory tracked as source: ' + raw)
        if relative != 'SHA256SUMS.txt':
            files[relative] = path.read_bytes()
    if REQUIRED - files.keys():
        raise ValueError('Required packaged assets missing: ' + str(sorted(REQUIRED - files.keys())))
    sums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                   for name, data in sorted(files.items()))
    (root / 'SHA256SUMS.txt').write_text(sums, encoding='utf-8', newline='\n')
    files['SHA256SUMS.txt'] = sums.encode('utf-8')
    return files


def write_archive(output, files, prefix, day):
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(prefix + name, date_time=(day.year, day.month, day.day, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError('Release CRC verification failed')
        if set(archive.namelist()) != {prefix + name for name in files}:
            raise ValueError('Release manifest differs from packaged paths')
        for name, content in files.items():
            if archive.read(prefix + name) != content:
                raise ValueError('Release content mismatch: ' + name)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(digest + '  ' + output.name + '\n')
    print(f'{output.name}: {len(files)} files, {output.stat().st_size} bytes, SHA256={digest}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--date', default='2026-10-19')
    parser.add_argument('--patch-base', type=Path)
    parser.add_argument('--patch-output', type=Path)
    args = parser.parse_args()
    if bool(args.patch_base) != bool(args.patch_output):
        parser.error('--patch-base and --patch-output must be used together')
    repo = Path(__file__).resolve().parent.parent
    files = tracked_source(repo); prefix = 'SOC-AI-v0.4-research/'
    day = date.fromisoformat(args.date)
    write_archive(args.output, files, prefix, day)
    if args.patch_base:
        with zipfile.ZipFile(args.patch_base) as archive:
            original = {name[len(prefix):]: archive.read(name) for name in archive.namelist()
                        if name.startswith(prefix) and not name.endswith('/')}
        changed = {name: data for name, data in files.items() if original.get(name) != data}
        if not changed:
            raise ValueError('No changed or missing files to repair')
        write_archive(args.patch_output, changed, '', day)


if __name__ == '__main__':
    main()
