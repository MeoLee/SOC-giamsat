"""Install an additive manager-local JSON input and dedicated AI rules.

Run on the Windows host using the inference environment. Configuration is
validated before restarting Wazuh. A private persistent backup is kept, and on
validation/restart failure the changed configuration is restored from memory.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from wazuh_install_checks import RuleCheck, embedded_support, restart_manager, ensure_no_restart_in_progress, ManagerRestartInProgress

LOCATION = '/var/ossec/logs/soc-ai/events.jsonl'
RULE_PATH = '/var/ossec/etc/rules/soc_ai_bridge_rules.xml'
MARKER = 'SOC-AI MANAGED'


def config_update(text):
    # Wazuh allows more than one ossec_config root; wrap for inspection only.
    clean = re.sub(r'<\?xml[^>]*\?>', '', text)
    root = ET.fromstring('<document>'+clean+'</document>')
    found = [f for f in root.iter('localfile') if (f.findtext('location') or '').strip() == LOCATION]
    if len(found) > 1:
        raise ValueError('Duplicate AI localfile entries; resolve before installation')
    if found:
        if (found[0].findtext('log_format') or '').strip() != 'json':
            raise ValueError('Existing AI localfile has wrong log_format')
        return text
    snippet = ('\n  <!-- SOC-AI MANAGED: JSON input -->\n  <localfile>\n'
               '    <log_format>json</log_format>\n    <location>'+LOCATION+'</location>\n'
               '  </localfile>\n')
    # The inserted element is a sibling of client/global, never inside client.
    if '</ossec_config>' not in text:
        raise ValueError('ossec_config closing tag missing')
    for token in re.finditer(r'<!--.*?-->|</ossec_config>', text, re.DOTALL):
        if token.group() == '</ossec_config>':
            return text[:token.start()]+snippet+text[token.start():]
    raise ValueError('Real ossec_config closing tag missing')


def check_collisions(rules_text, existing):
    ids = {r.attrib['id'] for r in ET.fromstring(rules_text).iter('rule')}
    for path, text in existing.items():
        if path == RULE_PATH:
            if MARKER not in text and text != rules_text:
                raise ValueError('AI rule filename already contains unmanaged content')
            continue
        used = set(re.findall(r'<rule\s+[^>]*\bid\s*=\s*[\"\x27](\d+)[\"\x27]', text))
        if used & ids:
            raise ValueError('Rule ID collision in '+path+': '+','.join(sorted(used & ids)))


def install_remote(payload):
    """Executed inside the manager; imported dependencies are standard library."""
    import grp
    import os
    import tempfile
    import time
    ensure_no_restart_in_progress()
    config = Path('/var/ossec/etc/ossec.conf')
    rules = Path(RULE_PATH)
    old_config = config.read_bytes()
    old_rule = rules.read_bytes() if rules.exists() else None
    updated = config_update(old_config.decode('utf-8-sig')).encode()
    texts = {str(p): p.read_text(encoding='utf-8-sig') for p in Path('/var/ossec/etc').glob('**/*.xml')}
    check_collisions(payload['rules'], texts)
    group = grp.getgrnam('wazuh').gr_gid
    logdir = Path(LOCATION).parent
    logdir.mkdir(parents=True, exist_ok=True)
    os.chown(logdir, 0, group); os.chmod(logdir, 0o750)
    log = Path(LOCATION)
    log.touch(exist_ok=True); os.chown(log, 0, group); os.chmod(log, 0o640)
    ready = logdir/'bridge-ready.json'
    old_ready = ready.read_bytes() if ready.exists() else None
    backup = Path('/var/ossec/backup')/('soc-ai-'+str(time.time_ns()))
    backup.mkdir(parents=True,mode=0o700,exist_ok=False)
    for name,data in [('ossec.conf',old_config),('soc_ai_bridge_rules.xml',old_rule),
                      ('bridge-ready.json',old_ready)]:
        if data is not None:
            entry=backup/name; entry.write_bytes(data); os.chmod(entry,0o600)
    print('CONFIG_BACKUP:',backup,flush=True)
    def write(path, data):
        stat = path.stat() if path.exists() else None
        fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.soc-ai-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temp, stat.st_mode & 0o777 if stat else 0o640)
            os.chown(temp, stat.st_uid if stat else 0, stat.st_gid if stat else group)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    def run(argv, **kwargs):
        result = subprocess.run(argv, capture_output=True, timeout=60, **kwargs)
        output = (result.stdout+result.stderr).decode(errors='replace')
        print(output, flush=True)
        if result.returncode:
            raise RuntimeError('Command failed: '+' '.join(argv))
        return output
    changed = False
    restarted = False
    try:
        write(config, updated)
        changed = True
        write(rules, payload['rules'].encode())
        run(['/var/ossec/bin/wazuh-analysisd', '-t'])
        run(['/var/ossec/bin/wazuh-logcollector', '-t'])
        samples = [{'soc_ai_kind': 'connection_test'},
            {'soc_ai_kind': 'model_summary', 'decision': 'possible_attack'},
            *({'soc_ai_kind': 'correlation', 'case_status': status} for status in
              ('possible_recon', 'possible_password_guessing', 'suspicious_login_sequence','possible_web_sqli')),
            {'soc_ai_kind':'model_summary','decision':'below_alert_threshold'},
            {'soc_ai_kind':'auth_observation','activity_type':'auth.success'},
            {'soc_ai_kind':'sensor_alert','signature':'lab signature','risk_score':50},
            {'soc_ai_kind':'http_observation','http_method':'GET','http_status':200,'request_count':1},
            {'soc_ai_kind':'telemetry_warning','source_container':'lab-sensor',
             'ipv4_truncated_packets':1,'tcp_reassembly_gaps':1,'kernel_drops':0},
            {'soc_ai_kind':'attack_chain','risk_level':'medium'},
            {'soc_ai_kind':'chain_stage','stage_name':'possible_recon'},
            {'soc_ai_kind':'attack_chain','risk_level':'high'},
            {'soc_ai_kind':'sensor_alert','signature_id':9900101},
            {'soc_ai_kind':'http_load','http_rate_exceeded':True,'http_rate_evidence_verified':True},
            {'soc_ai_kind':'http_load','http_rate_exceeded':True,'http_rate_evidence_verified':True,
             'healthy_baseline_observed':True,'service_degradation_observed':True,
             'baseline_comparison_scope':'same_host_ip_port_origin_method_path'},
            {'soc_ai_kind':'syn_load','syn_rate_evidence_verified':True},
            {'soc_ai_kind':'reverse_shell_evidence','kernel_process_observation':True,
             'stdin_stdout_same_socket':True,'native_ssh_session_verified':True,'outgoing_syn_verified':True,
             'pid':123,'effective_uid':1003,'peer_ip':'198.51.100.10','peer_port':4444},
            {'soc_ai_kind':'ssh_contact','ssh_syn_evidence_verified':True}]
        lines = ''.join(json.dumps({'soc_ai_producer': 'soc-ai-live',
            'source_ip': '198.51.100.10', 'target_ip': '192.0.2.10', 'target_host': 'test-host',
            'username': 'test-user', 'flow_count': 1, 'predicted_label': 'PortScan','model_interpretation':'Ung vien PortScan (chua xac minh)', 'score_max':0.8,'attack_score_threshold':0.5, **s})+'\n' for s in samples)
        checker = RuleCheck(lines, [*range(119201,119216),119217,119218,119219,119220,119221])
        checker.before_restart()
        restarted = True
        restart_manager()
        validation = checker.after_restart()
        write(ready, json.dumps({'version': 'soc-ai-wazuh/0.1', 'log_path': LOCATION,
            'installed_at_epoch': time.time(), 'rule_ids': [*range(119200,119216),119217,119218,119219,119220,119221],
            'installer_version': '0.4.14.1', 'validation': validation}).encode())
        print('WAZUH_BRIDGE_INSTALLED', flush=True)
    except ManagerRestartInProgress:
        print('RESTART_PENDING: no success marker written; candidate retained to avoid overlapping restarts.',flush=True)
        raise
    except BaseException:
        if changed:
            write(config, old_config)
            if old_rule is None: rules.unlink(missing_ok=True)
            else: write(rules, old_rule)
            if old_ready is None: ready.unlink(missing_ok=True)
            else: write(ready, old_ready)
            print('Previous configuration restored.', flush=True)
            if restarted:
                try:
                    restart_manager()
                except Exception as rollback_error:
                    print('ROLLBACK_RESTART_FAILED: '+str(rollback_error), flush=True)
        raise


def remote_script():
    code = Path(__file__).read_text(encoding='utf-8')
    return embedded_support()+code.rsplit("\nif __name__ == '__main__':", 1)[0]+'\ninstall_remote(json.load(sys.stdin))\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manager', default='single-node-wazuh.manager-1')
    a = p.parse_args()
    # Execute function in the container without entering main(). JSON uses stdin.
    remote = remote_script()
    rules = Path(__file__).with_name('soc_ai_bridge_rules.xml').read_text(encoding='utf-8')
    launcher = 'if [ -x /var/ossec/framework/python/bin/python3 ]; then exec /var/ossec/framework/python/bin/python3 "$@"; else exec python3 "$@"; fi'
    result = subprocess.run(['docker', 'exec', '-i', '--user', '0', a.manager, 'sh', '-c', launcher,
                             'soc-ai-setup', '-c', remote], input=json.dumps({'rules': rules}).encode())
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
