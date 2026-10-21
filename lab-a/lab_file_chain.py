"""SSH-bound EICAR transfers, enriched by exact native FIM -> VT references.

Reputation responses are enrichment, never actor activity or episode anchors.
No association by host/time alone; all joins require exact path and known hash.
"""
import re
from vt_lab_artifact import EICAR_SHA256, EICAR_MD5

PATH = re.compile(r'/var/lib/soc-lab/fim/vt-eicar-[a-f0-9]{32}\.txt\Z')


def native_event(wrapper, config):
    from lab_correlation import host_ip, instant, stamp
    rules = wrapper.get('rule', {})
    if not isinstance(rules, dict):
        raise ValueError('Wazuh rule must be an object')
    rule = str(rules.get('id', ''))
    if rule not in ('119253', '87105', '87104', '87103'):
        return None
    agent = wrapper['agent']
    target = host_ip(agent['name'], config)
    if not target:
        return None
    if not isinstance(wrapper.get('id'), str) or not 1 <= len(wrapper['id']) <= 128:
        raise ValueError('Native Wazuh alert ID required')
    base = dict(event_time=stamp(instant(wrapper['timestamp'])), target_host=agent['name'],
                target_ip=target, agent_id=agent['id'], wazuh_alert_id=wrapper['id'])
    if rule == '119253':
        s = wrapper.get('syscheck', {})
        if not isinstance(s, dict):
            raise ValueError('FIM syscheck must be an object')
        if (s.get('event') != 'added' or not PATH.fullmatch(s.get('path', ''))
                or s.get('sha256_after') != EICAR_SHA256 or s.get('md5_after') != EICAR_MD5):
            return None
        return {**base, 'kind': 'file.fim_eicar', 'artifact_path': s['path'],
                'artifact_sha256': EICAR_SHA256, 'artifact_md5': EICAR_MD5}
    data = wrapper.get('data', {})
    if not isinstance(data, dict):
        raise ValueError('Native VT data must be an object')
    vt = data.get('virustotal', {})
    if not isinstance(vt, dict):
        raise ValueError('Native VT fields must be an object')
    source = vt.get('source', {})
    if not isinstance(source, dict):
        raise ValueError('Native VT source must be an object')
    if (data.get('integration') != 'virustotal' or not PATH.fullmatch(source.get('file', ''))
            or source.get('md5') != EICAR_MD5 or not isinstance(source.get('alert_id'), str)):
        return None
    value = vt.get('positives', 0)
    if not (type(value) is int or isinstance(value, str) and value.isascii() and value.isdecimal()):
        raise ValueError('Invalid VirusTotal detection count')
    positive = int(value)
    if not 0 <= positive <= 100000:
        raise ValueError('Invalid VirusTotal detection count')
    found = str(vt.get('found', '0')) == '1'
    # Demand the positive rule AND native found/malicious fields; don't infer a verdict.
    detected = rule == '87105' and found and str(vt.get('malicious', '0')) == '1' and positive > 0
    return {**base, 'kind': 'file.vt_eicar', 'artifact_path': source['file'],
            'artifact_md5': EICAR_MD5, 'fim_alert_id': source['alert_id'],
            'vt_detected': detected, 'vt_positives': positive, 'vt_rule_id': rule}


def transfer_cases(events):
    from lab_correlation import instant, digest
    rows = {e['event_id']: e for e in events}
    result = []
    for e in sorted(rows.values(), key=lambda e: e['event_id']):
        if e['kind'] != 'file.eicar_received': continue
        matches = [a for a in rows.values() if a['kind'] == 'auth.success'
            and all(a.get(k) == e.get(k) for k in ('source_ip', 'target_ip', 'target_host', 'username', 'source_port'))
            and 0 <= (instant(e['started_at']) - instant(a['event_time'])).total_seconds() <= 60]
        # Ambiguous reused ports/auth identities do not establish a session.
        if len(matches) != 1: continue
        s = {k: e[k] for k in ('artifact_path', 'artifact_bytes', 'artifact_sha256', 'artifact_md5',
                              'probe_id', 'source_port', 'transfer_method')}
        s.update(name='observed_eicar_transfer', start_time=e['started_at'], end_time=e['event_time'],
                 evidence_ids=sorted([e['event_id'], matches[0]['event_id']]),
                 test_artifact=True, executed=False, vt_status='awaiting_fim_and_vt')
        result.append(dict(schema_version='soc-correlation-case/0.1', case_id='transfer:'+digest(e['event_id']),
            status='observed_eicar_transfer', source_ip=e['source_ip'], target_ip=e['target_ip'],
            target_host=e['target_host'], username=e['username'], first_seen=s['start_time'],
            last_seen=s['end_time'], stages=[s], confirmed_compromise=False, training_label=None,
            endpoint_evidence_scope='controlled_lab_probe_only',
            explanation='Fixed EICAR receiver verified bytes/hash in the exact successful SSH session. '
                        'Standard antivirus test file; execution and compromise are not established.'))
    return result


def enrich(chains, events):
    from lab_correlation import instant
    rows = list({e['event_id']: e for e in events}.values())
    transfers = [e for e in rows if e['kind'] == 'file.eicar_received']
    for chain in chains:
        for stage in chain['stages']:
            if stage['name'] != 'observed_eicar_transfer': continue
            # Never assign one destination path to two different sender records.
            owners = [e for e in transfers if e['artifact_path'] == stage['artifact_path']
                      and e['target_host'] == chain['target_host']]
            if len(owners) != 1: continue
            fims = [e for e in rows if e['kind'] == 'file.fim_eicar'
                and e['target_host'] == chain['target_host'] and e['artifact_path'] == stage['artifact_path']
                and e['artifact_sha256'] == stage['artifact_sha256'] and e['artifact_md5'] == stage['artifact_md5']
                and -2 <= (instant(e['event_time']) - instant(stage['end_time'])).total_seconds() <= 60]
            if len(fims) != 1: continue
            fim = fims[0]
            stage.update(fim_alert_id=fim['wazuh_alert_id'], vt_status='awaiting_vt')
            stage['evidence_ids'] = sorted(set(stage['evidence_ids'] + [fim['event_id']]))
            reports = [e for e in rows if e['kind'] == 'file.vt_eicar'
                and e['target_host'] == fim['target_host'] and e['agent_id'] == fim['agent_id']
                and e['fim_alert_id'] == fim['wazuh_alert_id'] and e['artifact_path'] == fim['artifact_path']
                and e['artifact_md5'] == fim['artifact_md5']
                and 0 <= (instant(e['event_time']) - instant(fim['event_time'])).total_seconds() <= 3600]
            if not reports: continue
            # Contradictory copies are not resolved by guessing which verdict wins.
            verdicts = {(e['vt_rule_id'], e['vt_detected'], e['vt_positives']) for e in reports}
            if len(verdicts) != 1:
                stage['vt_status'] = 'ambiguous_reports'; continue
            report = min(reports, key=lambda e: (e['event_time'], e['event_id']))
            stage.update(vt_status='detected_test_file' if report['vt_detected'] else 'no_positive_verdict',
                vt_positives=report['vt_positives'], vt_rule_id=report['vt_rule_id'],
                vt_alert_id=report['wazuh_alert_id'], vt_report_time=report['event_time'])
            stage['evidence_ids'] = sorted(set(stage['evidence_ids'] + [report['event_id']]))
        detected = any(s.get('vt_status') == 'detected_test_file' for s in chain['stages'])
        if detected:
            chain.update(risk_score_base=max(chain['risk_score_base'], 75))
            chain['risk_score'] = min(95, chain['risk_score_base'] + chain['risk_score_recon_bonus'] + chain['risk_score_diversity_bonus'])
            chain['risk_level'] = 'high' if chain['risk_score'] >= 70 else 'medium'
        # Do not alter first/last_seen, stage times, stage count or episode boundaries.
    return chains
