"""Explainable operational priority, not a probability or ground-truth label."""
import hashlib
import json
from datetime import datetime

POLICY = 'soc-operational-risk/0.1'

# ATT&CK candidates from observed evidence, not inferred decrypted SSH content.
STAGE_LABELS = {
    'ssh_service_contact':('SSH service contact (recon unproven)',None),
    'observed_ssh_session':('Native SSH session observed',None),
    'observed_reverse_shell':('Shell with outgoing TCP socket and exact SSH session','T1059.004'),
    'syn_connection_pressure': ('TCP SYN connection pressure (impact unproven)', None),
    'observed_eicar_transfer': ('Verified EICAR test-file transfer (SSH lab receiver)', 'T1105'),
    'observed_auth_failures': ('Authentication failures (context)', None),
    'http_request_pressure': ('High HTTP request volume', None),
    'possible_http_dos': ('HTTP pressure with service degradation', 'T1499'),
    'possible_recon': ('Network service scanning', 'T1046'),
    'repeated_auth_failures': ('Password guessing', 'T1110.001'),
    'auth_success_after_failures': ('Login after password guessing', 'T1078'),
    # Public-facing exposure is not established merely by a SQLi signature.
    'possible_web_sqli': ('SQL injection attempt', None),
    'observed_shell_execution': ('Shell execution (lab probe)', 'T1059.004'),
    'observed_file_transfer': ('File transfer (lab probe)', 'T1105'),
}


def assessment(score, basis, outcome='unverified_detection'):
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError('Risk score must be an integer in 0..100')
    return {'risk_score': score,
            'risk_level': 'high' if score >= 70 else 'medium' if score >= 40 else 'low',
            'risk_policy': POLICY, 'risk_basis': basis,
            'risk_is_probability': False, 'security_outcome': outcome,
            'confirmed_compromise': False}


def case_assessment(case):
    stages = case['stages']; names = [s['name'] for s in stages]
    base = {'possible_recon':40, 'possible_password_guessing':65,
             'suspicious_login_sequence':85, 'possible_web_sqli':60,
             'observed_eicar_transfer':40,'observed_reverse_shell':85}[case['status']]
    bonus = 10 if 'possible_recon' in names and len(names) > 1 else 0
    score = min(95, base+bonus)
    nodes = []
    for i, stage in enumerate(stages):
        identity = json.dumps([case['case_id'], i, stage['name']], separators=(',', ':'))
        nodes.append({'node_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
                      'stage': stage['name'], 'start_time': stage['start_time'],
                      'end_time': stage['end_time'],
                      'candidate_technique': STAGE_LABELS[stage['name']][1],
                      'evidence_ids': stage['evidence_ids'][:32],
                      'evidence_count': len(stage['evidence_ids'])})
    edges = [{'from':a['node_id'], 'to':b['node_id'], 'relation':'observed_sequence'}
             for a,b in zip(nodes,nodes[1:])]
    priority = assessment(score, 'Observed evidence stages: '+' -> '.join(names),
                          'correlated_hypothesis')
    labels = [STAGE_LABELS[name][0] for name in names]
    techniques = list(dict.fromkeys(STAGE_LABELS[name][1] for name in names
                                    if STAGE_LABELS[name][1]))
    attack_type = ' -> '.join(labels)
    # Parse the offsets before comparing times: lexical order is not event order
    # when inputs use different UTC offsets.
    moment = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
    started = min((s['start_time'] for s in stages), key=moment)
    ended = max((s['end_time'] for s in stages), key=moment)
    stage_details = []
    for i, stage in enumerate(stages, 1):
        label, technique = STAGE_LABELS[stage['name']]
        detail = (str(i)+'. '+label+' ['+(technique or 'unmapped')+']; '
                  +stage['start_time']+' -> '+stage['end_time']+'; '
                  +str(len(set(stage['evidence_ids'])))+' evidence event(s)')
        if stage['name'] == 'possible_recon':
            detail += ('; distinct ports='+str(stage['distinct_destination_ports'])
                       +'; threshold='+str(stage['port_threshold'])
                       +' within '+str(stage['port_window_seconds'])+'s')
        elif stage['name'] == 'repeated_auth_failures':
            detail += ('; password failures='+str(stage['failure_count'])
                       +'; threshold='+str(stage['threshold'])
                       +' within '+str(stage['window_seconds'])+'s')
        elif stage['name'] == 'observed_shell_execution':
            detail += '; fixed command='+stage['command']
        elif stage['name'] == 'observed_file_transfer':
            detail += ('; bytes='+str(stage['artifact_bytes'])
                       +'; URL='+stage['transfer_url']
                       +'; SHA256='+stage['artifact_sha256'])
        elif stage['name'] == 'observed_eicar_transfer':
            detail += ('; EICAR test file; path='+stage['artifact_path']
                       +'; bytes='+str(stage['artifact_bytes'])
                       +'; SHA256='+stage['artifact_sha256']+'; execution unproven')
        stage_details.append(detail)
    return {**priority,
            'chain_id': 'CHAIN-'+hashlib.sha256(case['case_id'].encode()).hexdigest()[:16].upper(),
            'techniques': ';'.join(techniques) or 'unmapped',
            'techniques_are_hypotheses': True,
            'technique_mapping_version': 'observed-stage-candidates/0.1',
            'attack_type': attack_type,
            'conclusion': priority['risk_level'].upper()+': '+attack_type+
                          '. Review evidence; compromise unconfirmed.',
            'attack_summary': str(len(nodes))+' observed stage(s); sequence hypothesis; compromise unconfirmed.',
            'chain_started_at': started, 'chain_last_seen_at': ended,
            'chain_duration_seconds': round((moment(ended)-moment(started)).total_seconds(), 6),
            'chain_evidence_count': len({eid for s in stages for eid in s['evidence_ids']}),
            'chain_password_failure_count': sum(s.get('failure_count', 0) for s in stages),
            'chain_stage_details': '\n'.join(stage_details),
            'endpoint_evidence_scope': case.get('endpoint_evidence_scope', 'no_endpoint_probe'),
            'risk_score_base':base,'risk_score_recon_bonus':bonus,'risk_score_cap':95,
            'attack_chain': ' -> '.join(names), 'attack_chain_stage_count':len(nodes),
            'attack_chain_is_causal_proof':False,
            'attack_chain_graph':{'nodes':nodes,'edges':edges}}
