"""Explainable operational priority, not a probability or ground-truth label."""
import hashlib
import json

POLICY = 'soc-operational-risk/0.1'


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
    score = {'possible_recon':40, 'possible_password_guessing':65,
             'suspicious_login_sequence':85, 'possible_web_sqli':60}[case['status']]
    if 'possible_recon' in names and len(names) > 1:
        score = min(95, score+10)
    nodes = []
    for i, stage in enumerate(stages):
        identity = json.dumps([case['case_id'], i, stage['name']], separators=(',', ':'))
        nodes.append({'node_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
                      'stage': stage['name'], 'start_time': stage['start_time'],
                      'end_time': stage['end_time'],
                      'evidence_ids': stage['evidence_ids'][:32],
                      'evidence_count': len(stage['evidence_ids'])})
    edges = [{'from':a['node_id'], 'to':b['node_id'], 'relation':'observed_sequence'}
             for a,b in zip(nodes,nodes[1:])]
    return {**assessment(score, 'Observed evidence stages: '+' -> '.join(names),
                         'correlated_hypothesis'),
            'attack_chain': ' -> '.join(names), 'attack_chain_stage_count':len(nodes),
            'attack_chain_is_causal_proof':False,
            'attack_chain_graph':{'nodes':nodes,'edges':edges}}
