"""Review the latest manual Live capture; never supplies labels to the detector."""
import argparse,hashlib,json,tempfile
from collections import Counter
from pathlib import Path
from soc_ai.common import read_json,write_json
from lab_correlation import Correlator,digest,instant


def latest(root):
    candidates=[]
    for path in root.glob('*/raw/*/session.json'):
        session=read_json(path)
        candidates.append((instant(session['started_at_utc']),path.parent))
    if not candidates:raise ValueError('No Live sessions below '+str(root))
    return max(candidates,key=lambda item:(item[0],str(item[1])))[1]


def review(capture,manager=None,expect_no_chain=False):
    session=read_json(capture/'session.json');saved=read_json(capture/'correlation-cases.json')
    if not session.get('closed'):raise ValueError('Close Live with Ctrl+C and wait for LIVE_DONE before final replay')
    config=saved['config'];hashes=session.get('sha256',{})
    missing=[];mismatch=[]
    for name in config['source_kinds']:
        if name not in hashes:missing.append(name)
        elif hashlib.sha256((capture/name).read_bytes()).hexdigest()!=hashes[name]:mismatch.append(name)
    if missing or mismatch:raise ValueError('Raw hash failure: '+json.dumps({'missing':missing,'mismatch':mismatch}))
    with tempfile.TemporaryDirectory() as folder:
        engine=Correlator(capture,Path(folder),config)
        while engine.consume():pass
    chains=engine.chains
    report={'format':'soc-manual-chain-review/0.1','capture':str(capture),'session_id':session['session_id'],
        'capture_status':session['status'],'raw_replay_matches':digest(chains)==digest(saved.get('chains',[])),
        'raw_hashes_verified':True,'invalid_records':engine.counts['invalid_source_records'],
        'unfinished_lines':[n for n,p in engine.pending.items() if p],
        'gaps':session.get('gaps',[]),'partials':session.get('partials',[]),
        'chain_count':len(chains),'chains':[{'chain_id':c['chain_id'],'source_ip':c['source_ip'],'target_ip':c['target_ip'],
            'risk_score':c['risk_score'],'observed_stages':[s['name'] for s in c['stages']],
            'no_observed_stage_is_a_prediction':True} for c in chains],
        'manager_delivery_verified':False,'indexer_verified':False,'dashboard_rendering_verified':False,
        'next_step_predictions_accuracy_established':False,'operator_intent_or_attack_success_verified':False}
    good=bool(report['raw_replay_matches'] and session['status']=='completed' and not report['invalid_records'] and not report['unfinished_lines'] and not report['gaps'] and not report['partials'])
    if expect_no_chain:good &= not chains
    if manager:
        from wazuh_trace import manager_alerts
        result=manager_alerts(manager,{'session_id':session['session_id']})
        alerts=result['alerts'];counts=Counter(str(a.get('rule',{}).get('id')) for a in alerts)
        report.update(manager_rule_counts=dict(counts),manager_tail_limited=result['tail_limited'])
        expected={c['chain_id'] for c in chains}
        summaries={a.get('data',{}).get('chain_id') for a in alerts if a.get('data',{}).get('soc_ai_kind')=='attack_chain'}
        stages={a.get('data',{}).get('chain_id') for a in alerts if a.get('data',{}).get('soc_ai_kind')=='chain_stage'}
        report['manager_delivery_verified']=bool(expected and expected<=summaries and expected<=stages and not result['tail_limited'])
        if chains:good &= report['manager_delivery_verified']
    report['checks_passed']=bool(good)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent/'monitor-sessions')
    p.add_argument('--capture',type=Path);p.add_argument('--manager');p.add_argument('--expect-no-chain',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Choose a new report filename')
    capture=a.capture or latest(a.root)
    result=review(capture,a.manager,a.expect_no_chain);write_json(a.output,result);print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['checks_passed'] else 2

if __name__=='__main__':raise SystemExit(main())
