"""Rebuild closed-session chains from raw logs, independently of operator intent."""
import argparse,hashlib,json,tempfile
from pathlib import Path
from lab_correlation import Correlator,digest
from soc_ai.common import read_json,write_json


def verify(capture,operator):
    session=read_json(capture/'session.json');saved=read_json(capture/'correlation-cases.json')
    if not session.get('closed'):raise ValueError('Close Live and wait for LIVE_DONE before replay')
    if operator['capture_session_id']!=session['session_id']:raise ValueError('Operator/session mismatch')
    config=saved['config']
    missing_hashes=[]
    for name in config['source_kinds']:
        path=capture/name
        expected=session.get('sha256',{}).get(name)
        if not expected:missing_hashes.append(name)
        if expected and hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Raw hash mismatch: '+name)
    with tempfile.TemporaryDirectory() as folder:
        engine=Correlator(capture,Path(folder)/'replay',config)
        while engine.consume():pass
        rebuilt=engine.chains
    names=[{s['name'] for s in c['stages']} for c in rebuilt]
    def covers(observed):
        return all((bool({'http_request_pressure','possible_http_dos'} & observed) if n=='http_pressure_or_degradation' else n in observed)
                   for n in operator['required_stages'])
    matching=[c['chain_id'] for c,n in zip(rebuilt,names) if covers(n)]
    raw_match=digest(rebuilt)==digest(saved.get('chains',[]))
    result={'schema_version':'soc-chain-replay/0.2','session_id':session['session_id'],'capture_closed':True,
        'raw_replay_matches_saved_chains':raw_match,'matched_chain_ids':matching,
        'required_stages_in_one_chain':bool(matching),'operator_complete':operator['complete'],
        'chain_count':len(rebuilt),'chains':[{'chain_id':c['chain_id'],'categories':c['categories'],
            'risk_score':c['risk_score'],'stage_names':[s['name'] for s in c['stages']]} for c in rebuilt],
        'invalid_raw_records':engine.counts['invalid_source_records'],
        'missing_recorded_hashes':missing_hashes,'unfinished_raw_lines':[n for n,p in engine.pending.items() if p],
        'manager_delivery_verified_by_this_check':False,'indexer_verified':False,'dashboard_rendering_verified':False,
        'confirmed_compromise':False,'expectations_are_not_training_labels':True}
    result['checks_passed']=bool(operator['complete'] and matching and raw_match and not engine.counts['invalid_source_records'] and session.get('status')=='completed' and not missing_hashes and not any(engine.pending.values()))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--operator',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Output exists; choose a new report filename')
    result=verify(a.capture,read_json(a.operator));write_json(a.output,result);print(json.dumps(result,indent=2));return 0 if result['checks_passed'] else 2
if __name__=='__main__':raise SystemExit(main())
