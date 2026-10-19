"""Read-only analysis of paired flow/prediction files and an optional prepared cache."""
import argparse
from collections import Counter
import json
from pathlib import Path

from soc_ai.common import CLASSES, read_json, sha256, write_json
from soc_ai.flow import FEATURE_HASH, FEATURE_NAMES, features, normalize


def analyze(flows, predictions):
    indexed = {}
    for event in flows:
        key = event['record_id']
        if key in indexed: raise ValueError('Duplicate input record_id')
        indexed[key] = event
    seen = set(); rows = []
    for prediction in predictions:
        key = prediction['record_id']
        if key in seen: raise ValueError('Duplicate prediction record_id')
        seen.add(key)
        if key not in indexed: raise ValueError('Prediction has no matching input')
        raw = indexed[key]; flow = normalize(raw)
        for field in ('src_ip','dest_ip','src_port','dest_port'):
            if prediction[field] != flow[field]: raise ValueError('Prediction/input identity mismatch: '+field)
        scores = prediction.get('class_scores')
        if scores and (set(scores) != set(CLASSES) or abs(sum(scores.values())-1)>1e-4):
            raise ValueError('Invalid class score vector')
        duration = flow['duration_seconds']
        packets = flow['pkts_toserver']+flow['pkts_toclient']
        byte_count = flow['bytes_toserver']+flow['bytes_toclient']
        rows.append({'record_id':key,'source_ip':flow['src_ip'],'source_port':flow['src_port'],
            'target_ip':flow['dest_ip'],'target_port':flow['dest_port'],
            'duration_seconds':duration,'packets':packets,'bytes':byte_count,
            'packets_per_second':packets/max(duration,.001),
            'bytes_per_second':byte_count/max(duration,.001),
            'eve_age':raw.get('flow',{}).get('age'),
            'duration_source':'flow.end - flow.start, not integer age',
            'http_transactions':raw.get('flow',{}).get('tx_cnt'),
            'model_label':prediction.get('predicted_label'),
            'model_label_score':scores.get(prediction.get('predicted_label')) if scores else None,
            'binary_attack_score':prediction.get('attack_score'),
            'binary_threshold':prediction.get('attack_score_threshold'),
            'features':dict(zip(FEATURE_NAMES,map(float,features(flow)))),
            'flow_quality_flags':flow['quality_flags'],
            'label_verified_by_this_audit':False,
            'http_path_available_in_flow':False})
    if seen != set(indexed): raise ValueError('Inputs without matching predictions')
    return rows


def prepared_audit(path):
    import numpy as np
    path=Path(path); report=read_json(path/'report.json')
    if report.get('complete') is not True or report.get('feature_hash')!=FEATURE_HASH:
        raise ValueError('Prepared data incompatible or incomplete')
    if report.get('data_sha256')!=sha256(path/'data.npz'): raise ValueError('Prepared data hash mismatch')
    with np.load(path/'data.npz',allow_pickle=False) as data:
        x,y,split,day=[data[k] for k in ('x','y','split','day')]
        http=FEATURE_NAMES.index('app_http')
        result={}
        for code,role in enumerate(('train','validation','test')):
            mask=split==code
            local_codes=[i for i,name in enumerate(report['day_names']) if name.startswith('LAB:')]
            local=mask & np.isin(day,local_codes)
            result[role]={'rows':int(mask.sum()),'local_rows':int(local.sum()),
                'local_fraction':float(local.sum()/max(mask.sum(),1)),
                'http_by_class':{name:int(np.sum(mask & (y==i) & (x[:,http]>.5))) for i,name in enumerate(CLASSES)},
                'local_http_by_class':{name:int(np.sum(local & (y==i) & (x[:,http]>.5))) for i,name in enumerate(CLASSES)}}
    return result


def read_lines(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--flows',type=Path,required=True)
    p.add_argument('--predictions',type=Path,required=True)
    p.add_argument('--prepared',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result={'version':'soc-quality-audit/0.1','complete':True,
            'inputs':{'flows_sha256':sha256(a.flows),'predictions_sha256':sha256(a.predictions)},
            'flows':analyze(read_lines(a.flows),read_lines(a.predictions)),
            'note':'Read-only diagnosis. No predictions become training labels; no model or threshold is changed.'}
    if a.prepared:result['prepared']=prepared_audit(a.prepared)
    write_json(a.output,result)
    print('QUALITY_AUDIT_COMPLETE:',a.output)
    for row in result['flows']:
        print(row['source_port'],'duration=',round(row['duration_seconds'],6),
            'packets=',row['packets'],'bytes=',row['bytes'],'model_label=',row['model_label'])
    if a.prepared:print(json.dumps(result['prepared'],indent=2))


if __name__=='__main__':main()
