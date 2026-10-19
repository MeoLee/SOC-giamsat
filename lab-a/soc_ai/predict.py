import argparse
from collections import Counter
import json
from pathlib import Path
import numpy as np
import torch
from .common import CLASSES,read_json,sha256
from .flow import FEATURE_HASH,normalize,features,transform
from .model import FlowMLP,load_weights
from .model import predict_batches

class Predictor:
    def __init__(self,directory,device_name='cpu'):
        self.directory=Path(directory); self.metadata=read_json(self.directory/'model.json')
        m=self.metadata
        if m.get('version')!='soc-flow-model/0.1' or m.get('complete') is not True:
            raise ValueError('Incomplete or unsupported model bundle')
        if m['feature_hash']!=FEATURE_HASH or m['classes']!=CLASSES:
            raise ValueError('Feature/class mismatch')
        for name,key in [('model-weights.npz','weights_sha256'),('preprocessor.json','preprocessor_sha256')]:
            if sha256(self.directory/name)!=m[key]: raise ValueError('Bundle integrity mismatch: '+name)
        if device_name=='cuda' and not torch.cuda.is_available(): raise ValueError('CUDA unavailable')
        torch.set_num_threads(4)
        self.device=torch.device(device_name)
        self.active=torch.tensor(m['active_classes'],dtype=torch.bool,device=self.device)
        self.preprocessor=read_json(self.directory/'preprocessor.json')
        self.model=load_weights(FlowMLP(),self.directory/'model-weights.npz').to(self.device).eval()

    def probabilities(self,flows):
        x=transform(np.stack([features(f) for f in flows]),self.preprocessor)
        return predict_batches(self.model,x,self.device,self.active)

    def verify(self):
        golden=read_json(self.directory/'golden.json')
        for e in golden:
            if not np.allclose(features(e['flow']),e['features'],rtol=1e-6,atol=1e-6):
                raise ValueError('Golden feature mismatch')
        actual=self.probabilities([e['flow'] for e in golden])
        expected=np.asarray(read_json(self.directory/'golden-predictions.json'))
        if not np.allclose(actual,expected,atol=1e-4,rtol=1e-4):
            raise ValueError('Golden inference mismatch')
        return float(np.max(np.abs(actual-expected)))

    def predict(self,events):
        outputs=[]; accepted=[]; positions=[]
        for event in events:
            flow=normalize(event)
            base={'schema_version':'soc-ai-flow-prediction/0.1','record_id':flow['record_id'],
                  'timestamp':flow['available_time'],'flow_id':flow['flow_id'],
                  'community_id':flow['community_id'],'src_ip':flow['src_ip'],'src_port':flow['src_port'],
                  'dest_ip':flow['dest_ip'],'dest_port':flow['dest_port'],'protocol':flow['protocol'],
                  'model_version':'soc-flow-model/0.1','experimental':True}
            reason=None
            if flow['protocol'] not in ('TCP','UDP'): reason='unsupported_protocol'
            elif flow['duration_seconds']<=0 or flow['pkts_toserver']+flow['pkts_toclient']<=1: reason='single_packet_or_zero_duration'
            elif flow['flow_reason']=='tcp_reuse': reason='tcp_reuse'
            if reason:
                outputs.append({**base,'decision':'out_of_training_scope','reason':reason})
            else:
                positions.append(len(outputs)); accepted.append(flow); outputs.append(base)
        if accepted:
            probs=self.probabilities(accepted)
            for position,p in zip(positions,probs):
                score=1.0-float(p[0]); threshold=self.metadata['attack_score_threshold']
                label=CLASSES[int(p.argmax())]
                outputs[position].update({'predicted_label':label,'attack_score':score,
                    'attack_score_threshold':threshold,'softmax_scores_calibrated':False,
                    'decision':'possible_attack' if score>=threshold else 'below_alert_threshold',
                    'class_scores':dict(zip(CLASSES,[float(v) for v in p]))})
        return outputs

def main():
    p=argparse.ArgumentParser(description='Batch inference using same flow normalizer/features as training')
    p.add_argument('--model',type=Path,required=True); p.add_argument('--input',type=Path)
    p.add_argument('--output',type=Path); p.add_argument('--verify-only',action='store_true')
    p.add_argument('--device',choices=('cpu','cuda'),default='cpu')
    a=p.parse_args(); predictor=Predictor(a.model,a.device)
    error=predictor.verify(); print('MODEL_VERIFY_OK max_probability_difference=',error,flush=True)
    if a.verify_only: return
    if a.input is None or a.output is None: p.error('--input and --output required without --verify-only')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    stats=Counter(); batch=[]
    with a.input.open(encoding='utf-8-sig') as inp,a.output.open('x',encoding='utf-8',newline='\n') as out:
        def flush():
            for e in predictor.predict(batch):
                out.write(json.dumps(e,ensure_ascii=False,allow_nan=False)+'\n'); stats[e['decision']]+=1
            batch.clear()
        for line_number,line in enumerate(inp,1):
            if not line.strip(): continue
            e=json.loads(line)
            if e.get('event_type') is not None and e.get('event_type')!='flow':
                stats['ignored_non_flow_events']+=1; continue
            batch.append(e)
            if len(batch)>=1024:
                flush(); print('PREDICT',line_number,dict(stats),flush=True)
        if batch: flush()
    print('PREDICT_COMPLETE:',a.output,dict(stats),flush=True)

if __name__=='__main__': main()
