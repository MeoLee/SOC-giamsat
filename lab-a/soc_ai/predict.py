import argparse
from collections import Counter
import json
import math
from pathlib import Path
import numpy as np
import torch
from .common import display_label,CLASSES,digest,read_json,sha256
from .flow import FEATURE_HASH,FEATURE_NAMES,normalize,features,transform,validate_preprocessor,_numeric_array
from .model import FlowMLP,load_weights
from .model import predict_batches

class Predictor:
    def __init__(self,directory,device_name='cpu'):
        self.directory=Path(directory); self.metadata=self._read_json('model.json')
        m=self.metadata
        if not isinstance(m,dict) or m.get('version')!='soc-flow-model/0.1' or m.get('complete') is not True:
            raise ValueError('Incomplete or unsupported model bundle')
        if m.get('feature_hash')!=FEATURE_HASH or m.get('classes')!=CLASSES:
            raise ValueError('Feature/class mismatch')
        mask=m.get('active_classes')
        if not isinstance(mask,list) or len(mask)!=len(CLASSES) or any(type(value) is not bool for value in mask):
            raise ValueError('active_classes must contain exactly six booleans')
        if not mask[0] or sum(mask)<2:
            raise ValueError('active_classes requires BENIGN and at least one attack class')
        threshold=m.get('attack_score_threshold')
        try:
            valid_threshold=not isinstance(threshold,bool) and isinstance(threshold,(int,float)) and math.isfinite(threshold) and 0<=threshold<=np.nextafter(1.0,np.inf)
        except OverflowError: valid_threshold=False
        if not valid_threshold:
            raise ValueError('attack_score_threshold must be finite and in the supported score range')
        contract=self._read_json('features.json')
        if not isinstance(contract,dict) or digest(contract)!=FEATURE_HASH:
            raise ValueError('features.json does not match the feature contract')
        for name,key in [('model-weights.npz','weights_sha256'),('preprocessor.json','preprocessor_sha256')]:
            try:
                actual_hash=sha256(self.directory/name)
            except OSError as error:
                raise ValueError('Missing or unreadable bundle file: '+name) from error
            if actual_hash!=m.get(key): raise ValueError('Bundle integrity mismatch: '+name)
        if device_name=='cuda' and not torch.cuda.is_available(): raise ValueError('CUDA unavailable')
        torch.set_num_threads(4)
        self.device=torch.device(device_name)
        self.active=torch.tensor(mask,dtype=torch.bool,device=self.device)
        self.preprocessor=self._read_json('preprocessor.json')
        validate_preprocessor(self.preprocessor)
        self.model=load_weights(FlowMLP(),self.directory/'model-weights.npz').to(self.device).eval()

    def _read_json(self,name):
        try:
            return read_json(self.directory/name)
        except (OSError,UnicodeError,json.JSONDecodeError) as error:
            raise ValueError('Invalid or unreadable bundle JSON: '+name) from error

    def probabilities(self,flows):
        if not flows: raise ValueError('inference needs at least one flow')
        x=transform(np.stack([features(f) for f in flows]),self.preprocessor)
        result=predict_batches(self.model,x,self.device,self.active)
        self._validate_probabilities(result,len(flows),'model probabilities')
        return result

    @staticmethod
    def _validate_probabilities(values,rows,name):
        _numeric_array(values,name,(rows,len(CLASSES)))
        result=np.asarray(values)
        if np.any(result<0) or np.any(result>1) or not np.allclose(result.sum(axis=1,dtype=np.float64),1,atol=1e-5,rtol=1e-5):
            raise ValueError(name+' must contain probability rows summing to one')
        return result

    def verify(self):
        golden=self._read_json('golden.json')
        if not isinstance(golden,list) or not golden:
            raise ValueError('Golden vectors must be a nonempty list')
        normalized_flows=[]
        for e in golden:
            if not isinstance(e,dict) or 'flow' not in e or 'features' not in e:
                raise ValueError('Invalid golden vector entry')
            expected_features=_numeric_array(e['features'],'golden features',(len(FEATURE_NAMES),))
            actual_features=features(e['flow'])
            try:
                normalized=normalize(e['flow'])
            except (KeyError,TypeError,AttributeError,OverflowError) as error:
                raise ValueError('Invalid golden flow') from error
            # Golden exports contain normalized flows. Recheck their derived
            # fields through the production normalizer rather than trusting a
            # changed duration or a malformed timestamp in a saved fixture.
            if not np.array_equal(actual_features,features(normalized)):
                raise ValueError('Golden flow is inconsistent with its timestamps/counters')
            if not np.allclose(actual_features,expected_features,rtol=1e-6,atol=1e-6):
                raise ValueError('Golden feature mismatch')
            normalized_flows.append(normalized)
        actual=self.probabilities(normalized_flows)
        expected=self._validate_probabilities(self._read_json('golden-predictions.json'),len(golden),'golden probabilities')
        inactive=~self.active.cpu().numpy()
        if np.any(expected[:,inactive]!=0):
            raise ValueError('Golden probabilities assign mass to inactive classes')
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
                outputs[position].update({'predicted_label':label,'predicted_label_display':display_label(label),
                    'class_scores_display':{display_label(c):float(v) for c,v in zip(CLASSES,p)},'attack_score':score,
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
