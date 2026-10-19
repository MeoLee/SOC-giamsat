import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time
import numpy as np
from .common import CLASSES, write_json, read_json, sha256
from .workflow import Workflow
from . import charts
from .flow import normalize,features,group_key,split_for_group,SPEC,FEATURE_HASH

SPLITS=['train','validation','test']
DAY_NAMES=['Monday','Tuesday','Friday']

def run(cohort,output,seed=42,tiers='all',experimental=False):
    if not experimental:
        raise ValueError('These are provisional labels: pass --experimental-labels to build a research baseline')
    manifest=read_json(cohort.parent/'report.json')
    if manifest.get('version')!='cic-experimental-cohort/0.1' or manifest.get('complete') is not True:
        raise ValueError('Requires complete experimental cohort 0.1')
    output.mkdir(parents=True,exist_ok=False)
    workflow=Workflow(output,"prepare")
    workflow.update("prepare","Normalizing flows, extracting features and splitting groups")
    report={'version':'soc-prepared/0.1','complete':False,'experimental_labels':True,
            'production_ready':False,'seed':seed,'tiers':tiers,'feature_hash':FEATURE_HASH,
            'classes':CLASSES,'day_names':DAY_NAMES,'cohort_path':str(cohort),'cohort_report_sha256':sha256(cohort.parent/'report.json'),
            'split_policy':'70/15/15 deterministic bidirectional endpoint-tuple groups; internal benchmark; not chronological or attack-episode independent'}
    write_json(output/'report.json',report)
    xs=[]; ys=[]; splits=[]; tier_ids=[]; day_ids=[]
    groups=[set(),set(),set()]; observed=Counter(); group_labels={}; golden=[]
    seen_records=set(); source_hash=hashlib.sha256(); last=time.monotonic()
    with cohort.open('rb') as f:
        for n,line in enumerate(f,1):
            source_hash.update(line); e=json.loads(line)
            if e['schema_version']!='cic-experimental-cohort/0.1': raise ValueError('Unexpected cohort schema')
            if e.get('label') is not None: raise ValueError('Unexpected final label field')
            label=e['provisional_label']; tier=e['evidence_tier']; flow=e['flow']
            if label not in CLASSES or tier not in ('strict','near_duration'): raise ValueError('Unknown label/tier')
            if e['record_id']!=flow['record_id'] or e['record_id'] in seen_records:
                raise ValueError('Duplicate/mismatched record ID at line '+str(n))
            seen_records.add(e['record_id']); observed[(flow['day'],tier,label)]+=1
            if tiers=='strict' and tier!='strict': continue
            normalized=normalize(flow); x=features(normalized)
            key=group_key(normalized); split=split_for_group(key,seed)
            groups[split].add(key); group_labels.setdefault(key,set()).add(label)
            xs.append(x); ys.append(CLASSES.index(label)); splits.append(split)
            tier_ids.append(int(tier=='near_duration')); day_ids.append(DAY_NAMES.index(flow['day']))
            if len(golden)<12: golden.append({'flow':normalized,'features':x.tolist(),'provisional_label':label})
            if n%25000==0 or time.monotonic()-last>=10:
                print('PREPARE',n,'selected',len(xs),flush=True); last=time.monotonic()
                workflow.update('prepare','Extracting features and assigning connection groups',rows_read=n,rows_selected=len(xs))
    expected={(day,tier,label):count for day,details in manifest['days'].items()
              for tier,labels in details['labels_by_tier'].items() for label,count in labels.items() if count}
    if dict(observed)!=expected: raise ValueError('Cohort counts disagree with manifest')
    if not xs: raise ValueError('No records selected')
    if any(groups[a]&groups[b] for a,b in ((0,1),(0,2),(1,2))): raise ValueError('Group leakage')
    x=np.stack(xs); y=np.asarray(ys,dtype=np.int64); split=np.asarray(splits,dtype=np.uint8)
    tier=np.asarray(tier_ids,dtype=np.uint8); day=np.asarray(day_ids,dtype=np.uint8)
    counts={}
    fingerprints=[set(),set(),set()]
    for j,name in enumerate(SPLITS):
        mask=split==j
        if not mask.any(): raise ValueError('Empty split: '+name)
        counts[name]={'rows':int(mask.sum()),'groups':len(groups[j]),
                     'classes':{label:int(np.sum(y[mask]==i)) for i,label in enumerate(CLASSES)}}
        fingerprints[j]={hashlib.sha256(row.tobytes()).digest() for row in x[mask]}
    # Report feature lookalikes: no claim that tuple grouping separates attack episodes.
    overlap={'validation_unique_vectors_also_in_train':len(fingerprints[1]&fingerprints[0]),
             'test_unique_vectors_also_in_train':len(fingerprints[2]&fingerprints[0]),
             'test_unique_vectors':len(fingerprints[2])}
    np.savez_compressed(output/'data.npz',x=x,y=y,split=split,tier=tier,day=day)
    write_json(output/'features.json',SPEC); write_json(output/'golden.json',golden)
    report.update({'complete':True,'cohort_sha256':source_hash.hexdigest(),'data_sha256':sha256(output/'data.npz'),
                   'counts':counts,'feature_lookalikes':overlap,
                   'mixed_label_tuple_groups':sum(len(v)>1 for v in group_labels.values()),
                   'warnings':['Original CSV labels remain provisional.',
                               'Same attack episode can occur in multiple splits; independent lab evaluation required.',
                               'Selected cohorts omit many short/reused/ambiguous flows.',
                               'Features require completed-flow counters; not packet-by-packet detection.']})
    write_json(output/'report.json',report)
    charts.preparation(output/'charts',counts)
    workflow.finish('completed','Preparation complete. Ready to train.')
    print('PREPARE_COMPLETE',flush=True); print(json.dumps(counts,indent=2),flush=True)

def main():
    p=argparse.ArgumentParser(description='Prepare research flow features from experimental cohort')
    p.add_argument('--cohort',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seed',type=int,default=42); p.add_argument('--tiers',choices=('all','strict'),default='all')
    p.add_argument('--experimental-labels',action='store_true')
    a=p.parse_args(); run(a.cohort,a.output,a.seed,a.tiers,a.experimental_labels)

if __name__=='__main__': main()
