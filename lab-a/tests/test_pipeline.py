import contextlib
import io
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
from soc_ai.common import CLASSES,write_json,read_json
from soc_ai.flow import normalize,features,FEATURE_NAMES,group_key,split_for_group,fit_preprocessor,transform
from soc_ai.prepare import run as prepare


def staging(i=0,label='BENIGN'):
    time=datetime(2017,7,4,12,0,tzinfo=timezone.utc)+timedelta(seconds=i*3)
    return {'schema_version':'cic-suricata-flow-staging/0.1','record_id':f'Tuesday:run:{i}',
        'day':'Tuesday','label':None,'label_status':'unassigned',
        'start_time':time.isoformat(),'end_time':(time+timedelta(seconds=1+i%5)).isoformat(),
        'eve_timestamp':(time+timedelta(seconds=5+i%5)).isoformat(),
        'src_ip':'172.16.0.1','dest_ip':'192.168.10.50','src_port':30000+i,'dest_port':22,
        'protocol':'TCP','app_protocol':'ssh','pkts_toserver':2+i%10,'pkts_toclient':3,
        'bytes_toserver':200+i*10,'bytes_toclient':300,'flow_state':'closed','flow_reason':'timeout'}

class FlowTests(unittest.TestCase):
    def test_staging_and_eve_same_features(self):
        s=staging(); e={'event_type':'flow','timestamp':s['eve_timestamp'],'src_ip':s['src_ip'],
            'dest_ip':s['dest_ip'],'src_port':s['src_port'],'dest_port':s['dest_port'],
            'proto':'TCP','app_proto':'ssh','flow':{'start':s['start_time'],'end':s['end_time'],
            'state':'closed','reason':'timeout',**{k:s[k] for k in ('pkts_toserver','pkts_toclient','bytes_toserver','bytes_toclient')}}}
        np.testing.assert_array_equal(features(normalize(s)),features(normalize(e)))
    def test_ip_port_not_features(self):
        a=normalize(staging()); b=deepcopy(a); b.update(src_ip='10.1.1.1',dest_ip='10.2.2.2',src_port=100,dest_port=80)
        np.testing.assert_array_equal(features(a),features(b))
    def test_group_reverse_and_repeat(self):
        a=normalize(staging()); b=deepcopy(a)
        b['src_ip'],b['dest_ip']=a['dest_ip'],a['src_ip']; b['src_port'],b['dest_port']=a['dest_port'],a['src_port']
        self.assertEqual(group_key(a),group_key(b)); self.assertEqual(split_for_group(group_key(a)),split_for_group(group_key(b)))
    def test_zero_duration_finite(self):
        s=staging(); s['end_time']=s['start_time']; x=features(normalize(s))
        self.assertTrue(np.isfinite(x).all()); self.assertEqual(len(x),24)
    def test_missing_counter_rejected(self):
        s=staging(); del s['bytes_toclient']
        with self.assertRaises(KeyError): normalize(s)
    def test_invalid_negative_counter_rejected(self):
        s=staging(); s['pkts_toclient']=-1
        with self.assertRaises(ValueError): normalize(s)
    def test_bad_interval_rejected(self):
        s=staging(); s['end_time']='2017-01-01T00:00:00Z'
        with self.assertRaises(ValueError): normalize(s)
    def test_train_only_preprocessor(self):
        x=np.zeros((2,len(FEATURE_NAMES)),dtype=np.float32); x[1]=2
        prep=fit_preprocessor(x); self.assertEqual(prep['mean'][0],1)
        transformed=transform(np.full((1,len(FEATURE_NAMES)),1e9,dtype=np.float32),prep)
        self.assertEqual(transformed.max(),10)
    def test_availability_not_start(self):
        f=normalize(staging()); self.assertEqual(f['available_time'],f['eve_timestamp'])
        self.assertGreater(f['available_time'],f['start_time'])
    def test_alert_is_not_flow(self):
        with self.assertRaises(ValueError): normalize({'event_type':'alert','alert':{'signature_id':9900001}})

class PrepareTests(unittest.TestCase):
    def dataset(self,root,count=180):
        source=root/'source'; source.mkdir(); path=source/'cohort.jsonl'
        counts={name:0 for name in CLASSES}; lines=[]
        for i in range(count):
            label=CLASSES[i%len(CLASSES)]; counts[label]+=1
            lines.append(json.dumps({'schema_version':'cic-experimental-cohort/0.1',
                'record_id':staging(i)['record_id'],'flow':staging(i),'label':None,
                'provisional_label':label,'evidence_tier':'strict','label_evidence':{}}))
        path.write_text('\n'.join(lines)+'\n')
        write_json(source/'report.json',{'version':'cic-experimental-cohort/0.1','complete':True,
                  'days':{'Tuesday':{'labels_by_tier':{'strict':counts,'near_duration':{}}}}})
        return path
    def test_prepare_counts_group_disjoint(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=self.dataset(root); out=root/'prepared'
            with contextlib.redirect_stdout(io.StringIO()):
                prepare(source,out,experimental=True)
            r=read_json(out/'report.json'); self.assertTrue(r['complete'])
            self.assertEqual(sum(v['rows'] for v in r['counts'].values()),180)
            with np.load(out/'data.npz',allow_pickle=False) as data:
                self.assertEqual(data['x'].shape,(180,24))
    def test_provisional_ack_required(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=self.dataset(root)
            with self.assertRaises(ValueError): prepare(source,root/'out')
    def test_manifest_count_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=self.dataset(root)
            source.write_text(source.read_text()+source.read_text().splitlines()[0]+'\n')
            with self.assertRaises(ValueError): prepare(source,root/'out',experimental=True)
            self.assertFalse(read_json(root/'out/report.json')['complete'])

class TrainingTests(unittest.TestCase):
    def test_cpu_train_export_roundtrip(self):
        import torch
        from soc_ai.train import run as train
        from soc_ai.predict import Predictor
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=PrepareTests().dataset(root,count=300)
            with contextlib.redirect_stdout(io.StringIO()):
                prepare(source,root/'prepared',experimental=True)
                train(root/'prepared',root/'model',epochs=2,batch_size=64,device_name='cpu',skip_baseline=False)
            predictor=Predictor(root/'model'); self.assertLess(predictor.verify(),1e-4)
            output=predictor.predict([staging(1)])[0]
            self.assertIn(output['predicted_label'],CLASSES); self.assertTrue(output['experimental'])
            s=staging(2); s['pkts_toserver']=1; s['pkts_toclient']=0
            self.assertEqual(predictor.predict([s])[0]['decision'],'out_of_training_scope')
            model=read_json(root/'model/model.json'); self.assertTrue(model['complete']); self.assertFalse(model['production_ready'])
            (root/'model/preprocessor.json').write_text('{}')
            with self.assertRaises(ValueError): Predictor(root/'model')

if __name__=='__main__': unittest.main()
