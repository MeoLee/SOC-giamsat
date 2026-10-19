import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from soc_ai.common import CLASSES,read_json,write_json,sha256
from soc_ai.flow import FEATURE_HASH,features,normalize
from soc_ai.metrics import choose_threshold,evaluate


def event(i,local=False):
    return {'event_type':'flow','record_id':str(i),'timestamp':'2026-10-15T06:02:00Z',
        'src_ip':'10.0.0.2','dest_ip':'10.0.0.3','src_port':30000+i,'dest_port':80,
        'proto':'TCP','app_proto':'http' if local else ('http','ftp','ssh')[i%3],
        'flow':{'start':'2026-10-15T06:00:00.000000Z',
            'end':f'2026-10-15T06:00:{i%20:02d}.{1000+i:06d}Z',
            'pkts_toserver':6+i%15,'pkts_toclient':4+i%8,
            'bytes_toserver':492+i,'bytes_toclient':510+i%300,
            'state':'closed','reason':'timeout'}}


def prepared(root,nlocal=100):
    root.mkdir();xs=[];ys=[];splits=[];days=[];golden=[]
    for role in range(3):
        for i in range(180):
            e=event(role*500+i);f=normalize(e);x=features(f)
            xs.append(x);ys.append(i%6);splits.append(role);days.append(0)
            if len(golden)<2:golden.append({'flow':f,'features':x.tolist()})
        for i in range(nlocal):
            e=event(2000+role*500+i,True)
            xs.append(features(normalize(e)));ys.append(0);splits.append(role);days.append(role+1)
    np.savez_compressed(root/'data.npz',x=np.stack(xs),y=np.array(ys),split=np.array(splits),
                        day=np.array(days),tier=np.zeros(len(ys),dtype=np.uint8))
    write_json(root/'golden.json',golden)
    write_json(root/'report.json',{'version':'soc-prepared/0.1','complete':True,
        'feature_hash':FEATURE_HASH,'classes':CLASSES,'seed':42,
        'data_sha256':sha256(root/'data.npz'),'split_policy':'synthetic test only',
        'day_names':['BASE','LAB:train:synthetic','LAB:validation:synthetic','LAB:test:synthetic'],
        'warnings':['Synthetic fixture; not a detection benchmark.']})


class ThresholdTests(unittest.TestCase):
    def test_float32_ties_do_not_exceed_selected_fpr(self):
        y=np.zeros(100,dtype=int);p=np.zeros((100,6),dtype=np.float32)
        p[:,0]=np.float32(.9);p[:,1]=1-p[:,0]
        t=choose_threshold(y,p)
        self.assertEqual(evaluate(y,p,t)['binary_attack']['fp'],0)
    def test_small_local_group_not_drowned_by_base(self):
        y=np.array([0,0,0,0,1]);p=np.zeros((5,6),dtype=np.float32)
        p[:,0]=[.999,.998,.6,.5,.1];p[:,1]=1-p[:,0]
        t=choose_threshold(y,p,np.array(['base','base','local','local','base']))
        result=evaluate(y,p,t)['binary_attack']
        self.assertEqual(result['fp'],0);self.assertEqual(result['tp'],1)


class QualityTrainingTests(unittest.TestCase):
    def test_quality_train_pause_resume_export_keeps_policy(self):
        import torch
        from soc_ai.train import run
        from soc_ai.predict import Predictor
        from soc_ai import charts
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'prepared';prepared(source)
            with patch.object(charts,'epoch'),patch.object(charts,'final'),contextlib.redirect_stdout(io.StringIO()):
                run(source,root/'full',epochs=2,batch_size=64,device_name='cpu',skip_baseline=True,local_loss_fraction=.2)
                result=run(source,root/'resumed',epochs=2,batch_size=64,device_name='cpu',skip_baseline=True,
                    local_loss_fraction=.2,pause_after_batches=1)
                self.assertEqual(result,'paused')
                run(None,root/'resumed',resume=True)
            a=Predictor(root/'full');b=Predictor(root/'resumed')
            self.assertLess(a.verify(),1e-4);self.assertLess(b.verify(),1e-4)
            self.assertEqual(read_json(root/'resumed/model.json')['hyperparameters']['local_loss_fraction'],.2)
            self.assertIn('local_quality_check',read_json(root/'resumed/metrics.json'))
            for key,value in a.model.state_dict().items():torch.testing.assert_close(value,b.model.state_dict()[key],rtol=0,atol=0)
    def test_tiny_local_data_is_rejected_before_quality_training(self):
        from soc_ai.train import run
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);prepared(root/'prepared',nlocal=8)
            with self.assertRaisesRegex(ValueError,'at least 100'):
                run(root/'prepared',root/'run',epochs=1,device_name='cpu',skip_baseline=True,local_loss_fraction=.2)


if __name__=='__main__':unittest.main()
