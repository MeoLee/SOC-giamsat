"""Corruption tests use a tiny local synthetic bundle; they do not measure accuracy."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import numpy as np
import torch

from soc_ai.common import CLASSES, sha256, write_json
from soc_ai.flow import FEATURE_HASH, FEATURE_NAMES, SPEC, features, fit_preprocessor, normalize, transform
from soc_ai.model import FlowMLP, save_weights
from soc_ai.predict import Predictor


def sample_flow(index=0):
    return normalize({
        'event_type': 'flow', 'timestamp': '2026-10-19T10:00:05Z',
        'src_ip': '192.0.2.10', 'dest_ip': '192.0.2.20', 'src_port': 40000+index,
        'dest_port': 22, 'proto': 'TCP', 'app_proto': 'ssh', 'flow_id': 123+index,
        'flow': {'start': '2026-10-19T10:00:00Z', 'end': '2026-10-19T10:00:04Z',
                 'pkts_toserver': 5+index, 'pkts_toclient': 4,
                 'bytes_toserver': 500+index*100, 'bytes_toclient': 400,
                 'state': 'closed', 'reason': 'timeout'}})


class BundleIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.flows=[sample_flow(0),sample_flow(1)]
        self.x=np.stack([features(flow) for flow in self.flows])
        self.preprocessor=fit_preprocessor(self.x)
        self.model=FlowMLP()
        with torch.no_grad():
            for parameter in self.model.parameters(): parameter.zero_()
        save_weights(self.model,self.root/'model-weights.npz')
        write_json(self.root/'features.json',SPEC)
        write_json(self.root/'preprocessor.json',self.preprocessor)
        self.metadata={'version':'soc-flow-model/0.1','complete':True,
                       'feature_hash':FEATURE_HASH,'classes':CLASSES,
                       'active_classes':[True]*6,'attack_score_threshold':.5,
                       'weights_sha256':sha256(self.root/'model-weights.npz'),
                       'preprocessor_sha256':sha256(self.root/'preprocessor.json')}
        write_json(self.root/'model.json',self.metadata)
        self.golden=[{'flow':flow,'features':features(flow).tolist()} for flow in self.flows]
        write_json(self.root/'golden.json',self.golden)
        self.probabilities=Predictor(self.root).probabilities(self.flows).tolist()
        write_json(self.root/'golden-predictions.json',self.probabilities)

    def replace_json(self,name,value,rehash=False):
        # Deliberately allow malformed nonfinite JSON for validation tests.
        (self.root/name).write_text(json.dumps(value),encoding='utf-8')
        if rehash:
            key={'preprocessor.json':'preprocessor_sha256','model-weights.npz':'weights_sha256'}[name]
            self.metadata[key]=sha256(self.root/name)
            write_json(self.root/'model.json',self.metadata)

    def replace_weights(self,arrays):
        np.savez_compressed(self.root/'model-weights.npz',**arrays)
        self.metadata['weights_sha256']=sha256(self.root/'model-weights.npz')
        write_json(self.root/'model.json',self.metadata)

    def arrays(self):
        return {key:value.detach().numpy().copy() for key,value in self.model.state_dict().items()}

    def test_valid_bundle_preserves_feature_contract_and_cpu_roundtrip(self):
        self.assertEqual(FEATURE_HASH,'5e023c54512136448cfb711ab424a19c5ba2c9bf3240c0543c8fc4d0c1b0a065')
        predictor=Predictor(self.root)
        self.assertEqual(predictor.verify(),0)
        result=predictor.predict(self.flows)
        self.assertEqual(len(result),2)
        self.assertAlmostEqual(result[0]['attack_score'],5/6,places=6)
        self.assertEqual(result[0]['predicted_label'],'BENIGN')

    def test_active_mask_is_exact_boolean_six_classes(self):
        for mask in (None,[],[True]*5,[True]*7,[1]*6,['true']*6,
                     [False,True,True,True,True,True],[True,False,False,False,False,False]):
            with self.subTest(mask=mask):
                metadata=deepcopy(self.metadata); metadata['active_classes']=mask
                self.replace_json('model.json',metadata)
                with self.assertRaises(ValueError): Predictor(self.root)

    def test_threshold_rejects_nonfinite_boolean_and_out_of_range(self):
        for threshold in (None,True,'0.5',float('nan'),float('inf'),-.001,1.00001,10**400):
            with self.subTest(threshold=threshold):
                metadata=deepcopy(self.metadata); metadata['attack_score_threshold']=threshold
                self.replace_json('model.json',metadata)
                with self.assertRaises(ValueError): Predictor(self.root)

    def test_existing_threshold_sentinel_above_one_is_accepted(self):
        self.metadata['attack_score_threshold']=float(np.nextafter(1.0,np.inf))
        write_json(self.root/'model.json',self.metadata)
        predictor=Predictor(self.root)
        self.assertEqual(predictor.verify(),0)
        self.assertEqual(predictor.predict(self.flows)[0]['decision'],'below_alert_threshold')

    def test_missing_and_changed_features_contract_rejected(self):
        for contract in (None,[],{},dict(SPEC,requires_completed_flow=False),
                         dict(SPEC,names=list(reversed(FEATURE_NAMES))),dict(SPEC,extra='ignored?')):
            with self.subTest(contract=contract):
                self.replace_json('features.json',contract)
                with self.assertRaises(ValueError): Predictor(self.root)
        (self.root/'features.json').unlink()
        with self.assertRaises(ValueError): Predictor(self.root)

    def test_preprocessor_semantics_rejected_even_with_updated_hash(self):
        cases=[]
        for key,value in [('mean',[0]*23),('std',[1]*25),('clip',0),('clip',11),
                          ('clip',True),('clip',float('nan'))]:
            cases.append(dict(self.preprocessor,**{key:value}))
        for key,value in [('mean',float('nan')),('mean',float('inf')),('mean',1e100),
                          ('mean',True),('std',float('nan')),('std',0),('std',-1),('std',1e-100)]:
            broken=deepcopy(self.preprocessor); broken[key][0]=value; cases.append(broken)
        for index,preprocessor in enumerate(cases):
            with self.subTest(index=index):
                self.replace_json('preprocessor.json',preprocessor,rehash=True)
                with self.assertRaises(ValueError): Predictor(self.root)

    def test_transform_rejects_nonfinite_or_broadcast_feature_inputs(self):
        for value in (np.zeros(24),np.zeros((1,1)),np.zeros((2,23)),
                      np.full((1,24),np.nan),np.full((1,24),np.inf),[['0']*24],[[True]*24]):
            with self.subTest(shape=np.shape(value)):
                with self.assertRaises(ValueError): transform(value,self.preprocessor)

    def test_weights_require_exact_keys_shapes_and_real_numeric_values(self):
        cases=[]
        wrong=self.arrays(); wrong.pop('net.0.bias'); cases.append(wrong)
        wrong=self.arrays(); wrong['unexpected']=np.zeros(1); cases.append(wrong)
        wrong=self.arrays(); wrong['net.0.bias']=np.zeros((1,128)); cases.append(wrong)
        for dtype in (object,complex,bool,'U1'):
            wrong=self.arrays(); wrong['net.0.bias']=np.zeros(128,dtype=dtype); cases.append(wrong)
        for value in (np.nan,np.inf,1e100):
            wrong=self.arrays(); wrong['net.0.bias']=np.full(128,value,dtype=np.float64); cases.append(wrong)
        for index,arrays in enumerate(cases):
            with self.subTest(index=index):
                self.replace_weights(arrays)
                with self.assertRaises(ValueError): Predictor(self.root)

    def test_oversized_weight_archive_rejected(self):
        (self.root/'model-weights.npz').write_bytes(b'0'*(4*1024*1024+1))
        self.metadata['weights_sha256']=sha256(self.root/'model-weights.npz')
        write_json(self.root/'model.json',self.metadata)
        with self.assertRaisesRegex(ValueError,'4 MiB'): Predictor(self.root)

    def test_forged_npy_shape_rejected_before_allocating_array(self):
        header=io.BytesIO()
        np.lib.format.write_array_header_1_0(header,{'descr':'<f4','fortran_order':False,'shape':(10**12,)})
        with zipfile.ZipFile(self.root/'model-weights.npz','w') as archive:
            for key,value in self.arrays().items():
                if key=='net.0.bias': payload=header.getvalue()
                else:
                    stream=io.BytesIO(); np.save(stream,value,allow_pickle=False); payload=stream.getvalue()
                archive.writestr(key+'.npy',payload)
        self.metadata['weights_sha256']=sha256(self.root/'model-weights.npz')
        write_json(self.root/'model.json',self.metadata)
        with self.assertRaisesRegex(ValueError,'shape mismatch'): Predictor(self.root)

    def test_golden_vectors_require_nonempty_object_entries(self):
        predictor=Predictor(self.root)
        for golden in ([],{},None,[0],[{}],[{'flow':self.flows[0]}]):
            with self.subTest(golden=golden):
                self.replace_json('golden.json',golden)
                with self.assertRaises(ValueError): predictor.verify()

    def test_golden_features_reject_broadcasting_nonfinite_and_changed_values(self):
        predictor=Predictor(self.root)
        for value in (0,[0],[[0]*24],[float('nan')]*24,[True]*24,['0']*24,[0]*24):
            with self.subTest(features=value):
                golden=deepcopy(self.golden); golden[0]['features']=value
                self.replace_json('golden.json',golden)
                with self.assertRaises(ValueError): predictor.verify()

    def test_golden_invalid_flow_inputs_are_rejected(self):
        predictor=Predictor(self.root)
        for key,value in [('duration_seconds',float('nan')),('duration_seconds',-1),
                          ('duration_seconds',8),('start_time','invalid timestamp'),
                          ('pkts_toserver',-1),('pkts_toserver',True),('app_protocol',None)]:
            with self.subTest(key=key,value=value):
                golden=deepcopy(self.golden); golden[0]['flow'][key]=value
                self.replace_json('golden.json',golden)
                with self.assertRaises(ValueError): predictor.verify()

    def test_golden_probabilities_require_exact_shape_finite_bounds_and_unit_sum(self):
        predictor=Predictor(self.root)
        cases=[0,[],[1/6]*6,[[1/6]*6],[[1/6],[1/6]],[[.2]*6]*2,
               [[float('nan')]*6]*2,[[float('inf')]*6]*2,[[True]*6]*2]
        for value in (-1e-50,1+1e-12):
            broken=deepcopy(self.probabilities); broken[0][0]=value; cases.append(broken)
        for index,probabilities in enumerate(cases):
            with self.subTest(index=index):
                self.replace_json('golden-predictions.json',probabilities)
                with self.assertRaises(ValueError): predictor.verify()

    def test_two_class_bundle_remains_valid_and_inactive_mass_is_rejected(self):
        self.metadata['active_classes']=[True,True,False,False,False,False]
        write_json(self.root/'model.json',self.metadata)
        predictor=Predictor(self.root)
        probabilities=predictor.probabilities(self.flows).tolist()
        self.replace_json('golden-predictions.json',probabilities)
        self.assertEqual(predictor.verify(),0)
        probabilities[0][1]-=1e-8; probabilities[0][2]=1e-8
        self.replace_json('golden-predictions.json',probabilities)
        with self.assertRaisesRegex(ValueError,'inactive'): predictor.verify()

    def test_golden_valid_distribution_with_changed_inference_is_rejected(self):
        probabilities=deepcopy(self.probabilities)
        probabilities[0][0]+=.1; probabilities[0][1]-=.1
        self.replace_json('golden-predictions.json',probabilities)
        with self.assertRaisesRegex(ValueError,'inference mismatch'): Predictor(self.root).verify()

    def test_checksum_changes_and_malformed_json_raise_value_error(self):
        (self.root/'preprocessor.json').write_text('{}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'integrity'): Predictor(self.root)
        (self.root/'model.json').write_text('{',encoding='utf-8')
        with self.assertRaises(ValueError): Predictor(self.root)


if __name__=='__main__': unittest.main()
