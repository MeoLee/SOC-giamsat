import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.request
import urllib.error
import numpy as np
import torch
from http.server import ThreadingHTTPServer
from soc_ai import checkpoint
from soc_ai.common import read_json,write_json
from soc_ai.prepare import run as prepare
from soc_ai.train import run as train
from soc_ai.dashboard import Manager,make_handler
import test_pipeline as fixtures

class CheckpointTests(unittest.TestCase):
    def test_old_checkpoint_format_still_loads(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'latest.pt'
            # v0.2 wrote a torch.save dictionary to the path directly.
            torch.save({'version':checkpoint.VERSION,'step':18,'tensor':torch.arange(3)},path)
            saved=checkpoint.load(path)
            self.assertEqual(saved['step'],18)
            torch.testing.assert_close(saved['tensor'],torch.arange(3))

    def test_training_finishes_despite_status_file_lock(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=fixtures.PrepareTests().dataset(root,count=120); prepared=root/'prepared'
            console=io.StringIO()
            with contextlib.redirect_stdout(console): prepare(source,prepared,experimental=True)
            error=PermissionError('status.json locked'); error.winerror=5
            with mock.patch('soc_ai.workflow.write_json',side_effect=error),contextlib.redirect_stdout(console):
                result=train(prepared,root/'run',epochs=1,batch_size=32,device_name='cpu',skip_baseline=True)
            self.assertEqual(result,'completed')
            self.assertTrue(read_json(root/'run/model.json')['complete'])
            saved=checkpoint.load(root/'run/checkpoints/latest.pt')
            self.assertTrue(saved['progress']['training_done'])
            self.assertEqual(len(saved['progress']['history']),1)
            self.assertIn('WARNING: Could not update dashboard status.json',console.getvalue())

    def test_atomic_failure_preserves_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'latest.pt'; checkpoint.save(p,{'step':1})
            with mock.patch('soc_ai.checkpoint.os.replace',side_effect=OSError('simulated stop')):
                with self.assertRaises(OSError): checkpoint.save(p,{'step':2})
            self.assertEqual(checkpoint.load(p)['step'],1)
    def test_run_lock_blocks_concurrent_worker(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'training.lock'
            with checkpoint.RunLock(path):
                with self.assertRaisesRegex(ValueError,'another process'):
                    with checkpoint.RunLock(path): pass
            with checkpoint.RunLock(path): pass
    def test_rng_restore(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'latest.pt'; torch.manual_seed(1); np.random.seed(1)
            checkpoint.save(p,{'step':1}); expected=torch.rand(5); n=np.random.rand(5)
            data=checkpoint.load(p); checkpoint.restore_rng(data['rng'],torch.device('cpu'))
            torch.testing.assert_close(torch.rand(5),expected,rtol=0,atol=0)
            np.testing.assert_array_equal(np.random.rand(5),n)
    def test_pause_resume_matches_uninterrupted_training(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=fixtures.PrepareTests().dataset(root,count=240); prepared=root/'prepared'
            with contextlib.redirect_stdout(io.StringIO()):
                prepare(source,prepared,experimental=True)
                self.assertEqual(train(prepared,root/'full',epochs=2,batch_size=32,device_name='cpu',skip_baseline=True),'completed')
                self.assertEqual(train(prepared,root/'resumed',epochs=2,batch_size=32,device_name='cpu',skip_baseline=True,pause_after_batches=3),'paused')
            paused=checkpoint.load(root/'resumed/checkpoints/latest.pt')
            self.assertEqual(paused['progress']['offset'],96)
            self.assertEqual(paused['progress']['global_step'],3)
            self.assertTrue(paused['optimizer']['state'])
            self.assertEqual(read_json(root/'resumed/status.json')['status'],'paused')
            # Simulate an incomplete history write after an abrupt stop.
            (root/'resumed/history.jsonl').write_text('partial-write')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(train(None,root/'resumed',resume=True),'completed')
            a=checkpoint.load(root/'full/checkpoints/latest.pt'); b=checkpoint.load(root/'resumed/checkpoints/latest.pt')
            self.assertEqual(a['progress']['global_step'],b['progress']['global_step'])
            for k in a['model']: torch.testing.assert_close(a['model'][k],b['model'][k],rtol=0,atol=0)
            for arow,brow in zip(a['progress']['history'],b['progress']['history']):
                self.assertEqual(arow['train_loss'],brow['train_loss'])
                self.assertEqual(arow['validation_loss'],brow['validation_loss'])
            self.assertEqual(len(read_json(root/'resumed/history.json')),2)
            charts=sorted((root/'resumed/charts').glob('*.png'))
            self.assertEqual(len(charts),7)
            self.assertEqual([int(x.name.split('_')[0]) for x in charts],list(range(1,8)))
            stages=read_json(root/'resumed/status.json')['stages']
            self.assertEqual(next(x for x in stages if x['id']=='lab')['status'],'planned')
            # Changed data/manifest must not silently resume.
            report=read_json(prepared/'report.json'); report['seed']=99; write_json(prepared/'report.json',report)
            with self.assertRaises(ValueError): train(None,root/'resumed',resume=True)

    def test_resume_rejects_changed_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=fixtures.PrepareTests().dataset(root,count=120); prepared=root/'prepared'
            with contextlib.redirect_stdout(io.StringIO()):
                prepare(source,prepared,experimental=True)
                train(prepared,root/'run',epochs=2,batch_size=16,device_name='cpu',skip_baseline=True,pause_after_batches=1)
            report=read_json(prepared/'report.json'); report['seed']=99; write_json(prepared/'report.json',report)
            with self.assertRaisesRegex(ValueError,'Resume dataset/feature mismatch'):
                train(None,root/'run',resume=True)
    def test_numbered_chart_exports(self):
        from soc_ai import charts
        from soc_ai.common import CLASSES
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)
            counts={name:{'rows':2,'classes':{label:1 for label in CLASSES}} for name in ('train','validation','test')}
            charts.preparation(directory,counts)
            self.assertEqual(len(list(directory.glob('*.png'))),2)
            self.assertEqual(len(list(directory.glob('*.svg'))),2)
            items=read_json(directory/'index.json'); self.assertEqual([e['number'] for e in items],[1,2])
            self.assertTrue((directory/items[0]['file']).read_bytes().startswith(b'\x89PNG'))

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.manager=Manager(Path(self.tmp.name)/'AI')
        self.server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.manager))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.tmp.cleanup()
    def test_html_and_state(self):
        html=urllib.request.urlopen(self.base).read().decode()
        self.assertIn('id="workflow"',html)
        self.assertIn('id="lossChart"',html)
        self.assertIn(self.manager.token,html)
        for field in ('patience','local_loss_fraction','skip_baseline'):
            self.assertIn('id="'+field+'"',html)
        state=json.load(urllib.request.urlopen(self.base+'/api/state'))
        self.assertEqual(state['status']['status'],'idle')
        self.assertEqual(len(state['status']['stages']),9)

    def post_action(self, data):
        request=urllib.request.Request(self.base+'/api/action',data=json.dumps(data).encode(),
            headers={'Content-Type':'application/json','X-SOC-Token':self.manager.token})
        return json.load(urllib.request.urlopen(request))

    def test_quality_train_from_http_exports_requested_policy(self):
        from test_quality_training import prepared
        source=Path(self.tmp.name)/'quality-data'; prepared(source)
        target=Path(self.tmp.name)/'quality-run'
        response=self.post_action({'action':'train','prepared':str(source),'run':str(target),
            'epochs':'1','batch_size':'128','device':'cpu','checkpoint_seconds':'30',
            'patience':'7','local_loss_fraction':'0.20','skip_baseline':'true'})
        self.assertEqual(response['message'],'Job started')
        process=self.manager.process
        try:
            process.wait(timeout=55)
            self.assertEqual(process.returncode,0,self.manager.log_path.read_text(encoding='utf-8',errors='replace'))
        finally:
            if process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        model=read_json(target/'model.json'); cfg=model['hyperparameters']
        self.assertTrue(model['complete'])
        self.assertEqual(cfg['local_loss_fraction'],.2)
        self.assertEqual(cfg['patience'],7)
        self.assertTrue(cfg['skip_baseline'])
        self.assertIn('local_quality_check',read_json(target/'metrics.json'))
        # Reloading the dashboard must keep typed settings, then selecting the
        # run must restore its policy even after the form was changed.
        restored=Manager(self.manager.root)
        self.assertEqual(restored.config['local_loss_fraction'],.2)
        response=self.post_action({'action':'select','run':str(target),
            'local_loss_fraction':'0','patience':'1','skip_baseline':'false'})
        self.assertEqual(response['config']['local_loss_fraction'],.2)
        self.assertEqual(response['config']['patience'],7)
        self.assertTrue(response['config']['skip_baseline'])

    def test_invalid_quality_settings_do_not_start_worker(self):
        cases=[{'local_loss_fraction':value} for value in ('nan','inf','-0.1','0.5',True)]
        cases += [{'skip_baseline':'yes'}, {'patience':'0'}]
        with mock.patch('soc_ai.dashboard.subprocess.Popen') as launch:
            for bad in cases:
                with self.subTest(bad=bad):
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        self.post_action({'action':'train','local_loss_fraction':'0.2',
                            'patience':'7','skip_baseline':'true',**bad})
                    self.assertEqual(error.exception.code,400)
            launch.assert_not_called()

    def test_select_legacy_run_resets_quality_options(self):
        run=Path(self.tmp.name)/'legacy'; run.mkdir()
        write_json(run/'model.json',{'hyperparameters':{'prepared_path':'legacy-data','epochs':20}})
        response=self.post_action({'action':'select','run':str(run),
            'local_loss_fraction':'0.2','patience':'7','skip_baseline':'true'})
        self.assertEqual(response['config']['local_loss_fraction'],0)
        self.assertEqual(response['config']['patience'],5)
        self.assertFalse(response['config']['skip_baseline'])
    def test_no_action_without_token(self):
        request=urllib.request.Request(self.base+'/api/action',data=b'{"action":"select"}',headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as e: urllib.request.urlopen(request)
        self.assertEqual(e.exception.code,403)
    def test_select_with_token(self):
        request=urllib.request.Request(self.base+'/api/action',data=b'{"action":"select","run":""}',
            headers={'Content-Type':'application/json','X-SOC-Token':self.manager.token})
        response=json.load(urllib.request.urlopen(request)); self.assertEqual(response['message'],'Run selected')
    def test_asset_traversal_rejected(self):
        with self.assertRaises(urllib.error.HTTPError): urllib.request.urlopen(self.base+'/asset?kind=run&file=..%2Fmodel.json')
    def test_foreign_host_rejected(self):
        request=urllib.request.Request(self.base,headers={'Host':'external.example'})
        with self.assertRaises(urllib.error.HTTPError) as e: urllib.request.urlopen(request)
        self.assertEqual(e.exception.code,403)

    def test_pause_requests_checkpoint_without_terminating_worker(self):
        run=Path(self.tmp.name)/'run'; run.mkdir(); self.manager.config['run']=str(run)
        process=mock.Mock(); process.poll.return_value=None; self.manager.process=process
        self.manager.action('pause',{})
        self.assertTrue((run/'stop.request').exists())
        process.terminate.assert_not_called(); process.kill.assert_not_called()

if __name__=='__main__': unittest.main()
