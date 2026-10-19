"""Local-only dashboard; launch CLI jobs without shell and request graceful pause."""
import argparse
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import math
import mimetypes
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
from urllib.parse import urlparse,parse_qs
from .common import read_json,write_json
from .fileio import read_bytes
from .workflow import STAGES

TRAINING_DEFAULTS = {'patience':5, 'local_loss_fraction':0.0, 'skip_baseline':False}
CONFIG_FIELDS = ('cohort','prepared','run','epochs','batch_size','device',
                 'checkpoint_seconds',*TRAINING_DEFAULTS)


def optional_json(path,default=None):
    try: return read_json(path)
    except (OSError,ValueError): return default

def alive(pid):
    if not pid: return False
    if os.name=='nt':
        import ctypes
        kernel=ctypes.windll.kernel32
        kernel.OpenProcess.restype=ctypes.c_void_p
        handle=kernel.OpenProcess(0x1000,False,int(pid))
        if not handle: return False
        code=ctypes.c_ulong()
        ok=kernel.GetExitCodeProcess(ctypes.c_void_p(handle),ctypes.byref(code))
        kernel.CloseHandle(ctypes.c_void_p(handle))
        return bool(ok and code.value==259)
    try: os.kill(int(pid),0); return True
    except OSError: return False

class Manager:
    def __init__(self,root):
        self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
        defaults={'cohort':str(self.root.parent/'dataset/normalized/CICIDS2017/experimental-cohort-20261011-184306/cohort.jsonl'),
                  'prepared':str(self.root/'prepared-v01'),'run':'','epochs':20,'batch_size':2048,
                  'device':'cuda','checkpoint_seconds':30,**TRAINING_DEFAULTS}
        self.config={**defaults,**(optional_json(self.root/'dashboard-session.json',{}) or {})}
        self.process=None; self.job=None; self.lock=threading.Lock(); self.pending_pause=False
        self.log_path=self.root/'dashboard-console.log'; self.token=secrets.token_urlsafe(32)
        self.project=Path(__file__).resolve().parent.parent
    def status(self):
        prepared=Path(self.config['prepared']); run=Path(self.config['run']) if self.config['run'] else None
        prep=optional_json(prepared/'report.json',{}) or {}
        status=optional_json(run/'status.json',{}) if run else {}
        if not status: status=optional_json(prepared/'status.json',{}) or {}
        if not status:
            status={'status':'idle','message':'Choose a prepared dataset or prepare your cohort.',
                    'stages':[{'id':k,'title':t,'description':d,'status':'done' if k=='prepare' and prep.get('complete') else 'planned' if k in ('lab','correlation') else 'pending'} for k,t,d in STAGES]}
        is_alive=self.process is not None and self.process.poll() is None
        external_alive=bool(status.get('status')=='running' and alive(status.get('pid')))
        if status.get('status')=='running' and not is_alive and not external_alive:
            status={**status,'status':'interrupted','message':'Process is no longer running. Resume from the latest checkpoint.'}
        history=optional_json(run/'history.json',[]) if run else []
        metrics=optional_json(run/'metrics.json',{}) if run else {}
        model=optional_json(run/'model.json',{}) if run else {}
        recent=sorted((self.root/'runs').glob('*/model.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:30]
        images=[]
        for kind,directory in [('prepared',prepared),('run',run)]:
            if directory:
                for p in sorted((directory/'charts').glob('*.png')):
                    images.append({'kind':kind,'file':p.name,'mtime':p.stat().st_mtime})
        log=''
        if self.log_path.exists():
            with self.log_path.open('rb') as f:
                f.seek(max(0,self.log_path.stat().st_size-16000)); log=f.read().decode('utf-8',errors='replace')
        return {'config':self.config,'status':status,'history':history,'metrics':metrics,'model':model,
                'prepared_report':prep,'charts':images,'recent_runs':[str(p.parent) for p in recent],
                'busy':is_alive or external_alive,'can_resume':bool(run and (run/'checkpoints/latest.pt').exists() and not model.get('complete')),
                'log':log,'job':self.job,'checkpoint_saved':bool(run and (run/'checkpoints/latest.pt').exists())}
    def action(self,action,data):
        with self.lock:
            if action=='pause':
                run=Path(self.config['run']) if self.config['run'] else None
                if not run: raise ValueError('No training run selected')
                self.pending_pause=True
                if run.exists(): (run/'stop.request').write_text('pause requested',encoding='utf-8')
                return {'message':'Pause requested. Wait for Paused / checkpoint saved before shutdown.'}
            if self.status()['busy']: raise ValueError('A job is running. Pause and wait before starting another job.')
            for key in CONFIG_FIELDS:
                if key in data: self.config[key]=data[key]
            if action in ('select','resume') and self.config['run']:
                metadata=optional_json(Path(self.config['run'])/'model.json',{}) or {}
                cfg=metadata.get('hyperparameters',{})
                if cfg.get('prepared_path'):
                    self.config['prepared']=cfg['prepared_path']
                    for k in ('epochs','batch_size','device','checkpoint_seconds'):
                        if k in cfg: self.config[k]=cfg[k]
                    # Legacy runs must not inherit Quality settings from another run.
                    for k,value in TRAINING_DEFAULTS.items(): self.config[k]=cfg.get(k,value)
            if action=='select':
                write_json(self.root/'dashboard-session.json',self.config); return {'message':'Run selected','config':self.config}
            if action not in ('prepare','train','resume','verify'): raise ValueError('Unknown action')
            command=[sys.executable,'-u','-m','soc_ai']
            if action=='prepare':
                target=Path(self.config['prepared']); command+=['prepare','--cohort',str(self.config['cohort']),
                    '--output',str(target),'--experimental-labels']
            elif action=='train':
                epochs=int(self.config['epochs']); batch=int(self.config['batch_size']); seconds=int(self.config['checkpoint_seconds'])
                patience=int(self.config['patience'])
                if not 1<=epochs<=1000 or not 1<=batch<=65536 or not 1<=seconds<=3600 or not 1<=patience<=1000: raise ValueError('Training settings outside supported range')
                if isinstance(self.config['local_loss_fraction'],bool): raise ValueError('Local loss fraction must be a number from 0 to less than 0.5')
                fraction=float(self.config['local_loss_fraction'])
                if not math.isfinite(fraction) or not 0<=fraction<.5: raise ValueError('Local loss fraction must be a number from 0 to less than 0.5')
                skip=self.config['skip_baseline']
                if isinstance(skip,str) and skip in ('true','false'): skip=skip=='true'
                if not isinstance(skip,bool): raise ValueError('Skip baseline must be true or false')
                self.config.update(patience=patience,local_loss_fraction=fraction,skip_baseline=skip)
                if self.config['device'] not in ('cpu','cuda'): raise ValueError('Unknown device')
                prefix='mlp04-quality-' if fraction else 'mlp04-'
                target=Path(self.config['run']) if self.config['run'] else self.root/'runs'/(prefix+datetime.now().strftime('%Y%m%d-%H%M%S'))
                self.config['run']=str(target)
                command+=['train','--prepared',str(self.config['prepared']),'--output',str(target),
                    '--epochs',str(epochs),'--batch-size',str(batch),'--device',self.config['device'],'--checkpoint-seconds',str(seconds),
                    '--patience',str(patience),'--local-loss-fraction',str(fraction)]
                if skip: command+=['--skip-baseline']
            elif action=='resume':
                target=Path(self.config['run']); command+=['train','--resume',str(target)]
                if not (target/'checkpoints/latest.pt').exists(): raise ValueError('No resumable checkpoint in selected folder')
            else:
                target=Path(self.config['run']); command+=['predict','--model',str(target),'--verify-only','--device','cpu']
            if action in ('prepare','train') and target.exists(): raise ValueError('Output folder already exists. Reuse completed prepared data or choose a new run folder.')
            self.pending_pause=False
            write_json(self.root/'dashboard-session.json',self.config)
            log=self.log_path.open('wb')
            options={'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
            try:
                self.process=subprocess.Popen(command,cwd=self.project,stdout=log,stderr=subprocess.STDOUT,**options)
            finally: log.close()
            self.job={'action':action,'directory':str(target),'pid':self.process.pid,'exit_code':None}
            process=self.process; job=self.job
            def monitor():
                while process.poll() is None:
                    if self.pending_pause and action in ('train','resume') and target.exists():
                        (target/'stop.request').write_text('pause requested',encoding='utf-8')
                    try: process.wait(timeout=.5)
                    except subprocess.TimeoutExpired: pass
                job['exit_code']=process.returncode
                if process.returncode:
                    s=optional_json(target/'status.json',{}) or {}
                    s.update(status='failed',message='Job failed. Read the console log for details.')
                    if target.exists():
                        try: write_json(target/'status.json',s)
                        except OSError as exc: print(f'WARNING: Could not update failed job status: {exc}',flush=True)
            threading.Thread(target=monitor,daemon=True).start()
            return {'message':'Job started','run':self.config['run'],'config':self.config}
    def asset(self,kind,name):
        if Path(name).name!=name: raise ValueError('Invalid file name')
        root=Path(self.config['prepared']) if kind=='prepared' else Path(self.config['run']) if kind=='run' and self.config['run'] else None
        if root is None: raise ValueError('No directory selected')
        if name.endswith(('.png','.svg')): path=root/'charts'/name
        elif name in ('metrics.json','model.json','preprocessor.json','features.json','model-weights.npz','requirements-lock.txt','history.json'):
            path=root/name
        else: raise ValueError('Unsupported asset')
        return path

def make_handler(manager):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,code,body,content_type='application/json'):
            self.send_response(code); self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(body))); self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(body)
        def valid_host(self):
            return self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}')
        def do_GET(self):
            if not self.valid_host():
                self.send(403,b'{}'); return
            parsed=urlparse(self.path)
            try:
                if parsed.path=='/':
                    html=(Path(__file__).parent/'web/dashboard.html').read_text(encoding='utf-8').replace('__TOKEN__',manager.token)
                    self.send(200,html.encode(),'text/html; charset=utf-8')
                elif parsed.path=='/api/state': self.send(200,json.dumps(manager.status()).encode())
                elif parsed.path=='/asset':
                    query=parse_qs(parsed.query); path=manager.asset(query.get('kind',['run'])[0],query.get('file',[''])[0])
                    self.send(200,read_bytes(path),mimetypes.guess_type(path.name)[0] or 'application/octet-stream')
                else: self.send(404,b'{}')
            except (OSError,ValueError) as e: self.send(400,json.dumps({'error':str(e)}).encode())
        def do_POST(self):
            if not self.valid_host() or urlparse(self.path).path!='/api/action':
                self.send(403,b'{}'); return
            if self.headers.get('X-SOC-Token')!=manager.token:
                self.send(403,b'{"error":"Invalid local session token"}'); return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if length>20000: raise ValueError('Request too large')
                data=json.loads(self.rfile.read(length)); result=manager.action(data.pop('action'),data)
                self.send(200,json.dumps(result).encode())
            except (ValueError,OSError,KeyError,TypeError) as e: self.send(400,json.dumps({'error':str(e)}).encode())
    return Handler

def main():
    p=argparse.ArgumentParser(description='Local SOC AI workflow dashboard')
    p.add_argument('--root',type=Path,required=True); p.add_argument('--port',type=int,default=8765)
    a=p.parse_args(); manager=Manager(a.root); server=ThreadingHTTPServer(('127.0.0.1',a.port),make_handler(manager))
    print(f'DASHBOARD: http://127.0.0.1:{server.server_port}',flush=True)
    print('Pause & save training before closing the dashboard or shutting down.',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt:
        if manager.process and manager.process.poll() is None and manager.job['action'] in ('train','resume'):
            manager.action('pause',{})
            try: manager.process.wait(timeout=30)
            except subprocess.TimeoutExpired: print('Pause still pending. Check the training status before shutting down.',flush=True)
    finally: server.server_close()

if __name__=='__main__': main()
