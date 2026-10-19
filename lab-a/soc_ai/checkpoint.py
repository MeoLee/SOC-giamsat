"""Atomic full-training checkpoints, safe weights-only loading and RNG restoration."""
import os
from pathlib import Path
import random
import numpy as np
import torch
from .fileio import atomic_writer,open_shared_read

VERSION='soc-training-checkpoint/0.1'

def cpu_copy(value):
    if isinstance(value,torch.Tensor): return value.detach().cpu().clone()
    if isinstance(value,dict): return {k:cpu_copy(v) for k,v in value.items()}
    if isinstance(value,list): return [cpu_copy(v) for v in value]
    if isinstance(value,tuple): return tuple(cpu_copy(v) for v in value)
    return value

def rng_state():
    n=np.random.get_state()
    return {'python':random.getstate(),'numpy':{'name':n[0],'keys':n[1].tolist(),'position':n[2],
            'has_gauss':n[3],'cached_gaussian':n[4]},'torch_cpu':torch.get_rng_state(),
            'torch_cuda':torch.cuda.get_rng_state_all() if torch.cuda.is_available() else []}

def restore_rng(state,device):
    random.setstate(state['python']); n=state['numpy']
    np.random.set_state((n['name'],np.asarray(n['keys'],dtype=np.uint32),n['position'],n['has_gauss'],n['cached_gaussian']))
    torch.set_rng_state(state['torch_cpu'])
    if device.type=='cuda' and state['torch_cuda']:
        if len(state['torch_cuda'])!=torch.cuda.device_count(): raise ValueError('CUDA device count differs from checkpoint')
        torch.cuda.set_rng_state_all(state['torch_cuda'])

def save(path,payload):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with atomic_writer(path) as f:
        torch.save(cpu_copy({'version':VERSION,**payload,'rng':rng_state()}),f)

def load(path):
    with open_shared_read(path) as stream:
        result=torch.load(stream,map_location='cpu',weights_only=True)
    if result.get('version')!=VERSION: raise ValueError('Unsupported checkpoint')
    return result

class RunLock:
    """OS lock automatically released after process death; prevents concurrent resumes."""
    def __init__(self,path): self.path=Path(path); self.file=None
    def __enter__(self):
        self.file=self.path.open('a+b')
        if self.path.stat().st_size==0:
            self.file.write(b'0'); self.file.flush()
        self.file.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.file.close(); self.file=None
            raise ValueError('This run is already being trained by another process')
        return self
    def __exit__(self,*args):
        try:
            self.file.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(),fcntl.LOCK_UN)
        finally: self.file.close()
