import numpy as np
import torch
from torch import nn
from pathlib import Path
import zipfile
from .common import CLASSES
from .flow import FEATURE_NAMES

class FlowMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.net=nn.Sequential(nn.Linear(len(FEATURE_NAMES),128),nn.ReLU(),nn.Dropout(0.1),
                               nn.Linear(128,64),nn.ReLU(),nn.Dropout(0.1),
                               nn.Linear(64,len(CLASSES)))
    def forward(self,x): return self.net(x)

def save_weights(model,path):
    np.savez_compressed(path,**{k:v.detach().cpu().numpy() for k,v in model.state_dict().items()})

def load_weights(model,path):
    """Read only bounded numeric NPZ arrays matching this architecture exactly.

    Check NPY headers before numpy allocates arrays; compressed-size checks alone
    do not protect against a tiny archive declaring an enormous array.
    """
    expected=model.state_dict(); maximum_bytes=4*1024*1024
    try:
        path=Path(path)
        if path.stat().st_size>maximum_bytes: raise ValueError('weights archive exceeds 4 MiB limit')
        with zipfile.ZipFile(path) as archive:
            members=archive.infolist(); wanted={name+'.npy':value for name,value in expected.items()}
            if len(members)!=len(wanted) or {item.filename for item in members}!=set(wanted):
                raise ValueError('weight keys do not match model architecture')
            if sum(item.file_size for item in members)>maximum_bytes:
                raise ValueError('uncompressed weights exceed 4 MiB limit')
            for item in members:
                if item.flag_bits&1: raise ValueError('encrypted weights are unsupported')
                with archive.open(item) as stream:
                    version=np.lib.format.read_magic(stream)
                    if version==(1,0):
                        shape,fortran,dtype=np.lib.format.read_array_header_1_0(stream,max_header_size=10000)
                    elif version==(2,0):
                        shape,fortran,dtype=np.lib.format.read_array_header_2_0(stream,max_header_size=10000)
                    else: raise ValueError('unsupported weight NPY version')
                    target=wanted[item.filename]
                    if shape!=tuple(target.shape): raise ValueError('weight shape mismatch: '+item.filename)
                    if dtype.kind not in 'fiu' or dtype.itemsize>8:
                        raise ValueError('weights must be non-pickle real numeric arrays')
                    if item.file_size-stream.tell()!=target.numel()*dtype.itemsize:
                        raise ValueError('weight array length mismatch: '+item.filename)
        with np.load(path,allow_pickle=False) as data:
            state={}
            for name,target in expected.items():
                array=data[name]
                if not np.isfinite(array).all(): raise ValueError('nonfinite weights: '+name)
                with np.errstate(over='ignore',invalid='ignore'):
                    array=array.astype(np.float32)
                if not np.isfinite(array).all(): raise ValueError('weights exceed float32 range: '+name)
                state[name]=torch.from_numpy(array.copy()).to(dtype=target.dtype)
        model.load_state_dict(state,strict=True)
    except (OSError,RuntimeError,TypeError,EOFError,NotImplementedError,zipfile.BadZipFile) as error:
        raise ValueError('invalid model weights: '+str(error)) from error
    return model


@torch.inference_mode()
def predict_batches(model,x,device,active,batch_size=8192,poll=None):
    model.eval(); pieces=[]
    for start in range(0,len(x),batch_size):
        if poll: poll()
        logits=model(torch.from_numpy(x[start:start+batch_size]).to(device))
        logits[:,~active]=-1e9
        pieces.append(torch.softmax(logits,dim=1).cpu().numpy())
    return np.concatenate(pieces)
