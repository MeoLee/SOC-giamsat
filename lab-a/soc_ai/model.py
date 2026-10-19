import numpy as np
import torch
from torch import nn
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
    with np.load(path,allow_pickle=False) as data:
        state={k:torch.from_numpy(data[k].copy()) for k in data.files}
    model.load_state_dict(state,strict=True)
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
