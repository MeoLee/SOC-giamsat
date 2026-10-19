"""Human-readable, persisted workflow status used by CLI and local dashboard."""
from datetime import datetime,timezone
import os
import time
from pathlib import Path
from .common import write_json,read_json

STAGES=[('prepare','Prepare data','Normalize flows, extract features and split connection groups.'),
        ('load','Load training data','Check the prepared dataset and load the training configuration.'),
        ('train','Train model','Update model weights batch by batch; save resumable checkpoints.'),
        ('validation','Validate epoch','Measure validation loss/F1 and keep the best model.'),
        ('evaluation','Evaluate holdout','Evaluate the selected model on held-out test data.'),
        ('baseline','Compare baseline','Compare against a linear classifier on the same split.'),
        ('export','Export and verify','Save the model/preprocessor and verify portable inference.'),
        ('lab','Independent lab experiment','Planned: replay or consume lab logs and measure detection.'),
        ('correlation','Correlation and Grafana','Planned: combine flow/auth events and report attack chains.')]

def now(): return datetime.now(timezone.utc).isoformat()

class Workflow:
    def __init__(self,directory,kind):
        self.directory=Path(directory); self.kind=kind
        self.state={'version':'soc-workflow/0.1','kind':kind,'status':'running','pid':os.getpid(),
                    'updated_at':now(),'stage':'prepare' if kind=='prepare' else 'load',
                    'message':'Starting','stages':[{ 'id':key,'title':title,'description':description,
                     'status':'planned' if key in ('lab','correlation') else 'pending'} for key,title,description in STAGES]}
        if kind=='train': self.state['stages'][0]['status']='done'
        self.update(self.state['stage'],'Starting')
    def update(self,stage,message,**fields):
        self.state.update(stage=stage,message=message,updated_at=now(),**fields)
        for item in self.state['stages']:
            if item['id']==stage: item['status']='active'
            elif item['status']=='active': item['status']='done'
        self._persist()
    def finish(self,status,message):
        self.state.update(status=status,message=message,updated_at=now())
        for item in self.state['stages']:
            if item['status']=='active': item['status']=status if status!='completed' else 'done'
        self._persist()
    def _persist(self):
        # Progress is best effort; checkpoint/model writes remain mandatory.
        try:
            write_json(self.directory/'status.json',self.state)
            self._status_warning_at=None
            return True
        except OSError as exc:
            last=getattr(self,'_status_warning_at',None)
            if last is None or time.monotonic()-last>=60:
                print(f'WARNING: Could not update dashboard status.json: {exc}. '
                      'Training state is unchanged; checkpoint writes are still mandatory.',flush=True)
                self._status_warning_at=time.monotonic()
            return False
