import argparse
from copy import deepcopy
import json
import math
import os
import platform
from pathlib import Path
import random
import signal
import subprocess
import sys
import time
import numpy as np
import torch
from torch import nn
from sklearn.linear_model import SGDClassifier
from .common import CLASSES,read_json,write_json,sha256
from .flow import FEATURE_HASH,SPEC,fit_preprocessor,transform
from .model import FlowMLP,save_weights,load_weights,predict_batches
from .metrics import evaluate,choose_threshold
from .data_contract import load_prepared
from .workflow import Workflow,now
from . import checkpoint,charts


class PauseTraining(Exception): pass

QUALITY_SELECTION = 'quality-present-class-and-attack-recall/0.2'
LEGACY_QUALITY_SELECTION = 'quality-legacy/0.1'
STANDARD_SELECTION = 'macro-f1-six-class/0.1'


def quality_selection(y, probs, is_local, threshold, active_classes, *, policy=QUALITY_SELECTION):
    """Choose an epoch with validation only; expose every component and support.

    The legacy branch is retained so a pre-upgrade checkpoint keeps exactly the
    objective used by its already committed best epoch.
    """
    from sklearn.metrics import f1_score
    y = np.asarray(y)
    local = np.asarray(is_local, dtype=bool)
    if local.shape != y.shape or not local.any() or local.all():
        raise ValueError('Quality selection requires both local and base validation rows')
    pred = probs.argmax(axis=1)
    local_labels = np.unique(y[local])
    local_f1 = float(f1_score(y[local], pred[local], labels=local_labels, average='macro', zero_division=0))
    external = evaluate(y[~local], probs[~local], threshold)
    coverage = {name: int(np.sum(y[~local] == i)) for i, name in enumerate(CLASSES)}
    if policy == LEGACY_QUALITY_SELECTION:
        whole = evaluate(y, probs, threshold)
        components = {
            'external_six_class_macro_f1': float(external['multiclass']['macro avg']['f1-score']),
            'local_present_class_macro_f1': local_f1,
            'aggregate_validation_attack_recall': float(whole['binary_attack']['recall'] or 0),
        }
        score = len(components) / sum(1 / max(value, 1e-12) for value in components.values())
    elif policy == QUALITY_SELECTION:
        labels = np.unique(y[~local])
        external_f1 = float(f1_score(y[~local], pred[~local], labels=labels, average='macro', zero_division=0))
        missing = [CLASSES[i] for i, active in enumerate(active_classes) if active and coverage[CLASSES[i]] == 0]
        if missing:
            raise ValueError('Quality validation is missing active base classes: ' + ', '.join(missing))
        attack_recalls = [float(external['attack_types'][name]['attack_alert_recall'])
                          for i, name in enumerate(CLASSES[1:], 1) if active_classes[i]]
        local_benign = local & (y == 0)
        if not local_benign.any() or not attack_recalls:
            raise ValueError('Quality validation requires local BENIGN and base attack examples')
        local_specificity = float(np.mean((1.0 - np.asarray(probs[local_benign], dtype=np.float64)[:, 0]) < threshold))
        components = {
            'external_present_class_macro_f1': external_f1,
            'local_present_class_macro_f1': local_f1,
            'base_attack_class_macro_recall': float(np.mean(attack_recalls)),
            'base_attack_class_minimum_recall': float(min(attack_recalls)),
            'local_benign_specificity': local_specificity,
        }
        score = (len(components) / sum(1 / value for value in components.values())
                 if all(value > 0 for value in components.values()) else 0.0)
    else:
        raise ValueError('Unknown quality selection policy: ' + str(policy))
    detail = {
        'policy': policy, 'aggregation': 'harmonic mean', 'components': components,
        'external_class_support': coverage, 'local_rows': int(local.sum()),
        'local_class_support': {name: int(np.sum(y[local] == i)) for i, name in enumerate(CLASSES)},
        'threshold': float(threshold), 'threshold_source': 'validation BENIGN only',
        'test_used_for_selection': False,
        'note': 'Validation diagnostics select an epoch; independent detection quality remains unproven.',
    }
    if policy == QUALITY_SELECTION:
        # A missed class gives primary score zero. Still track learning progress
        # within an exact tie, rather than stopping while every epoch is zero.
        detail['exact_tie_breaker'] = {'policy': 'mean validation components',
                                      'value': float(np.mean(list(components.values())))}
    return float(score), detail

def weighted_validation_loss(y,probs,weights):
    selected=np.clip(probs[np.arange(len(y)),y],1e-12,1)
    w=weights[y]
    return float(np.sum(-np.log(selected)*w)/max(float(w.sum()),1e-12))

def run(prepared,output,epochs=20,batch_size=2048,device_name='cuda',patience=5,
        skip_baseline=False,resume=False,checkpoint_seconds=30,pause_after_batches=None,local_loss_fraction=0.0):
    output=Path(output).resolve()
    if not resume: output.mkdir(parents=True,exist_ok=False)
    elif not output.is_dir(): raise ValueError('Resume run folder not found')
    with checkpoint.RunLock(output/'training.lock'):
        saved=checkpoint.load(output/'checkpoints/latest.pt') if resume else None
        if saved:
            cfg=saved['config']; prepared=Path(cfg['prepared_path'])
            epochs=cfg['epochs']; batch_size=cfg['batch_size']; device_name=cfg['device']; patience=cfg['patience']
            skip_baseline=cfg['skip_baseline']; checkpoint_seconds=cfg['checkpoint_seconds']
            local_loss_fraction=cfg.get('local_loss_fraction',0.0)
            if read_json(output/'model.json').get('complete'): raise ValueError('Run already complete; start a new run for a new experiment')
            (output/'stop.request').unlink(missing_ok=True)
        else: prepared=Path(prepared).resolve()
        workflow=Workflow(output,'train')
        try:
            return _run(prepared,output,workflow,saved,epochs,batch_size,device_name,patience,
                        skip_baseline,checkpoint_seconds,pause_after_batches,local_loss_fraction)
        except Exception as exc:
            workflow.finish('failed',str(exc))
            if (output/'model.json').exists():
                try:
                    m=read_json(output/'model.json'); m['complete']=False; write_json(output/'model.json',m)
                except (OSError,ValueError) as secondary:
                    print(f'WARNING: Could not record the training error in model.json: {secondary}',flush=True)
            raise

def _run(prepared,output,workflow,saved,epochs,batch_size,device_name,patience,skip_baseline,checkpoint_seconds,pause_after_batches,local_loss_fraction):
    workflow.update('load','Checking dataset integrity and loading arrays')
    prepared_data=load_prepared(prepared)
    report=prepared_data.report
    data_hash=prepared_data.data_sha256; report_hash=prepared_data.report_sha256
    if min(epochs,batch_size,patience,checkpoint_seconds)<1: raise ValueError('Training settings must be positive')
    if saved and (saved['prepared_data_sha256']!=data_hash or saved['prepared_report_sha256']!=report_hash or saved['feature_hash']!=FEATURE_HASH):
        raise ValueError('Resume dataset/feature mismatch')
    if device_name=='cuda' and not torch.cuda.is_available(): raise ValueError('CUDA unavailable; no silent CPU fallback')
    device=torch.device(device_name); seed=report['seed']
    selection_policy=(saved['config'].get('selection_policy', LEGACY_QUALITY_SELECTION if local_loss_fraction else STANDARD_SELECTION)
                      if saved else QUALITY_SELECTION if local_loss_fraction else STANDARD_SELECTION)
    if selection_policy not in (QUALITY_SELECTION,LEGACY_QUALITY_SELECTION,STANDARD_SELECTION):
        raise ValueError('Unsupported saved selection policy')
    cfg={'prepared_path':str(prepared),'epochs':epochs,'batch_size':batch_size,'device':device_name,
         'patience':patience,'skip_baseline':skip_baseline,'checkpoint_seconds':checkpoint_seconds,'seed':seed,
         'torch_version':str(torch.__version__),'local_loss_fraction':local_loss_fraction,'selection_policy':selection_policy}
    if saved and saved['config']['torch_version']!=str(torch.__version__): raise ValueError('Resume requires the same PyTorch version')
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    if device.type=='cuda': torch.cuda.manual_seed_all(seed)
    torch.set_num_threads(4)
    arrays=prepared_data.arrays
    x=arrays['x']; y=arrays['y']; split=arrays['split']; tier=arrays['tier']; day=arrays['day']
    if not 0<=local_loss_fraction<.5: raise ValueError('local-loss-fraction must be >=0 and <0.5')
    local_codes=[i for i,name in enumerate(report['day_names']) if name.startswith('LAB:')]
    is_local=np.isin(day,local_codes)
    masks=[split==j for j in range(3)]
    if any(not mask.any() for mask in masks): raise ValueError('Empty split')
    if local_loss_fraction:
        for j,mask in enumerate(masks):
            subset=mask & is_local
            if subset.sum()<100: raise ValueError('Quality training needs at least 100 local flow records in each split from separate sessions')
            if j==0 and len(np.unique(x[subset],axis=0))<50:
                raise ValueError('Need at least 50 distinct local feature vectors; do not duplicate rows')
        if not np.any(masks[0] & ~is_local): raise ValueError('Base training replay is required')
    counts=np.bincount(y[masks[0]],minlength=len(CLASSES)); active_np=counts>0
    if counts[0]==0 or np.sum(active_np)<2: raise ValueError('Training requires BENIGN and an attack class')
    if not np.any(y[masks[1]]==0): raise ValueError('Validation needs BENIGN')
    if local_loss_fraction and selection_policy==QUALITY_SELECTION:
        base_val=masks[1] & ~is_local
        missing=[CLASSES[i] for i,active in enumerate(active_np) if active and not np.any(y[base_val]==i)]
        if missing: raise ValueError('Quality validation is missing active base classes: '+', '.join(missing))
    metadata=saved['metadata'] if saved else {'version':'soc-flow-model/0.1','software_version':'0.4.0-research','complete':False,
        'production_ready':False,'experimental_labels':True,'feature_hash':FEATURE_HASH,'classes':CLASSES,
        'active_classes':active_np.tolist(),'prepared_report_sha256':report_hash,'prepared_data_sha256':data_hash,
        'split_policy':report['split_policy'],'device':str(device),'gpu':torch.cuda.get_device_name(0) if device.type=='cuda' else None,
        'environment':{'python':sys.version,'torch':str(torch.__version__),'numpy':np.__version__,
                       'cuda_runtime':torch.version.cuda,'platform':platform.platform()},
        'hyperparameters':cfg,'missing_training_classes':[c for c,ok in zip(CLASSES,active_np) if not ok]}
    metadata['complete']=False; metadata['paused']=False
    metadata['prepared_contract']=prepared_data.validation
    metadata['training_provenance']=prepared_data.provenance
    metadata['synthetic_fixture']=prepared_data.provenance['synthetic_fixture']
    metadata['selection_policy']=selection_policy
    write_json(output/'model.json',metadata)
    expected_preprocessor=fit_preprocessor(x[masks[0]])
    preprocessor=read_json(output/'preprocessor.json') if saved else expected_preprocessor
    if saved and preprocessor!=expected_preprocessor: raise ValueError('Resume preprocessor mismatch; training-only preprocessing changed')
    write_json(output/'preprocessor.json',preprocessor); write_json(output/'features.json',SPEC)
    scaled=transform(x,preprocessor); del x
    arrays.pop('x')  # Release the unscaled cache rather than retaining a second full feature matrix.
    xs=[scaled[mask] for mask in masks]; ys=[y[mask] for mask in masks]
    active=torch.tensor(active_np,dtype=torch.bool,device=device)
    weights=np.sqrt(counts[active_np].sum()/np.maximum(counts,1)).astype(np.float32)
    weights/=weights[active_np].mean(); weights=np.minimum(weights,10); weights[~active_np]=0
    domain_weights=np.ones(len(ys[0]),dtype=np.float32)
    if local_loss_fraction:
        local_train=is_local[masks[0]]
        base_mass=float(weights[ys[0][~local_train]].sum())
        local_mass=float(weights[ys[0][local_train]].sum())
        if min(base_mass,local_mass)<=0: raise ValueError('Missing weighted domain mass')
        factor=local_loss_fraction/(1-local_loss_fraction)*base_mass/local_mass
        domain_weights[local_train]=factor
        metadata['training_policy']={'local_loss_fraction':local_loss_fraction,
            'local_sample_weight':factor,'selection':selection_policy,
            'threshold':'maximum validation BENIGN 99th percentile across base and whole local sessions',
            'quality_is_unproven_until_independent_lab_attack_tests':True}
    weight_tensor=torch.from_numpy(weights).to(device)
    model=FlowMLP().to(device); optimizer=torch.optim.AdamW(model.parameters(),lr=.001,weight_decay=1e-4)
    loss_fn=nn.CrossEntropyLoss(weight=weight_tensor,reduction='none')
    state=saved['progress'] if saved else {'epoch':1,'offset':0,'loss_sum':0.0,'weight_sum':0.0,'global_step':0,
         'best':-1.0,'stale':0,'history':[],'training_done':False,'best_state':None,'active_seconds':0.0}
    if saved:
        model.load_state_dict(saved['model']); optimizer.load_state_dict(saved['optimizer'])
        checkpoint.restore_rng(saved['rng'],device)
    write_json(output/'history.json',state['history'])
    # Checkpoint history is authoritative; reconcile after a sudden stop between writes.
    (output/'history.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in state['history']),encoding='utf-8')
    charts_dir=output/'charts'; latest=output/'checkpoints/latest.pt'
    stop_signal=[False]; previous_handler=signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT,lambda *_:stop_signal.__setitem__(0,True))
    started=time.monotonic(); last_checkpoint=time.monotonic(); initial_active=state['active_seconds']
    last_status=0; last_print=0; session_steps=0
    def save_checkpoint():
        nonlocal last_checkpoint
        state['active_seconds']=initial_active+time.monotonic()-started
        payload={'config':cfg,'prepared_data_sha256':data_hash,'prepared_report_sha256':report_hash,
                 'feature_hash':FEATURE_HASH,'metadata':metadata,'progress':state,
                 'model':model.state_dict(),'optimizer':optimizer.state_dict()}
        checkpoint.save(latest,payload); last_checkpoint=time.monotonic()
        workflow.state.update(checkpoint_file=str(latest),checkpoint_at=now())
    def poll():
        if stop_signal[0] or (output/'stop.request').exists(): raise PauseTraining()
    try:
        save_checkpoint()
        print('RESUMING' if saved else 'TRAIN_DEVICE:',device,'epoch=',state['epoch'],'offset=',state['offset'],flush=True)
        # Restore missing plot files for epochs already committed to the checkpoint.
        for i,row in enumerate(state['history'],1):
            if not (charts_dir/f'{2*i:03d}_epoch_{row["epoch"]:04d}_validation.png').exists():
                charts.epoch(charts_dir,state['history'][:i],row['validation_metrics'])
        while not state['training_done'] and state['epoch']<=epochs:
            epoch=state['epoch']; model.train(); ntrain=len(xs[0]); batches=math.ceil(ntrain/batch_size)
            generator=torch.Generator().manual_seed(seed+epoch)
            order=torch.randperm(ntrain,generator=generator).numpy()
            while state['offset']<ntrain:
                poll(); start=state['offset']; indices=order[start:start+batch_size]
                bx=torch.from_numpy(xs[0][indices]).to(device); by=torch.from_numpy(ys[0][indices]).to(device)
                optimizer.zero_grad(set_to_none=True); logits=model(bx); logits[:,~active]=-1e9
                per_row=loss_fn(logits,by)
                domain=torch.from_numpy(domain_weights[indices]).to(device)
                denominator_tensor=(weight_tensor[by]*domain).sum()
                loss=(per_row*domain).sum()/denominator_tensor
                if not torch.isfinite(loss): raise ValueError('Nonfinite loss')
                loss.backward(); nn.utils.clip_grad_norm_(model.parameters(),5); optimizer.step()
                # Only a fully committed optimizer step advances the resume position.
                denominator=float(denominator_tensor.item())
                state['loss_sum']+=loss.item()*denominator; state['weight_sum']+=denominator
                state['offset']+=len(indices); state['global_step']+=1; session_steps+=1
                if time.monotonic()-last_checkpoint>=checkpoint_seconds: save_checkpoint()
                if time.monotonic()-last_status>=2 or state['offset']==ntrain:
                    workflow.update('train',f'Training epoch {epoch}/{epochs}',epoch=epoch,total_epochs=epochs,
                       batch=math.ceil(state['offset']/batch_size),total_batches=batches,
                       epoch_percent=100*state['offset']/ntrain,global_step=state['global_step'],
                       train_loss=state['loss_sum']/max(state['weight_sum'],1e-12),gpu=metadata['gpu'])
                    last_status=time.monotonic()
                if time.monotonic()-last_print>=10:
                    print(f'TRAIN epoch={epoch}/{epochs} batch={math.ceil(state["offset"]/batch_size)}/{batches}',flush=True)
                    last_print=time.monotonic()
                if pause_after_batches is not None and session_steps>=pause_after_batches: raise PauseTraining()
            poll(); workflow.update('validation',f'Validating epoch {epoch}',epoch=epoch,total_epochs=epochs)
            val_probs=predict_batches(model,xs[1],device,active,poll=poll)
            val_threshold=choose_threshold(ys[1],val_probs,day[masks[1]] if local_loss_fraction else None) if local_loss_fraction else .5
            val=evaluate(ys[1],val_probs,val_threshold); score=float(val['multiclass']['macro avg']['f1-score'])
            selection_score=score
            if local_loss_fraction:
                local_val=is_local[masks[1]]
                selection_score,selection_detail=quality_selection(ys[1],val_probs,local_val,val_threshold,active_np,policy=selection_policy)
            else:
                selection_detail={'policy':STANDARD_SELECTION,'components':{'six_class_macro_f1':score},
                    'test_used_for_selection':False,'threshold':.5,'threshold_source':'fixed diagnostic threshold'}

            row={'epoch':epoch,'train_loss':state['loss_sum']/max(state['weight_sum'],1e-12),
                 'validation_loss':weighted_validation_loss(ys[1],val_probs,weights),'validation_macro_f1':score,
                 'validation_metrics':val,'global_step':state['global_step']}
            state['history'].append(row)
            row['quality_selection_score']=selection_score
            row['validation_selection']=selection_detail
            improved=selection_score>state['best']+1e-5
            if local_loss_fraction and selection_policy==QUALITY_SELECTION and selection_score==state['best']:
                improved=selection_detail['exact_tie_breaker']['value']>state.get('best_quality_tiebreaker',-1.0)+1e-5
            if improved:
                state['best']=selection_score; state['stale']=0; state['best_state']=checkpoint.cpu_copy(model.state_dict())
                if local_loss_fraction and selection_policy==QUALITY_SELECTION:
                    state['best_quality_tiebreaker']=selection_detail['exact_tie_breaker']['value']
                metadata['best_epoch']=epoch; metadata['best_validation_macro_f1']=score
                metadata['best_selection_score']=selection_score
                metadata['best_validation_selection']=selection_detail
            else: state['stale']+=1
            state.update(epoch=epoch+1,offset=0,loss_sum=0.0,weight_sum=0.0)
            state['training_done']=state['stale']>=patience or epoch>=epochs
            save_checkpoint()
            write_json(output/'history.json',state['history'])
            (output/'history.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in state['history']),encoding='utf-8')
            write_json(output/'model.json',metadata)
            charts.epoch(charts_dir,state['history'],val)
            workflow.update('validation',f'Epoch {epoch} complete; charts saved',epoch=epoch,
                            validation_loss=row['validation_loss'],validation_macro_f1=score)
            print(f'EPOCH {epoch:02d} train_loss={row["train_loss"]:.5f} val_loss={row["validation_loss"]:.5f} val_macro_f1={score:.5f}',flush=True)
        state['training_done']=True; save_checkpoint(); poll()
        model.load_state_dict(state['best_state']); model.eval()
        workflow.update('evaluation','Evaluating best model on validation and held-out test data')
        vp=predict_batches(model,xs[1],device,active,poll=poll); threshold=choose_threshold(ys[1],vp,day[masks[1]] if local_loss_fraction else None)
        tp=predict_batches(model,xs[2],device,active,poll=poll)
        evaluation={'version':'soc-flow-evaluation/0.1','provisional_ground_truth':True,
          'threshold_policy':('maximum validation BENIGN 99th percentile across global and day/session groups' if local_loss_fraction else 'validation BENIGN 99th percentile; exploratory observed 1% FPR target'),
          'validation':evaluate(ys[1],vp,threshold),'test':evaluate(ys[2],tp,threshold),'test_subsets':{},'validation_subsets':{},'warnings':report['warnings'],
          'selection_policy':selection_policy,'best_validation_selection':metadata.get('best_validation_selection'),
          'training_provenance':prepared_data.provenance,'synthetic_fixture':prepared_data.provenance['synthetic_fixture']}
        for variable,values,names in [('tier',tier,report.get('tier_names',['strict','near_duration','controlled_lab'])),('day',day,report['day_names'])]:
            test_values=values[masks[2]]
            for code,name in enumerate(names):
                select=test_values==code
                if select.any(): evaluation['test_subsets'][variable+':'+name]=evaluate(ys[2][select],tp[select],threshold)
        for code,name in enumerate(report['day_names']):
            select=day[masks[1]]==code
            if select.any(): evaluation['validation_subsets']['day:'+name]=evaluate(ys[1][select],vp[select],threshold)
        if local_loss_fraction:
            local_reports={name:value for name,value in evaluation['test_subsets'].items() if name.startswith('day:LAB:')}
            evaluation['local_quality_check']={'local_benign_test_false_positive_rates':{
                name:value['binary_attack']['benign_false_positive_rate'] for name,value in local_reports.items()},
                'local_attack_recall_established':bool(np.any(is_local[masks[2]] & (ys[2]!=0))),
                'production_ready':False,
                'note':'Diagnostic only. No automatic promotion; small normal-only local tests cannot establish attack detection quality.'}
        if not skip_baseline:
            workflow.update('baseline','Training linear comparison model (CPU); MLP checkpoint is complete')
            baseline=SGDClassifier(loss='log_loss',random_state=seed,alpha=.0001)
            bw=counts[active_np].sum()/(np.maximum(counts,1)*int(active_np.sum()))
            for lap in range(15):
                order=np.random.default_rng(seed+lap).permutation(len(xs[0]))
                for start in range(0,len(order),8192):
                    poll(); ids=order[start:start+8192]
                    baseline.partial_fit(xs[0][ids],ys[0][ids],classes=np.flatnonzero(active_np),sample_weight=bw[ys[0][ids]])
                workflow.update('baseline',f'Linear baseline pass {lap+1}/15',baseline_pass=lap+1)
            def baseline_probs(values):
                result=np.zeros((len(values),len(CLASSES)))
                margins=baseline.decision_function(values)
                if margins.ndim==1: margins=np.column_stack((-margins,margins))
                margins=margins-margins.max(axis=1,keepdims=True)
                probability=np.exp(margins); probability/=probability.sum(axis=1,keepdims=True)
                result[:,baseline.classes_]=probability; return result
            bp=baseline_probs(xs[1]); bt=choose_threshold(ys[1],bp)
            evaluation['linear_baseline_test']=evaluate(ys[2],baseline_probs(xs[2]),bt)
        poll(); workflow.update('export','Exporting model, charts and portable verification vectors')
        save_weights(model,output/'model-weights.npz'); write_json(output/'metrics.json',evaluation)
        charts.final(charts_dir,state['history'],evaluation)
        write_json(output/'golden.json',read_json(prepared/'golden.json'))
        from .flow import features
        golden=read_json(output/'golden.json'); gx=transform(np.stack([features(e['flow']) for e in golden]),preprocessor)
        gp=predict_batches(model,gx,device,active); write_json(output/'golden-predictions.json',gp.tolist())
        locked=subprocess.check_output([sys.executable,'-m','pip','freeze'],text=True)
        (output/'requirements-lock.txt').write_text(locked,encoding='utf-8')
        metadata.update(complete=True,paused=False,attack_score_threshold=threshold,softmax_scores_calibrated=False,
            training_seconds=initial_active+time.monotonic()-started,weights_sha256=sha256(output/'model-weights.npz'),
            preprocessor_sha256=sha256(output/'preprocessor.json'))
        write_json(output/'model.json',metadata)
        from .predict import Predictor
        difference=Predictor(output,'cpu').verify()
        workflow.update('export','Export verification passed',verify_probability_difference=difference)
        workflow.finish('completed','Training complete. Independent lab evaluation is required before selecting this model for live use.')
        print('TRAIN_COMPLETE:',output,flush=True); print('TEST binary attack:',json.dumps(evaluation['test']['binary_attack']),flush=True)
        return 'completed'
    except PauseTraining:
        # If evaluation already selected best weights, keep training complete; resume reevaluates.
        metadata['paused']=True; save_checkpoint(); write_json(output/'model.json',metadata)
        workflow.finish('paused','Checkpoint saved. You may close the program and shut down the PC.')
        print('TRAINING_PAUSED checkpoint=',latest,flush=True)
        return 'paused'
    finally:
        signal.signal(signal.SIGINT,previous_handler)

def main():
    p=argparse.ArgumentParser(description='Train/resume completed-flow MLP with checkpoint and reports')
    p.add_argument('--prepared',type=Path); p.add_argument('--output',type=Path); p.add_argument('--resume',type=Path)
    p.add_argument('--epochs',type=int,default=20); p.add_argument('--batch-size',type=int,default=2048)
    p.add_argument('--device',choices=('cuda','cpu'),default='cuda'); p.add_argument('--patience',type=int,default=5)
    p.add_argument('--local-loss-fraction',type=float,default=0.0)
    p.add_argument('--checkpoint-seconds',type=int,default=30); p.add_argument('--skip-baseline',action='store_true')
    a=p.parse_args()
    if a.resume:
        run(None,a.resume,resume=True)
    else:
        if a.prepared is None or a.output is None: p.error('--prepared and --output required for new training')
        run(a.prepared,a.output,a.epochs,a.batch_size,a.device,a.patience,a.skip_baseline,
            checkpoint_seconds=a.checkpoint_seconds,local_loss_fraction=a.local_loss_fraction)

if __name__=='__main__': main()
