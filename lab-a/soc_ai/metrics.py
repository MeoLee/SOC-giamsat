import numpy as np
from sklearn.metrics import classification_report,confusion_matrix,average_precision_score,roc_auc_score
from .common import CLASSES

def attack_scores(probs):
    # Keep threshold selection, evaluation and scalar inference in float64.
    return 1.0-np.asarray(probs,dtype=np.float64)[:,0]

def choose_threshold(y,probs,groups=None,target_fpr=.01):
    if not 0<target_fpr<1: raise ValueError('target_fpr must be between 0 and 1')
    y=np.asarray(y); scores=attack_scores(probs); normal=y==0
    if not normal.any(): raise ValueError('Validation contains no BENIGN for threshold selection')
    selections=[normal]
    if groups is not None:
        groups=np.asarray(groups)
        if groups.shape!=y.shape: raise ValueError('Threshold group shape mismatch')
        selections += [normal & (groups==g) for g in np.unique(groups[normal])]
    # A fixed, validation-only operating rule; test is never used to tune it.
    value=max(float(np.quantile(scores[mask],1-target_fpr,method='higher')) for mask in selections)
    return float(np.nextafter(value,float('inf')))

def evaluate(y,probs,threshold):
    pred=probs.argmax(axis=1); truth=y!=0; score=attack_scores(probs); alarm=score>=threshold
    tp=int(np.sum(truth & alarm)); fn=int(np.sum(truth & ~alarm))
    fp=int(np.sum(~truth & alarm)); tn=int(np.sum(~truth & ~alarm))
    multiclass=classification_report(y,pred,labels=list(range(len(CLASSES))),target_names=CLASSES,
                                    output_dict=True,zero_division=0)
    per_type={name:{'support':int(np.sum(y==i)),
                   'attack_alert_recall':float(np.mean(alarm[y==i])) if np.any(y==i) else None}
              for i,name in enumerate(CLASSES[1:],1)}
    return {'multiclass':multiclass,'confusion_matrix':confusion_matrix(y,pred,labels=list(range(len(CLASSES)))).tolist(),
            'class_order':CLASSES,'binary_attack':{'threshold':threshold,'tp':tp,'fn':fn,'fp':fp,'tn':tn,
              'precision':tp/(tp+fp) if tp+fp else 0.0,'recall':tp/(tp+fn) if tp+fn else None,
              'benign_false_positive_rate':fp/(fp+tn) if fp+tn else None,
              'pr_auc':float(average_precision_score(truth,score)) if truth.any() and (~truth).any() else None,
              'roc_auc':float(roc_auc_score(truth,score)) if truth.any() and (~truth).any() else None},
            'attack_types':per_type,'softmax_scores_calibrated':False}
