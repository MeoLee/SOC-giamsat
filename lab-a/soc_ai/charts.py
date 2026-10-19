"""Numbered publication/export charts using a noninteractive backend."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from .common import CLASSES,write_json
from .fileio import replace_with_retry

plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,
                     'figure.facecolor':'white','axes.facecolor':'#f7f9fc','savefig.facecolor':'white'})

def save(fig,directory,index,name):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    stem=f'{index:03d}_{name}'
    for extension in ('png','svg'):
        target=directory/(stem+'.'+extension); temporary=directory/(stem+'.'+extension+'.tmp')
        fig.savefig(temporary,format=extension,dpi=160,bbox_inches='tight')
        replace_with_retry(temporary,target)
    plt.close(fig)
    items=[{'file':p.name,'number':int(p.name.split('_')[0])} for p in sorted(directory.glob('*.png'))]
    write_json(directory/'index.json',items)

def preparation(directory,counts):
    names=list(counts); fig,ax=plt.subplots(figsize=(8,4))
    ax.bar(names,[counts[n]['rows'] for n in names],color=['#3269d6','#12a887','#f3a32b'])
    ax.set(ylabel='Selected flows',title='Prepared dataset: group split counts'); ax.grid(axis='y',alpha=.2)
    save(fig,directory,1,'preparation_splits')
    fig,ax=plt.subplots(figsize=(10,4)); positions=np.arange(len(CLASSES)); width=.25
    for i,name in enumerate(names):
        ax.bar(positions+(i-1)*width,[counts[name]['classes'][label] for label in CLASSES],width,label=name)
    ax.set_xticks(positions,CLASSES,rotation=15); ax.set_yscale('symlog',linthresh=1)
    ax.set(ylabel='Flow count (symlog)',title='Prepared dataset: class counts'); ax.legend()
    save(fig,directory,2,'preparation_classes')

def epoch(directory,history,validation):
    n=len(history); epochs=[x['epoch'] for x in history]
    fig,ax=plt.subplots(figsize=(8,4))
    ax.plot(epochs,[x['train_loss'] for x in history],'o-',label='Train loss',color='#3269d6')
    ax.plot(epochs,[x['validation_loss'] for x in history],'o-',label='Validation loss',color='#e28125')
    ax.set(xlabel='Epoch',ylabel='Weighted cross entropy',title=f'Loss through epoch {history[-1]["epoch"]}')
    ax.set_xticks(epochs); ax.grid(alpha=.2); ax.legend()
    save(fig,directory,2*n-1,f'epoch_{history[-1]["epoch"]:04d}_loss')
    fig,(a,b)=plt.subplots(1,2,figsize=(12,4))
    a.plot(epochs,[x['validation_macro_f1'] for x in history],'o-',color='#12a887')
    a.set(xlabel='Epoch',ylabel='Validation macro F1',ylim=(0,1),title='Validation trajectory'); a.grid(alpha=.2)
    scores=[validation['multiclass'][label]['f1-score'] for label in CLASSES]
    b.barh(CLASSES,scores,color='#3269d6'); b.set(xlim=(0,1),xlabel='F1',title='Validation F1 by class')
    fig.tight_layout(); save(fig,directory,2*n,f'epoch_{history[-1]["epoch"]:04d}_validation')

def final(directory,history,evaluation):
    n=2*len(history)
    fig,ax=plt.subplots(figsize=(8,5))
    confusion=np.asarray(evaluation['test']['confusion_matrix'])
    im=ax.imshow(np.log1p(confusion),cmap='Blues')
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)): ax.text(j,i,str(confusion[i,j]),ha='center',va='center',fontsize=8)
    ax.set_xticks(range(len(CLASSES)),CLASSES,rotation=35,ha='right'); ax.set_yticks(range(len(CLASSES)),CLASSES)
    ax.set(xlabel='Predicted label',ylabel='Provisional reference label',title='Test confusion matrix (log-color)')
    fig.colorbar(im,ax=ax,label='log1p(count)'); save(fig,directory,n+1,'test_confusion_matrix')
    fig,ax=plt.subplots(figsize=(10,4)); x=np.arange(len(CLASSES))
    ax.bar(x-.18,[evaluation['test']['multiclass'][c]['f1-score'] for c in CLASSES],.36,label='MLP')
    if 'linear_baseline_test' in evaluation:
        ax.bar(x+.18,[evaluation['linear_baseline_test']['multiclass'][c]['f1-score'] for c in CLASSES],.36,label='Linear baseline')
    ax.set_xticks(x,CLASSES,rotation=15); ax.set(ylim=(0,1),ylabel='F1',title='Internal test F1 by class'); ax.legend()
    save(fig,directory,n+2,'test_class_f1')
    metrics=evaluation['test']['binary_attack']; names=['precision','recall','benign_false_positive_rate','pr_auc']
    fig,ax=plt.subplots(figsize=(9,4)); ax.bar(names,[metrics[k] or 0 for k in names],color='#12a887')
    ax.set(ylim=(0,1),title='Internal test attack alert metrics',ylabel='Score / rate'); ax.tick_params(axis='x',rotation=15)
    save(fig,directory,n+3,'test_attack_metrics')
