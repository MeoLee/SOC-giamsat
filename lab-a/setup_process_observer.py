"""Install defensive, root-owned /proc observation; no attack or privilege helpers."""
import argparse
import base64
from datetime import datetime,timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile
from live_config import container_name,load_config
from process_observer import LOG

INSTALL=r'''
import base64,hashlib,json,os,pwd,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
p=json.load(sys.stdin)
if os.getuid()!=0 or pwd.getpwnam(p['username']).pw_uid==0:raise ValueError('Root installer and existing non-root account required')
root=Path('/usr/local/lib/soc-lab');folder=Path('/var/log/soc-lab/process-observer')
for d in (root,folder):
    if any(x.is_symlink() for x in (d,*d.parents)):raise ValueError('Symlink directory refused')
    if d.exists() and (d.stat().st_uid!=0 or d.stat().st_mode&0o022):raise ValueError('Unsafe root-owned installation directory')
    d.mkdir(parents=True,exist_ok=True)
    if d.parent.stat().st_uid!=0 or d.parent.stat().st_mode&0o022:raise ValueError('Unsafe observer parent '+str(d.parent))
    os.chown(d,0,0);os.chmod(d,0o755 if d==root else 0o700)
module=root/'artifact_observer.py'
program=root/'process_observer.py';marker=root/'managed-process-observer.json';health=folder/'health.json';log=folder/'events.jsonl'
for f in (program,module,marker,health,log,folder/'service.log'):
    if f.is_symlink() or f.exists() and (not f.is_file() or f.stat().st_uid!=0 or f.stat().st_mode&0o022):
        raise ValueError('Unsafe observer file '+str(f))
code=base64.b64decode(p['code']);compile(code,'process_observer.py','exec')
modulecode=base64.b64decode(p['artifact_code']);compile(modulecode,'artifact_observer.py','exec')
previous=json.loads(marker.read_text()) if marker.exists() else {}
old=program.read_bytes() if program.exists() else None
if old is not None and old!=code and previous.get('sha256')!=hashlib.sha256(old).hexdigest():
    raise ValueError('Unmanaged/modified observer program; refusing overwrite')
oldmodule=module.read_bytes() if module.exists() else None
if oldmodule is not None and oldmodule!=modulecode and previous.get('artifact_module_sha256')!=hashlib.sha256(oldmodule).hexdigest():
    raise ValueError('Unmanaged artifact module; refusing overwrite')
oldwatch=False
# All preflight validation precedes stopping an existing managed process.
if health.exists():
    h=json.loads(health.read_text());oldwatch=bool(h.get('artifact_watch_enabled'));pid=h.get('observer_pid');proc=Path('/proc')/str(pid)
    if proc.exists():
        fields=(proc/'stat').read_text().rsplit(') ',1)[1].split();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        expected=hashlib.sha256(f'{boot}:{pid}:{fields[19]}'.encode()).hexdigest()
        if h.get('observer_process_id')==expected and str(program).encode() in (proc/'cmdline').read_bytes().split(b'\0'):
            os.kill(pid,signal.SIGTERM);deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                try:
                    if (proc/'stat').read_text().rsplit(') ',1)[1].split()[0]=='Z':break
                except FileNotFoundError:break
                time.sleep(.1)
            else:raise RuntimeError('Previous observer still running; replacement not started')
def atomic(path,data,mode):
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.soc-proc-')
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.chown(temp,0,0);os.chmod(temp,mode);os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)
backup=None
if old is not None:
    backup=root/('process_observer.py.before-'+str(time.time_ns()));atomic(backup,old,0o600)
oldmarker=marker.read_bytes() if marker.exists() else None
fd=os.open(log,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o640);os.close(fd);os.chown(log,0,0);os.chmod(log,0o640)
child=None
def start(watch=None):
    if watch is None:watch=p.get('watch_artifacts',False)
    fd=os.open(folder/'service.log',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:return subprocess.Popen(['python3',str(program)]+(['--watch-artifacts'] if watch else []),stdin=subprocess.DEVNULL,stdout=fd,stderr=fd,start_new_session=True,close_fds=True)
    finally:os.close(fd)
try:
    atomic(module,modulecode,0o644);atomic(program,code,0o644);atomic(marker,json.dumps({'sha256':hashlib.sha256(code).hexdigest(),'artifact_module_sha256':hashlib.sha256(modulecode).hexdigest(),'version':'0.4.15'}).encode(),0o644)
    child=start();deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        if child.poll() is not None:raise RuntimeError('Observer exited; inspect '+str(folder/'service.log'))
        if health.exists():
            h=json.loads(health.read_text())
            if h.get('running') and h.get('observer_pid')==child.pid:
                print(json.dumps({'observer_ready':True,'observer_pid':child.pid,'source':str(log),'backup':str(backup) if backup else None,
                    'coverage':'IPv4 /proc polling; short-lived processes and unreadable /proc entries can be missed'}),flush=True);break
        time.sleep(.2)
    else:raise RuntimeError('Observer heartbeat not confirmed')
except BaseException:
    if child is not None and child.poll() is None:
        child.terminate()
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:raise RuntimeError('Observer still terminating; no overlapping rollback started')
    if oldmodule is not None:atomic(module,oldmodule,0o644)
    else:module.unlink(missing_ok=True)
    if old is not None:
        atomic(program,old,0o644)
        if oldmarker is not None:atomic(marker,oldmarker,0o644)
        else:marker.unlink(missing_ok=True)
        start(oldwatch)
    else:program.unlink(missing_ok=True);marker.unlink(missing_ok=True)
    raise
'''


def candidate_config(data,sensor):
    result=json.loads(json.dumps(data))
    if not any(a['host']==sensor for a in result.get('assets',[])):raise ValueError('Sensor must match a configured asset host')
    source={'kind':'process','container':sensor,'path':LOG,'output':'process-observer.jsonl'}
    for s in result['sources']:
        if s.get('output')==source['output'] or (s.get('container'),s.get('path'))==(sensor,LOG):
            if s!=source:raise ValueError('Conflicting process source')
            break
    else:result['sources'].append(source)
    result.setdefault('correlation',{})['attack_chain_enabled']=True
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sensor',default='ubuntu-endpoint');parser.add_argument('--username',default='soctest',help='Existing non-root account; never creates or modifies users')
    parser.add_argument('--config',type=Path,default=Path(__file__).with_name('live-config.json'))
    parser.add_argument('--watch-artifacts',action='store_true',help='Enable bounded inotify file and script-path observations')
    a=parser.parse_args();container_name(a.sensor)
    if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',a.username):parser.error('Invalid account name')
    load_config(a.config);old=a.config.read_bytes();data=candidate_config(json.loads(old.decode('utf-8-sig')),a.sensor)
    with tempfile.TemporaryDirectory() as folder:
        check=Path(folder)/'config.json';check.write_text(json.dumps(data));load_config(check)
    payload={'username':a.username,'code':base64.b64encode(Path(__file__).with_name('process_observer.py').read_bytes()).decode(),
        'artifact_code':base64.b64encode(Path(__file__).with_name('artifact_observer.py').read_bytes()).decode(),'watch_artifacts':a.watch_artifacts}
    result=subprocess.run(['docker','exec','-i','--user','0',a.sensor,'python3','-c',INSTALL],input=json.dumps(payload).encode(),capture_output=True,timeout=60)
    print(result.stdout.decode(errors='replace'),end='')
    if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')[-4000:])
    if a.config.read_bytes()!=old:raise RuntimeError('Config changed concurrently; observer installed but config not overwritten')
    if data!=json.loads(old.decode('utf-8-sig')):
        backup=a.config.with_name(a.config.name+'.before-process-observer-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.write_bytes(old)
        from soc_ai.common import write_json
        write_json(a.config,data);print('CONFIG_BACKUP:',backup)
    print('PROCESS_OBSERVER_READY: start NEW Live; existing SSH sessions before collection cannot be fully joined. Rerun installer after sensor container restart.')

if __name__=='__main__':main()
