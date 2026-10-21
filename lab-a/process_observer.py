"""Opt-in root /proc observer: shell socket FDs and SSH-bound UID evidence.

IPv4 TCP only. Polling can miss short-lived processes. No command lines,
passwords or full environments are logged. This is not tamper-resistant audit.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import time

SCHEMA='soc-process-observer/0.2'
PROGRAM='/usr/local/lib/soc-lab/process_observer.py'
DIRECTORY='/var/log/soc-lab/process-observer'
LOG=DIRECTORY+'/events.jsonl'
HEALTH=DIRECTORY+'/health.json'
LOCK='/run/soc-lab-process-observer.lock'
SHELLS={'/bin/bash','/usr/bin/bash','/bin/dash','/usr/bin/dash','/bin/sh','/usr/bin/sh'}
SSHDS={'sshd','sshd-session','sshd-auth'}


def now():return datetime.now(timezone.utc).isoformat(timespec='microseconds')
def identity(boot,pid,ticks):return hashlib.sha256(f'{boot}:{pid}:{ticks}'.encode()).hexdigest()
def private(value):
    ip=ipaddress.IPv4Address(value)
    if not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('Only RFC1918 lab connections are observed')
    return str(ip)

@contextmanager
def filesystem_identity(uid,gid):
    """Read same-UID /proc FDs without requiring Docker CAP_SYS_PTRACE.

    Only effective/filesystem credentials change; real/saved UID remain root.
    The single-threaded observer restores credentials before logging or writing.
    It cannot be ptraced by the target UID (its real/saved UID are still zero).
    """
    previous_uid,previous_gid=os.geteuid(),os.getegid()
    try:
        if previous_uid==0 and uid!=0:
            os.setegid(gid);os.seteuid(uid)
        yield
    finally:
        if os.geteuid()!=previous_uid:os.seteuid(previous_uid)
        if os.getegid()!=previous_gid:os.setegid(previous_gid)

def process(pid,boot,proc=Path('/proc')):
    root=proc/str(pid)
    raw=(root/'stat').read_text();fields=raw.rsplit(') ',1)[1].split()
    ppid=int(fields[1]);ticks=int(fields[19])
    status=(root/'status').read_text().splitlines()
    uidline=next(x for x in status if x.startswith('Uid:'))
    uids=[int(x) for x in uidline.split()[1:]]
    gids=[int(x) for x in next(x for x in status if x.startswith('Gid:')).split()[1:]]
    try:
        with filesystem_identity(uids[1],gids[1]):
            exe=os.readlink(root/'exe').removesuffix(' (deleted)')
    except PermissionError:
        # E.g. the setuid sudo process is non-dumpable. Keep ancestry identity,
        # but never classify an unreadable executable as a shell. Protected
        # root SSH intermediates are considered only below a verified sshd.
        exe=''
    # Recheck PID start after reading metadata; never combine recycled processes.
    if (root/'stat').read_text().rsplit(') ',1)[1].split()[19]!=str(ticks):
        raise ProcessLookupError('Process changed while sampling')
    return dict(pid=pid,ppid=ppid,start_ticks=ticks,process_id=identity(boot,pid,ticks),
                real_uid=uids[0],effective_uid=uids[1],effective_gid=gids[1],executable=exe,
                kernel_comm=(root/'comm').read_text().strip())

def ancestry(row,boot,proc=Path('/proc')):
    chain=[row];seen={row['pid']}
    for _ in range(31):
        pid=chain[-1]['ppid']
        if pid<=1 or pid in seen:break
        parent=process(pid,boot,proc);chain.append(parent);seen.add(pid)
    return chain

def ssh_context(chain,proc=Path('/proc')):
    import pwd
    ssh=[p for p in chain if Path(p['executable']).name in SSHDS]
    if not ssh:return None
    for p in chain:
        if p['effective_uid']==0:continue
        # Whitelist one environment key. Never log arbitrary env/argv.
        try:
            with filesystem_identity(p['effective_uid'],p['effective_gid']):
                values=[v.split(b'=',1)[1] for v in (proc/str(p['pid'])/'environ').read_bytes().split(b'\0')
                        if v.startswith(b'SSH_CONNECTION=')]
        except PermissionError:continue
        if len(values)!=1:continue
        fields=values[0].decode('ascii').split()
        if len(fields)!=4 or fields[3]!='22':continue
        if not fields[1].isdecimal() or not 1<=int(fields[1])<=65535:continue
        try:src,dst=private(fields[0]),private(fields[2])
        except ValueError:continue
        # Only sshd ancestors ABOVE this user's process establish ancestry.
        parents=chain[chain.index(p)+1:]
        verified=[i for i,x in enumerate(parents) if Path(x['executable']).name in SSHDS and x['effective_uid']==0]
        if not verified:continue
        # Privilege-separated root monitors may be non-dumpable without
        # CAP_SYS_PTRACE. Their root UID + kernel comm + position BELOW a
        # verified sshd permits PID correlation, never shell classification.
        outer=max(verified)
        server=[x for i,x in enumerate(parents) if i<=outer and (i in verified or
            x['effective_uid']==0 and not x['executable'] and x.get('kernel_comm') in SSHDS)]
        return dict(source_ip=src,target_ip=dst,source_port=int(fields[1]),target_port=22,
                    username=pwd.getpwuid(p['real_uid']).pw_name,session_uid=p['real_uid'],
                    sshd_pids=[x['pid'] for x in server],sshd_process_ids=[x['process_id'] for x in server])
    return None

def tcp_sockets(proc=Path('/proc')):
    result={}
    for line in (proc/'net/tcp').read_text().splitlines()[1:]:
        f=line.split()
        if len(f)<10 or f[3]!='01':continue
        def addr(value):
            host,port=value.split(':');return socket.inet_ntoa(bytes.fromhex(host)[::-1]),int(port,16)
        local,lp=addr(f[1]);remote,rp=addr(f[2])
        result[f[9]]=dict(local_ip=local,local_port=lp,peer_ip=remote,peer_port=rp)
    return result

def socket_fds(pid,proc=Path('/proc')):
    links={}
    for fd in (0,1,2):
        try:
            match=re.fullmatch(r'socket:\[(\d+)\]',os.readlink(proc/str(pid)/'fd'/str(fd)))
            if match:links[fd]=match.group(1)
        except FileNotFoundError:pass
    return links

def environment_context(row,proc=Path('/proc')):
    """An environment hint is explicitly weaker than observed SSH ancestry."""
    import pwd
    with filesystem_identity(row['effective_uid'],row['effective_gid']):
        values=[v.split(b'=',1)[1] for v in (proc/str(row['pid'])/'environ').read_bytes().split(b'\0') if v.startswith(b'SSH_CONNECTION=')]
    if len(values)!=1:return None
    f=values[0].decode('ascii').split()
    if len(f)!=4 or f[3]!='22' or not f[1].isdecimal() or not 1<=int(f[1])<=65535:return None
    return dict(source_ip=private(f[0]),target_ip=private(f[2]),source_port=int(f[1]),target_port=22,
                username=pwd.getpwuid(row['real_uid']).pw_name,session_uid=row['real_uid'],
                sshd_pids=[],sshd_process_ids=[],ssh_context_method='environment_hint')


def event_base(row,chain,connection,boot,when):
    import pwd
    try:user=pwd.getpwuid(row['real_uid']).pw_name
    except KeyError:user='uid_'+str(row['real_uid'])
    context=connection or dict(source_ip=None,target_ip=None,source_port=0,target_port=0,
        username=user,session_uid=row['real_uid'],sshd_pids=[],sshd_process_ids=[],ssh_context_method='unavailable')
    return {**row,**context,'schema_version':SCHEMA,'observer_uid':0,'boot_id':boot,
        'event_time':when,'ancestry_process_ids':[p['process_id'] for p in chain[1:]],
        'ancestry_pids':[p['pid'] for p in chain[1:]],'kernel_process_observation':True,
        'sampling_is_complete_audit':False}


def observe(row,chain,connection,sockets,fds,boot,when):
    if row['executable'] not in SHELLS:return []
    if not fds.get(0) or fds.get(0)!=fds.get(1) or fds[0] not in sockets:return []
    net=sockets[fds[0]]
    try:private(net['local_ip']);private(net['peer_ip'])
    except ValueError:return []
    # The kernel tuple defines the peer even when SSH environment is absent or
    # altered. Association to SSH is separately verified by the correlator.
    if connection and (net['peer_ip']!=connection['source_ip'] or net['local_ip']!=connection['target_ip']):connection=None
    common=event_base(row,chain,connection,boot,when)
    common.update(source_ip=net['peer_ip'],target_ip=net['local_ip'])
    return [{**common,**net,'kind':'process.shell_socket','socket_inode':fds[0],
             'stdin_stdout_same_socket':True,'scope':'kernel_shell_fd_established_socket'}]


def append_record(path,row):
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o640)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('Observer log must be root-owned and not group/world-writable')
        data=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
        if os.write(fd,data)!=len(data):raise OSError('Incomplete observer log append')
        os.fsync(fd)
    finally:os.close(fd)

def health_write(value):
    path=Path(HEALTH);temp=path.with_suffix('.new')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'w') as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)

def check_health(require_artifacts=False):
    h=json.loads(Path(HEALTH).read_text())
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(h['event_time'])).total_seconds()
    if h.get('schema_version')!=SCHEMA or h.get('observer_uid')!=0 or h.get('running') is not True or not -2<=age<=10:
        raise ValueError('Observer heartbeat is stale/stopped; rerun setup_process_observer.py')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    p=process(h['observer_pid'],boot)
    if p['effective_uid']!=0 or p['process_id']!=h.get('observer_process_id'):
        raise ValueError('Observer PID/UID/start identity differs')
    paths=[PROGRAM,LOG,HEALTH,DIRECTORY,str(Path(PROGRAM).parent),str(Path(DIRECTORY).parent)]
    if h.get('artifact_watch_enabled'):paths.append(str(Path(PROGRAM).with_name('artifact_observer.py')))
    for path in paths:
        s=os.lstat(path)
        if s.st_uid!=0 or s.st_mode&0o022 or stat.S_ISLNK(s.st_mode):
            raise ValueError('Observer source/code must be root-owned and not writable by the lab account')
    if require_artifacts and (h.get('artifact_watch_enabled') is not True or '/tmp' not in h.get('artifact_watch_paths',[]) or h.get('artifact_queue_overflows',0)):
        raise ValueError('Artifact observation disabled or queue overflow; inspect health and reinstall observer')
    return dict(observer_running=True,heartbeat_age_seconds=round(age,3),observer_uid=0,
                root_owned_source_verified=True,packet_or_exec_completeness_established=False,
                **{k:v for k,v in h.items() if k.startswith('artifact_')})

def run(interval=.1,watch_artifacts=False):
    import fcntl
    if os.getuid()!=0:raise ValueError('Root observer required for process ancestry/FD inspection')
    folder=Path(DIRECTORY)
    if any(x.is_symlink() for x in (folder,*folder.parents)) or folder.stat().st_uid!=0 or folder.stat().st_mode&0o022:
        raise ValueError('Unsafe observer directory')
    lock=os.open(LOCK,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o640)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    self_row=process(os.getpid(),boot);seen={};context_cache={};stopping=False;last_health=0;count=0;denied=0
    watcher=None
    if watch_artifacts:
        from artifact_observer import ArtifactWatch
        watcher=ArtifactWatch()
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        while not stopping:
            sockets=tcp_sockets();when=now();alive=set()
            for p in Path('/proc').iterdir():
                if not p.name.isdecimal():continue
                try:
                    row=process(int(p.name),boot)
                    if not row['executable']:denied+=1
                    chain=ancestry(row,boot)
                    conn=ssh_context(chain)
                    if conn is not None:conn={**conn,'ssh_context_method':'live_ssh_ancestry'}
                    else:
                        for parent in chain:
                            cached=context_cache.get(parent['process_id'])
                            if cached:
                                conn={**cached,'ssh_context_method':'cached_observed_ancestry'};break
                    if conn is None:
                        try:conn=environment_context(row)
                        except (OSError,ValueError,KeyError):pass
                    if conn and conn.get('sshd_pids'):context_cache[row['process_id']]=conn
                    alive.add(row['process_id'])
                    if row['executable'] not in SHELLS:continue
                    with filesystem_identity(row['effective_uid'],row['effective_gid']):
                        fds=socket_fds(row['pid'])
                    current=process(row['pid'],boot)
                    if any(current[k]!=row[k] for k in ('process_id','effective_uid','executable')):continue
                    records=observe(row,chain,conn,sockets,fds,boot,when)
                    if watcher:
                        from artifact_observer import script_metadata
                        try:
                            with filesystem_identity(row['effective_uid'],row['effective_gid']):m=script_metadata(row['pid'])
                            if m:records.append({**event_base(row,chain,conn,boot,when),**m,'kind':'process.script_execution','artifact_action':'script_execution'})
                        except (OSError,ValueError):pass
                    for event in records:
                        key=(event['kind'],event['process_id'],event.get('socket_inode'),event.get('artifact_sha256'))
                        strength=2 if event.get('sshd_pids') else 1 if event.get('source_port') else 0
                        if seen.get(key,-1)>=strength:continue
                        append_record(LOG,event);seen[key]=strength;count+=1
                except (FileNotFoundError,ProcessLookupError):pass
                except PermissionError:denied+=1
                except (StopIteration,IndexError,KeyError,ValueError):pass
            seen={key:v for key,v in seen.items() if key[1] in alive}
            context_cache={key:v for key,v in context_cache.items() if key in alive}
            if watcher:
                for event in watcher.poll(when):
                    append_record(LOG,{**event,'schema_version':SCHEMA,'observer_uid':0,'kernel_file_observation':True});count+=1
            if time.monotonic()-last_health>=2:
                health_write(dict(schema_version=SCHEMA,observer_pid=os.getpid(),observer_uid=0,
                    observer_process_id=self_row['process_id'],boot_id=boot,event_time=now(),running=True,
                    records_written=count,permission_denials=denied,poll_interval_seconds=interval,
                    coverage='polling_can_miss_short_lived_processes',**(watcher.health() if watcher else {'artifact_watch_enabled':False})))
                last_health=time.monotonic()
            time.sleep(interval)
    finally:
        health_write(dict(schema_version=SCHEMA,observer_pid=os.getpid(),observer_uid=0,
            observer_process_id=self_row['process_id'],boot_id=boot,event_time=now(),running=False))
        if watcher:watcher.close()
        os.close(lock)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--watch-artifacts',action='store_true');a=p.parse_args();run(watch_artifacts=a.watch_artifacts)
