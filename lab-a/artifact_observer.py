"""Defensive inotify metadata and bounded script-path observations. No payloads."""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import struct

WATCH_ROOTS=('/tmp','/var/lib/soc-lab/fim','/var/spool/cron/crontabs','/var/spool/cron')
MAX_BYTES=1024*1024
EXTENSIONS={'.sh','.py','.pl','.php','.bin'}


def allowed(path,cron=False):
    p=Path(path)
    if not p.is_absolute() or '..' in p.parts or any(ord(c)<32 for c in str(p)):return False
    if str(p.parent) not in WATCH_ROOTS:return False
    if any(x.is_symlink() for x in (p,*p.parents)):return False
    return cron or p.suffix.lower() in EXTENSIONS


def metadata(path,cron=False):
    if not allowed(path,cron):raise ValueError('Path outside bounded artifact scope')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_BYTES:raise ValueError('Artifact must be a bounded regular single-link file')
        data=bytearray()
        while len(data)<=MAX_BYTES:
            block=os.read(fd,min(65536,MAX_BYTES+1-len(data)))
            if not block:break
            data.extend(block)
        after=os.fstat(fd)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        if len(data)>MAX_BYTES or identity(before)!=identity(after) or identity(after)!=identity(os.lstat(path)):raise ValueError('Artifact changed during observation')
        try:user=pwd.getpwuid(after.st_uid).pw_name
        except KeyError:user=str(after.st_uid)
        result=dict(artifact_path=str(Path(path)),artifact_sha256=hashlib.sha256(data).hexdigest(),artifact_bytes=len(data),artifact_uid=after.st_uid,artifact_owner=user,artifact_device=after.st_dev,artifact_inode=after.st_ino,artifact_mtime_ns=after.st_mtime_ns,artifact_hash_complete=True)
        if cron:
            refs=set()
            for b in re.findall(rb'/(?:tmp|var/lib/soc-lab/fim)/[A-Za-z0-9_./-]+',data):
                p=b.decode('ascii')
                if allowed(p):refs.add(p)
            result['referenced_paths']=sorted(refs)[:16]
        return result
    finally:os.close(fd)


class ArtifactWatch:
    def __init__(self):
        lib=ctypes.CDLL(None,use_errno=True);self.lib=lib
        lib.inotify_init1.argtypes=[ctypes.c_int];lib.inotify_init1.restype=ctypes.c_int
        lib.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32];lib.inotify_add_watch.restype=ctypes.c_int
        self.fd=lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        if self.fd<0:raise OSError(ctypes.get_errno(),'inotify unavailable')
        self.paths={};self.missing=[];self.overflows=0;self.skipped=0;self.seen={}
        for name in WATCH_ROOTS:
            p=Path(name)
            if not p.is_dir() or any(x.is_symlink() for x in (p,*p.parents)):self.missing.append(name);continue
            wd=lib.inotify_add_watch(self.fd,os.fsencode(name),0x8|0x80|0x01000000|0x02000000) # CLOSE_WRITE, MOVED_TO, ONLYDIR, DONT_FOLLOW
            if wd<0:self.missing.append(name)
            else:self.paths[wd]=name
        if '/tmp' not in self.paths.values():self.close();raise RuntimeError('Required /tmp artifact watch unavailable')
    def close(self):
        if self.fd>=0:os.close(self.fd);self.fd=-1
    def poll(self,when):
        result=[]
        for _ in range(16): # bounded drain; queue-overflow remains explicit
            try:data=os.read(self.fd,65536)
            except BlockingIOError:break
            offset=0
            while offset+16<=len(data):
                wd,mask,cookie,length=struct.unpack_from('iIII',data,offset);offset+=16
                raw=data[offset:offset+length].split(b'\0',1)[0];offset+=length
                if mask&0x4000:self.overflows+=1;continue
                if wd not in self.paths or not raw or mask&0x40000000:continue
                directory=self.paths[wd];path=str(Path(directory)/os.fsdecode(raw));cron=directory.startswith('/var/spool/cron')
                try:m=metadata(path,cron)
                except (OSError,ValueError):self.skipped+=1;continue
                fingerprint=(m['artifact_device'],m['artifact_inode'],m['artifact_sha256'],m['artifact_mtime_ns'])
                if self.seen.get(path)==fingerprint:continue
                self.seen[path]=fingerprint
                if len(self.seen)>4096:self.seen.pop(next(iter(self.seen)))
                result.append({**m,'kind':'file.cron_changed' if cron else 'file.artifact_closed','event_time':when,'artifact_action':'cron_changed' if cron else 'file_closed','file_transport_verified':False,'sampling_is_complete_audit':False})
        return result
    def health(self):return dict(artifact_watch_enabled=True,artifact_watch_paths=sorted(self.paths.values()),artifact_watch_missing=self.missing,artifact_queue_overflows=self.overflows,artifact_skipped=self.skipped)


def script_metadata(pid,proc=Path('/proc')):
    # Whitelist only the interpreter's script argument. Never retain full argv,
    # shell -c strings, passwords, environment values or file contents.
    args=(proc/str(pid)/'cmdline').read_bytes().split(b'\0')
    if len(args)<2:return None
    index=2 if args[1]==b'--' else 1
    if len(args)<=index or not args[index] or args[index].startswith(b'-'):return None
    value=os.fsdecode(args[index]);p=Path(value)
    if not p.is_absolute():p=Path(os.readlink(proc/str(pid)/'cwd'))/p
    path=os.path.normpath(str(p))
    if not allowed(path):return None
    return metadata(path)
