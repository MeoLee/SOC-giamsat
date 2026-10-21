"""Create one benign control or standard EICAR test artifact inside Kali only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re

EICAR_MD5='44d88612fea8a8f36de82e1278abb02f'
EICAR_SHA256='275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
# Encoded to avoid distributing an actual antivirus test file in a Windows ZIP.
EICAR_B64='WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='


def create(directory,kind,token):
    if not re.fullmatch(r'[A-Za-z0-9-]{1,48}',token):raise ValueError('Invalid artifact token')
    root=Path(directory)
    if not root.is_dir() or root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise ValueError('Use an existing real temporary directory')
    data=base64.b64decode(EICAR_B64,validate=True) if kind=='eicar' else ('SOC LAB BENIGN VT CONTROL '+token+'\n').encode()
    if kind not in ('eicar','control'):raise ValueError('Invalid artifact kind')
    digest=hashlib.sha256(data).hexdigest()
    if kind=='eicar' and (len(data)!=68 or digest!=EICAR_SHA256):raise RuntimeError('EICAR test vector mismatch')
    path=root/('vt-'+kind+'-'+token+'.txt')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    return {'path':str(path),'bytes':len(data),'sha256':digest,'md5':hashlib.md5(data).hexdigest(),
            'standard_antivirus_test_file':kind=='eicar','real_malware':False,'executed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--kind',choices=('control','eicar'),required=True)
    parser.add_argument('--token',required=True);args=parser.parse_args()
    print(json.dumps(create(args.directory,args.kind,args.token),indent=2))


if __name__=='__main__':main()
