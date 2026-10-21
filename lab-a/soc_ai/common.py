import hashlib
import json
from pathlib import Path
from .fileio import atomic_writer,read_bytes

CLASSES = ['BENIGN','FTP-Patator','SSH-Patator','Bot','PortScan','DDoS']

def display_label(label):
    """Presentation alias only; keep trained class indices and raw scores intact."""
    return 'DoS' if label == 'DDoS' else label

DISPLAY_CLASSES = [display_label(label) for label in CLASSES]

def write_json(path, obj):
    path=Path(path)
    payload=json.dumps(obj,indent=2,ensure_ascii=False,allow_nan=False).encode('utf-8')
    with atomic_writer(path) as stream:
        stream.write(payload)

def read_json(path):
    return json.loads(read_bytes(path).decode('utf-8-sig'))

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
