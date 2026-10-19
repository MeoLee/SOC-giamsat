"""Collect three separate normal HTTP sessions and build a new mixed cache."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import uuid

from collect_normal_http import collect
from prepare_lab_mix import run as mix, load_local
from soc_ai.common import read_json, sha256, write_json

EXISTING=[r'E:\SOC-Lab\AI\lab-data\imports\normal-train-20261014-103038-358',
          r'E:\SOC-Lab\AI\lab-data\imports\normal-validation-20261014-210754-354',
          r'E:\SOC-Lab\AI\lab-data\imports\normal-test-20261014-211740-656']


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-prepared',type=Path,default=Path(r'E:\SOC-Lab\AI\prepared-v01'))
    p.add_argument('--existing-imports',nargs='+',type=Path,default=list(map(Path,EXISTING)))
    p.add_argument('--output-root',type=Path,default=Path(r'E:\SOC-Lab\AI\quality-data'))
    p.add_argument('--connections',type=int,default=120)
    a=p.parse_args()
    base=read_json(a.base_prepared/'report.json')
    if not base.get('complete') or base.get('local_inputs'):
        raise ValueError('Requires original complete prepared-v01, not an already mixed cache')
    if sha256(a.base_prepared/'data.npz')!=base.get('data_sha256'):
        raise ValueError('Base prepared cache hash mismatch')
    load_local(a.existing_imports)  # Reject missing/changed original imports before generating traffic.
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output=a.output_root/(stamp+'-'+uuid.uuid4().hex[:6]);output.mkdir(parents=True,exist_ok=False)
    plan={'version':'soc-quality-data/0.1','complete':False,'base_prepared':str(a.base_prepared),
          'existing_imports':list(map(str,a.existing_imports)),'http_imports':{}}
    write_json(output/'quality-plan.json',plan)
    print('QUALITY DATA:',output,flush=True)
    print('Three separate sessions; no concurrent attacks. Each waits for completed Suricata flows.',flush=True)
    for role in ('train','validation','test'):
        args=SimpleNamespace(role=role,connections=a.connections,source='kali-attacker',
            sensor='ubuntu-endpoint',server='172.20.0.3',port=80,wait_seconds=180,output_root=output/role)
        directory=collect(args)
        plan['http_imports'][role]=str(directory)
        write_json(output/'quality-plan.json',plan)
    prepared=output/'prepared'
    mix(a.base_prepared,list(a.existing_imports)+[Path(v) for v in plan['http_imports'].values()],prepared)
    plan.update(complete=True,prepared=str(prepared))
    write_json(output/'quality-plan.json',plan)
    write_json(a.output_root/'latest-quality-plan.json',plan|{'plan_file':str(output/'quality-plan.json')})
    print('QUALITY_DATA_READY:',prepared,flush=True)
    print('Dataset prepared. No training, model replacement, or change to AI Live was performed.',flush=True)


if __name__=='__main__':main()
