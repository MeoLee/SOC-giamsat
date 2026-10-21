"""Enable bounded campaign correlation, preserving the existing live config."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
from soc_ai.common import read_json, write_json
from live_config import load_config
from lab_campaign import DEFAULTS


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=Path(__file__).with_name('live-config.json'))
    parser.add_argument('--http-flood',action='store_true',help='Enable dedicated Apache HTTP-pressure/degradation alerts; requires 0.4.12 Wazuh bridge rules')
    parser.add_argument('--syn-flood',action='store_true',help='Enable unique SYN connection pressure alerts (119219)')
    a=parser.parse_args();load_config(a.config)
    config=read_json(a.config)
    candidate={**config,'correlation':{**DEFAULTS,**config.get('correlation',{}),'attack_chain_enabled':True}}
    if a.http_flood:
        if not any(s['kind']=='web' for s in load_config(a.config)['sources']):
            parser.error('HTTP flood detection requires an Apache TSV web source in live-config.json')
        candidate['correlation']['http_load_alerts_enabled']=True
    if a.syn_flood:candidate['correlation']['syn_load_alerts_enabled']=True
    # Validate before replacing; write_json itself uses an atomic replacement.
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        path=Path(folder)/'candidate.json';write_json(path,candidate);load_config(path)
    if candidate!=config:
        backup=a.config.with_name(a.config.name+'.before-chains-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        shutil.copy2(a.config,backup);write_json(a.config,candidate);print('CONFIG_BACKUP:',backup)
    print('ATTACK_CHAIN_ENABLED; start a NEW Live session. Existing weights/SSH/PAM unchanged.')
    if a.http_flood:print('HTTP_FLOOD_ALERTS_ENABLED: verify same-route baseline and Wazuh rules 119217/119218 before traffic.')


if __name__=='__main__':main()
