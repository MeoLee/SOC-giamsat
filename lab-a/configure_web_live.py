"""Append Apache sources to the existing live configuration, preserving assets."""
import argparse
import json
from pathlib import Path
import subprocess


def updated_config(data, container):
    import copy
    result = copy.deepcopy(data)
    desired = [
        {'kind':'web','container':container,'path':'/var/log/apache2/soc-lab-requests.tsv','output':'apache-requests.tsv'},
        {'kind':'raw','container':container,'path':'/var/log/apache2/soc-lab-access.log','output':'apache-access.log'},
    ]
    for source in desired:
        existing = [s for s in result['sources'] if s['output']==source['output']]
        if existing and existing != [source]:
            raise ValueError('Conflicting web source output: '+source['output'])
        if not existing: result['sources'].append(source)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,default=Path('live-config.json'))
    p.add_argument('--container',default='ubuntu-endpoint')
    a = p.parse_args()
    from soc_ai.common import read_json, write_json
    from live_config import load_config
    load_config(a.config)
    data = updated_config(read_json(a.config), a.container)
    for source in data['sources']:
        if source['kind'] in ('web','raw'):
            subprocess.run(['docker','exec',a.container,'test','-f',source['path']],check=True)
    write_json(a.config,data)
    from live_config import load_config
    load_config(a.config)
    print('WEB_SOURCES_CONFIGURED:',a.config)
    print('New sessions will archive Apache raw logs and normalize HTTP requests.')


if __name__=='__main__': main()
