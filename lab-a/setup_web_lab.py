"""Host-side installer. Run in Windows PowerShell, not in Kali Bash."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--container', default='ubuntu-endpoint')
    p.add_argument('--lab-cidr', default='172.20.0.0/24')
    a = p.parse_args()
    ipaddress.ip_network(a.lab_cidr, strict=True)
    state = subprocess.check_output(['docker', 'inspect', a.container, '--format', '{{.State.Running}}'], text=True).strip()
    if state != 'true': raise SystemExit('Start ubuntu-endpoint first')
    packages = ['apache2', 'mariadb-server', 'mariadb-client', 'php', 'php-mysql', 'php-gd',
                'libapache2-mod-php', 'git', 'curl', 'ca-certificates', 'python3', 'procps']
    print('Installing Apache/PHP/MariaDB. Keep this terminal open; apt progress follows.', flush=True)
    for command in (['apt-get', 'update'], ['apt-get', 'install', '-y', '--no-install-recommends', *packages]):
        subprocess.run(['docker', 'exec', '--user', '0', '-e', 'DEBIAN_FRONTEND=noninteractive', a.container, *command], check=True)
    root = Path(__file__).resolve().parent
    script = (root/'endpoint/setup_web.py').read_text(encoding='utf-8')
    payload = {'lab_cidr': a.lab_cidr, 'start_script': (root/'endpoint/start-soc-web.sh').read_text(encoding='utf-8')}
    subprocess.run(['docker', 'exec', '-i', '--user', '0', a.container, 'python3', '-c', script],
                   input=json.dumps(payload).encode(), check=True)
    print('NEXT: verify access from kali-attacker, then add web detection rules and AI web telemetry.', flush=True)


if __name__ == '__main__': main()
