"""Bounded operational scenarios for the two existing private Docker lab hosts.

Run only after Live has enabled Wazuh publication. Operator evidence is kept
separately; these scenarios never create training labels or assert compromise.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time

from live_config import container_name
from soc_ai.common import read_json, write_json

SCENARIOS = {
    'normal-http':('12 ordinary GET requests, about one per second', ['119210','119207']),
    'normal-ssh':('Five successful SSH sessions, 5 seconds each', ['119208','119207']),
    'port-scan':('One TCP connect scan of ports 1..32, at most 5 probes/second', ['119209','119203']),
    'single-port':('24 TCP connections to SSH only; no password attempts', ['119209']),
    'ssh-negative':('One intentionally wrong password then one interactive correct login', ['119208']),
    'ssh-burst':('Eight intentionally wrong passwords to a dedicated test account', ['119204']),
    'ssh-success':('One correct interactive login; standalone control, not a full chain', ['119208']),
    'chain':('32-port recon, eight wrong passwords, then one correct login in one Live session', ['119203','119204','119205']),
    'web-sqli':('One SQL syntax indicator GET against DVWA; exploitation is not asserted', ['119209','119206']),
    'http-burst':('At most 50 GETs, at most 5 per second, 10-second start window; not a DDoS label', ['119210']),
}


def now():
    return datetime.now(timezone.utc).isoformat()


def private_v4(value):
    ip=ipaddress.ip_address(value)
    return ip.version==4 and any(ip in ipaddress.ip_network(n) for n in
        ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def lab_scope(client, sensor, target, runner=subprocess.run):
    for name in (client,sensor): container_name(name)
    if client==sensor or not private_v4(target):
        raise ValueError('Choose two separate lab containers and an RFC1918 target')
    def inspect(*args):
        r=runner(['docker',*args],capture_output=True,timeout=15)
        if r.returncode: raise RuntimeError(r.stderr.decode(errors='replace')[:500])
        return json.loads(r.stdout)
    containers=inspect('inspect',client,sensor)
    if len(containers)!=2: raise ValueError('Expected exactly two lab containers')
    c,s=containers
    matches=[]
    for name,link in s['NetworkSettings']['Networks'].items():
        peer=c['NetworkSettings']['Networks'].get(name)
        if link.get('IPAddress')!=target or not peer: continue
        source=peer.get('IPAddress')
        if source==target or not private_v4(source): continue
        network=inspect('network','inspect',name)[0]
        if network.get('Driver')=='bridge':
            matches.append({'network':name,'source_ip':source,'target_ip':target,
                            'client':client,'sensor':sensor})
    if len(matches)!=1: raise ValueError('Target must identify one common private Docker bridge')
    return matches[0]


def normal_http_commands(client,target):
    return [['docker','exec',client,'curl','--max-time','4','--retry','0',
        '--silent','--show-error','--output','/dev/null','--write-out','%{http_code} %{time_total}\\n',
        'http://'+target+path] for path in ('/soc-lab-health','/dvwa/login.php')*6]


def scan_command(client,target):
    return ['docker','exec',client,'timeout','30','nmap','-sT','-Pn','-n',
        '--max-retries','0','--scan-delay','200ms','--max-parallelism','1',
        '--max-rate','5','--host-timeout','25s','-p','1-32',target]


def ssh_command(client,target,username,wrong=False):
    # Remote command is fixed; account and IP are independently validated.
    argv=['docker','exec']
    if not wrong: argv+=['-it']
    argv += [client,'timeout','25' if not wrong else '7']
    if wrong: argv+=['sshpass','-p','SOC-LAB-INTENTIONAL-WRONG-PASSWORD-ONLY']
    argv += ['ssh','-o','ConnectTimeout=3','-o','ConnectionAttempts=1',
        '-o','NumberOfPasswordPrompts=1','-o','PubkeyAuthentication=no',
        '-o','PreferredAuthentications=password','-o','StrictHostKeyChecking=accept-new',
        '-o','UserKnownHostsFile=/tmp/soc-wazuh-scenarios-known-hosts',
        username+'@'+target,'whoami; date -Is; uptime; sleep 5']
    return argv


def expected_password_rejection(result, target, username):
    """Classify the client's rejection, not proof of a server auth-log event.

    With NumberOfPasswordPrompts=1 OpenSSH can exit 255 before sshpass sees
    another prompt and returns its own code 5. Other SSH errors also use 255,
    so require the exact account/target and password in the denial methods.
    """
    if result.returncode == 5:
        return True
    if result.returncode != 255:
        return False
    stderr = result.stderr.decode(errors='replace')
    match = re.search(r'(?m)^' + re.escape(username + '@' + target)
                      + r': Permission denied \(([^)\r\n]+)\)\.\r?$', stderr)
    return bool(match and 'password' in match.group(1).split(','))


def validate_capture(path, client, sensor):
    capture=read_json(path/'session.json'); ai=read_json(path/'ai-session.json')
    if capture.get('closed') or ai.get('status')!='running':
        raise ValueError('Open a fresh running Live session before this scenario')
    if not ai.get('wazuh_publication',{}).get('enabled'):
        raise ValueError('Live must be started with --publish-wazuh')
    if not ai['wazuh_publication'].get('observations_enabled'):
        raise ValueError('Live must enable --publish-observations for normal controls')
    if sensor not in {s['container'] for s in capture.get('sources',[])}:
        raise ValueError('Capture does not contain the selected sensor')
    return capture, ai


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('plan','run'))
    p.add_argument('--scenario',choices=SCENARIOS,required=True)
    p.add_argument('--client',default='kali-attacker')
    p.add_argument('--sensor',default='ubuntu-endpoint')
    p.add_argument('--target',default='172.20.0.3')
    p.add_argument('--username',default='soctest')
    p.add_argument('--capture',type=Path)
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',a.username): p.error('Invalid lab account name')
    if not private_v4(a.target): p.error('Target must be RFC1918 IPv4')
    for name in (a.client,a.sensor): container_name(name)
    description,ids=SCENARIOS[a.scenario]
    if a.action=='plan':
        print(json.dumps({'scenario':a.scenario,'description':description,
            'expected_rule_ids':ids,'target':a.target,'username':a.username,
            'note':'Expectations are operational checks, not training labels. Single-port may trigger SYN rules but must not be called distinct-port scanning.'},indent=2))
        return 0
    if not a.capture or not a.output: p.error('run requires --capture and --output')
    if a.output.exists(): p.error('Output exists; choose a new evidence directory')
    capture,ai=validate_capture(a.capture,a.client,a.sensor)
    scope=lab_scope(a.client,a.sensor,a.target)
    a.output.mkdir(parents=True,exist_ok=False)
    report={'schema_version':'soc-operational-scenario/0.1','scenario':a.scenario,
        'description':description,'expected_rule_ids':ids,'scope':scope,'username':a.username,
        'capture_session_id':capture['session_id'],'capture_directory':str(a.capture),
        'model_weights_sha256':ai['model_weights_sha256'],'started_at':now(),
        'complete':False,'training_label':None,'steps':[]}
    path=a.output/'operator.json'
    def command(argv, *, interactive=False, expected=(0,), timeout=40,
                expect_password_rejection=False):
        start=now()
        r=subprocess.run(argv,timeout=timeout,capture_output=not interactive)
        step={'argv':argv,'started_at':start,'ended_at':now(),'returncode':r.returncode,
              'interactive':interactive}
        if not interactive:
            step.update(stdout=r.stdout.decode(errors='replace')[:16000],
                        stderr=r.stderr.decode(errors='replace')[:4000])
            print(step['stdout'],end='',flush=True)
        accepted = (expected_password_rejection(r,a.target,a.username)
                    if expect_password_rejection else r.returncode in expected)
        if expect_password_rejection:
            step['client_outcome'] = 'password_rejected' if accepted else 'unexpected_result'
        report['steps'].append(step); write_json(path,report)
        if not accepted:
            detail = step.get('stderr','').strip() or step.get('stdout','').strip()
            raise RuntimeError(f'Scenario command failed (exit {r.returncode}): '
                               + (detail[:2000] or 'inspect operator.json'))
        if expect_password_rejection:
            print(f'EXPECTED_PASSWORD_REJECTION: exit={r.returncode}',flush=True)
        return r
    try:
        # One operation per capture. A chain is one operation with multiple steps.
        with (a.capture/'scenario-operation.json').open('x',encoding='utf-8') as f:
            json.dump({'scenario':a.scenario,'operator_file':str(path)},f)
        write_json(path,report)
        burst=a.scenario in ('ssh-burst','ssh-negative','chain')
        if a.scenario.startswith('ssh') or a.scenario in ('normal-ssh','chain'):
            command(['docker','exec',a.sensor,'id',a.username])
        if burst:
            command(['docker','exec',a.client,'sh','-c','command -v sshpass'])
            # Do not change PAM/lockout policy to force a successful scenario.
            check=command(['docker','exec',a.sensor,'python3','-c',
                'from pathlib import Path; print("\\n".join(l for n in ("sshd","common-auth","common-account") if (Path("/etc/pam.d")/n).exists() for l in (Path("/etc/pam.d")/n).read_text().splitlines() if not l.lstrip().startswith("#")))'])
            if re.search(r'pam_(?:faillock|tally2)\.so',check.stdout.decode(errors='replace')):
                raise ValueError('Account lockout module found; review the dedicated lab account policy first')
        if a.scenario in ('port-scan','chain'):
            command(scan_command(a.client,a.target))
        if a.scenario=='single-port':
            for _ in range(24):
                command(['docker','exec',a.client,'nc','-z','-w','1',a.target,'22'])
                time.sleep(.2)
        if a.scenario=='normal-http':
            for argv in normal_http_commands(a.client,a.target):
                result=command(argv)
                if result.stdout.split()[:1]!=[b'200']: raise ValueError('Expected normal page HTTP 200')
                time.sleep(1)
        if a.scenario=='http-burst':
            started=time.monotonic();count=0
            argv=normal_http_commands(a.client,a.target)[0]
            while count<50 and time.monotonic()-started<10:
                command(argv);count+=1;time.sleep(.2)
            report.update(http_requests=count,http_start_window_seconds=10,
                          ddos_ground_truth_established=False)
        if burst:
            count=1 if a.scenario=='ssh-negative' else 8
            started=time.monotonic()
            for _ in range(count):
                if time.monotonic()-started>50: raise RuntimeError('Password-failure window exceeded; collect actual auth outcomes')
                command(ssh_command(a.client,a.target,a.username,True),
                        expect_password_rejection=True,timeout=12)
            report['failure_attempts']=count
            report['failure_attempts_seconds']=round(time.monotonic()-started,3)
        if a.scenario in ('normal-ssh','ssh-success','ssh-negative','chain'):
            for _ in range(5 if a.scenario=='normal-ssh' else 1):
                print('Enter the correct dedicated lab account password at the SSH prompt.',flush=True)
                command(ssh_command(a.client,a.target,a.username),interactive=True,timeout=35)
        if a.scenario=='web-sqli':
            command(['docker','exec',a.client,'curl','--max-time','5','--retry','0',
                '--silent','--show-error','--output','/tmp/soc-wazuh-sqli-response.html',
                '--write-out','%{http_code} %{time_total}\\n',
                'http://'+a.target+'/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit'])
            report['exploitation_success_proven']=False
        report['complete']=True
        print('SCENARIO_COMMANDS_COMPLETED; verify raw outcomes and Wazuh events separately')
        return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        report['error']=str(exc);print('SCENARIO_FAILED:',exc)
        return 2
    finally:
        report['ended_at']=now();write_json(path,report);print('EVIDENCE:',path)


if __name__=='__main__':
    raise SystemExit(main())
