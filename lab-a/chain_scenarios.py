"""Scan-first, bounded exercises; phases are evidence collection, not labels."""
import argparse,json,subprocess,time
from pathlib import Path
from soc_ai.common import write_json
from wazuh_scenarios import lab_scope,validate_capture,scan_command,ssh_command,expected_password_rejection,now
SCENARIOS={'http-pressure':['http_pressure_or_degradation'],
           'chain-http-sqli':['http_pressure_or_degradation','possible_web_sqli'], 'chain-sqli':['possible_web_sqli'], 'chain-bruteforce':['repeated_auth_failures'],
           'chain-dos':['http_pressure_or_degradation'],
           'chain-mixed':['repeated_auth_failures','http_pressure_or_degradation','possible_web_sqli']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenario',choices=SCENARIOS,required=True)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--username',default='soctest');p.add_argument('--plan',action='store_true');a=p.parse_args()
    import re
    if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',a.username):p.error('Invalid lab account')
    if a.plan:
        print(json.dumps({'scenario':a.scenario,'required_stages':SCENARIOS[a.scenario],
            'http_limits':{'requests':100,'starts_per_second':20,'concurrency':4},'training_label':None}));return 0
    capture,ai=validate_capture(a.capture,'kali-attacker','ubuntu-endpoint')
    frozen=json.loads((a.capture/'correlation-cases.json').read_text(encoding='utf-8-sig'))
    if not frozen.get('config',{}).get('attack_chain_enabled'):raise ValueError('Enable attack chains and open NEW Live')
    scope=lab_scope('kali-attacker','ubuntu-endpoint','172.20.0.3')
    a.output.mkdir(parents=True,exist_ok=False);path=a.output/'operator.json'
    report={'schema_version':'soc-chain-scenario/0.2','scenario':a.scenario,'capture_session_id':capture['session_id'],
            'scope':scope,'username':a.username,'started_at':now(),'complete':False,'training_label':None,
            'expected_rule_ids':['119213'],
            'expected_rule_id_groups':[['119212','119214']],'required_stages':([] if a.scenario=='http-pressure' else ['possible_recon'])+SCENARIOS[a.scenario],
            'steps':[],'phase_errors':[]}
    def command(argv,wrong=False,input_bytes=None):
        started=now();r=subprocess.run(argv,input=input_bytes,capture_output=True,timeout=35)
        accepted=expected_password_rejection(r,scope['target_ip'],a.username) if wrong else r.returncode==0
        report['steps'].append({'argv':argv,'started_at':started,'ended_at':now(),'returncode':r.returncode,
            'stdout':r.stdout.decode(errors='replace')[:8000],'stderr':r.stderr.decode(errors='replace')[:3000],
            'client_outcome':'password_rejected' if wrong and accepted else 'completed' if accepted else 'unexpected_result'})
        write_json(path,report)
        if not accepted:raise RuntimeError(report['steps'][-1]['stderr'] or 'Command returned '+str(r.returncode))
        print(r.stdout.decode(errors='replace'),end='',flush=True);return r
    target=scope['target_ip'];client=scope['client']
    try:
        with (a.capture/'scenario-operation.json').open('x',encoding='utf-8') as f:json.dump({'scenario':a.scenario,'operator_file':str(path)},f)
        if a.scenario!='http-pressure':
            scan=scan_command(client,target);scan[scan.index('-p')+1]='1-32,80,443';command(scan)
        if a.scenario in ('chain-bruteforce','chain-mixed'):
            try:
                command(['docker','exec','ubuntu-endpoint','id',a.username])
                # Observe existing protection; never turn off lockout/penalties.
                check=command(['docker','exec','ubuntu-endpoint','sh','-c','cat /etc/pam.d/common-auth /etc/pam.d/common-account'])
                if re.search(r'pam_(faillock|tally2)\.so',check.stdout.decode(errors='replace')):
                    raise ValueError('Lockout module present; review dedicated lab account policy')
                started=time.monotonic()
                for _ in range(8):
                    if time.monotonic()-started>50:raise RuntimeError('Auth window exceeded')
                    command(ssh_command(client,target,a.username,True),wrong=True)
            except (RuntimeError,ValueError,subprocess.SubprocessError) as e:
                report['phase_errors'].append({'phase':'auth','error':str(e)})
                print('AUTH_PHASE_INCOMPLETE; independent HTTP phases continue; no transport error counted as auth failure.')
        if a.scenario in ('chain-dos','chain-mixed','http-pressure','chain-http-sqli'):
            for _ in range(20):
                command(['docker','exec',client,'curl','--noproxy','*','--max-time','3','--silent','--show-error',
                    '--output','/dev/null','--fail','http://'+target+'/soc-lab-health']);time.sleep(1)
            script=Path(__file__).with_name('bounded_http_load.py').read_bytes()
            r=command(['docker','exec','-i',client,'python3','-',target],input_bytes=script)
            report['http_load']=json.loads(r.stdout)
        if a.scenario in ('chain-sqli','chain-mixed','chain-http-sqli'):
            command(['docker','exec',client,'curl','--noproxy','*','--max-time','5','--silent','--show-error',
                '--output','/dev/null','--write-out','%{http_code}\n',
                'http://'+target+'/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit'])
        report['complete']=not report['phase_errors']
        print('SCENARIO_COMMANDS_COMPLETED' if report['complete'] else 'SCENARIO_PARTIAL; inspect phase_errors and raw outcomes')
        return 0 if report['complete'] else 2
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:
        report['phase_errors'].append({'phase':'runner','error':str(e)});print('SCENARIO_FAILED:',e);return 2
    finally:
        report['ended_at']=now();write_json(path,report);print('EVIDENCE:',path)
if __name__=='__main__':raise SystemExit(main())
