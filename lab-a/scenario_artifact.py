"""Transfer a fixed benign marker for FIM, with peer/server/hash evidence."""
import argparse,json,subprocess,uuid
from pathlib import Path
from soc_ai.common import write_json
from wazuh_scenarios import validate_capture,lab_scope,now
from endpoint_probe import PAYLOAD,PAYLOAD_SHA256,SERVER_PORT
from chain_exercise import start_server,read_state,verify_server,STOP_SERVER


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    capture,_=validate_capture(a.capture,'kali-attacker','ubuntu-endpoint')
    scope=lab_scope('kali-attacker','ubuntu-endpoint','172.20.0.3')
    a.output.mkdir(parents=True,exist_ok=False);path=a.output/'operator.json';token=uuid.uuid4().hex
    destination='/var/lib/soc-lab/fim/'+token+'.txt'
    report={'schema_version':'soc-benign-artifact/0.1','capture_session_id':capture['session_id'],
        'scope':scope,'artifact_path':destination,'sha256':PAYLOAD_SHA256,'bytes':len(PAYLOAD),
        'started_at':now(),'complete':False,'malware_test':False,'virustotal_used':False,'steps':[]}
    started=False
    def command(argv):
        r=subprocess.run(argv,capture_output=True,timeout=15)
        report['steps'].append({'argv':argv,'returncode':r.returncode,'stdout':r.stdout.decode(errors='replace')[:16000],'stderr':r.stderr.decode(errors='replace')[:3000]})
        write_json(path,report)
        if r.returncode:raise RuntimeError(report['steps'][-1]['stderr'] or 'Command failed')
        return r
    try:
        with (a.capture/'scenario-operation.json').open('x') as f:json.dump({'scenario':'benign-file-transfer','operator_file':str(path)},f)
        check='import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert p.parent.is_dir() and not p.parent.is_symlink() and not p.exists() and not p.is_symlink()'
        command(['docker','exec','--user','soctest','ubuntu-endpoint','python3','-c',check,destination])
        started=True;start_server(scope['client'],scope['source_ip'],scope['target_ip'],token,command)
        command(['docker','exec','--user','soctest','ubuntu-endpoint','curl','--noproxy','*','--proto','=http','--max-time','5','--max-filesize','4096','--max-redirs','0','--fail','--silent','--show-error','--output',destination,'http://'+scope['source_ip']+':'+str(SERVER_PORT)+'/'+token+'.txt'])
        actual=command(['docker','exec','--user','soctest','ubuntu-endpoint','python3','-c','import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())',destination]).stdout.decode().strip()
        if actual!=PAYLOAD_SHA256:raise RuntimeError('Artifact SHA256 mismatch')
        rows=read_state(scope['client'],token,command);report['server_evidence']=verify_server(rows,scope['target_ip'],token)
        report['complete']=True
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:report['error']=str(e)
    finally:
        if started:
            try:command(['docker','exec',scope['client'],'python3','-c',STOP_SERVER,token])
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as e:report['cleanup_error']=str(e);report['complete']=False
        report['ended_at']=now();write_json(path,report)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('EVIDENCE:',path)
    print('FIM/native alert delivery must be verified separately; no actor/chain is inferred from FIM alone.')
    return 0 if report['complete'] else 2

if __name__=='__main__':raise SystemExit(main())
