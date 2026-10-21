from pathlib import Path
import subprocess,urllib.request,json,shutil,hashlib,zipfile,yaml
R=Path(__file__).resolve().parent.parent
import argparse,tempfile
a=argparse.ArgumentParser();a.add_argument('--staging',type=Path,required=True);args=a.parse_args()
root=args.staging/'Bai-Nop';D=root/'SOC-AI-Lab'
if root.exists():raise SystemExit('Choose a fresh staging directory')
def write(p,s):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8',newline='\n')
def fetch(rel):
 u='https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.14.7/single-node/'+rel
 b=urllib.request.urlopen(u,timeout=25).read();p=D/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
for rel in ['docker-compose.yml','generate-indexer-certs.yml','config/certs.yml','config/wazuh_dashboard/opensearch_dashboards.yml','config/wazuh_dashboard/wazuh.yml','config/wazuh_indexer/wazuh.indexer.yml','config/wazuh_indexer/internal_users.yml','config/wazuh_cluster/wazuh_manager.conf']:fetch(rel)
c=yaml.safe_load((D/'docker-compose.yml').read_text());(D/'docker-compose.yml').unlink()
c['name']='soc-ai-submission'
for n,s in c['services'].items():
 s['container_name']='single-node-'+n+'-1'
 s['networks']={'lab':{'ipv4_address':'172.20.0.2'}} if n=='wazuh.manager' else {'backend':{}}
 if n=='wazuh.manager':s['networks']['backend']={}
 s.pop('links',None)
 if 'ports' in s:s['ports']=['127.0.0.1:'+str(p) for p in s['ports']]
 if n=='wazuh.manager':s['environment']=[x.replace('INDEXER_URL="https://wazuh.indexer:9200"','INDEXER_URL=https://wazuh.indexer:9200') for x in s['environment']]
for n,s in c['services'].items():
 s['volumes']=list(s['volumes'])
c['networks']={'backend':{},'lab':{'ipam':{'config':[{'subnet':'172.20.0.0/24'}]}}}
c['services']['ubuntu-endpoint']={'build':{'context':'.','dockerfile':'containers/endpoint/Dockerfile'},'image':'soc-ai-endpoint:submission-1','container_name':'ubuntu-endpoint','hostname':'ubuntu-endpoint','init':True,'environment':{'LAB_SSH_PASSWORD':'${LAB_SSH_PASSWORD:-123456}'},'networks':{'lab':{'ipv4_address':'172.20.0.3'}},'restart':'unless-stopped'}
c['services']['kali-attacker']={'build':{'context':'.','dockerfile':'containers/kali/Dockerfile'},'image':'soc-ai-kali:submission-1','container_name':'kali-attacker','hostname':'kali-attacker','init':True,'tty':True,'stdin_open':True,'networks':{'lab':{'ipv4_address':'172.20.0.4'}},'restart':'unless-stopped'}
ai={'build':{'context':'.','dockerfile':'ai/Dockerfile'},'image':'soc-ai-controller:submission-1','working_dir':'/app','volumes':['./ai/src:/app','./model/mlp04-quality:/model:ro','./runtime/sessions:/sessions','/var/run/docker.sock:/var/run/docker.sock'],'networks':{'backend':{}},'init':True,'profiles':['ai'],'environment':{'PYTHONUNBUFFERED':'1'}}
c['services']['ai']={**ai,'command':['python','/app/submission_entry.py','monitor']}
c['services']['bootstrap']={**ai,'profiles':['setup'],'command':['python','/app/submission_entry.py','bootstrap']}
write(D/'compose.yaml','# Wazuh configuration derived from wazuh/wazuh-docker v4.14.7 (GPLv2).\n'+yaml.safe_dump(c,sort_keys=False))
# Runtime: all defensive collector/correlation installers, shared package and assets.
tracked=subprocess.check_output(['git','ls-files','lab-a'],cwd=R,text=True).splitlines()
for name in tracked:
 p=R/name;rel=p.relative_to(R/'lab-a')
 if not p.is_file():continue
 if rel.parts[0]=='docs':
  dest=root/'Tai-Lieu'/'Tai-Lieu-Ky-Thuat'/Path(*rel.parts[1:])
 elif rel.parts[0]=='dashboards':dest=D/rel
 elif rel.parts[0]=='soc_ai':
  dest=root/'Model-Training'/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
  if len(rel.parts)>1 and rel.parts[1] in ('train.py','prepare.py','dashboard.py','web'):continue
  dest=D/'ai/src'/rel
 elif rel.parts[0]=='tests' or rel.name.startswith('test_'):
  dest=root/'Model-Training'/rel
 elif p.suffix in ('.py','.json','.xml','.rules','.txt','.html','.sh') and rel.name!='SHA256SUMS.txt':dest=D/'ai/src'/rel
 else:continue
 dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
# Preserve complete research sources outside the runtime for teacher review.
for name in tracked:
 p=R/name;rel=p.relative_to(R/'lab-a')
 if p.is_file() and rel.parts[0]!='docs' and rel.name!='SHA256SUMS.txt':
  dest=root/'Model-Training'/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
# Training launcher dependency files and actual verified versions kept separately.
for n in ['requirements-tested.txt','requirements.txt','run_checks.py']:
 shutil.copy2(R/'lab-a'/n,root/'Model-Training'/n)
write(D/'ai/Dockerfile','''FROM docker:29-cli AS dockercli
FROM python:3.12-slim-bookworm
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
RUN pip install --no-cache-dir torch==2.11.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir numpy==2.3.5 scikit-learn==1.8.0 matplotlib==3.10.8
COPY ai/src/ /app/
CMD ["python","submission_entry.py","monitor"]
''')
write(D/'containers/endpoint/Dockerfile','''FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg openssh-server rsyslog python3 python3-yaml procps iproute2 netcat-openbsd suricata apache2 mariadb-server mariadb-client php php-mysql php-gd libapache2-mod-php git && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update && apt-get install -y --no-install-recommends wazuh-agent=4.14.7-1 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1003 -s /bin/bash soctest && mkdir -p /run/sshd /var/log/suricata /etc/suricata/rules /var/log/soc-lab && echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/00-soc-lab.conf && sed -i 's/MANAGER_IP/172.20.0.2/g' /var/ossec/etc/ossec.conf
COPY ai/src/soc-recon.rules /etc/suricata/rules/soc-lab.rules
COPY containers/endpoint/entrypoint.sh /usr/local/bin/submission-entrypoint
RUN chmod 755 /usr/local/bin/submission-entrypoint
ENTRYPOINT ["/usr/local/bin/submission-entrypoint"]
''')
write(D/'containers/endpoint/entrypoint.sh','''#!/bin/bash
set -Eeuo pipefail
mkdir -p /run/sshd /var/log/suricata /var/log/soc-lab
ssh-keygen -A
printf 'soctest:%s\\n' "${LAB_SSH_PASSWORD:?LAB_SSH_PASSWORD is required}" | chpasswd
/usr/sbin/rsyslogd -n -i /run/soc-lab-rsyslog.pid &
rpid=$!
cleanup() { trap - EXIT TERM INT; /var/ossec/bin/wazuh-control stop || true; apache2ctl -k stop || true; kill "${spid:-0}" "$rpid" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 0' TERM INT
if ! test -s /var/ossec/etc/client.keys; then
  ready=no
  for i in $(seq 1 120); do
    if /var/ossec/bin/agent-auth -m 172.20.0.2 -p 1515 -A ubuntu-endpoint; then ready=yes; break; fi
    sleep 2
  done
  test "$ready" = yes || { echo 'Wazuh enrollment failed' >&2; exit 1; }
fi
/var/ossec/bin/wazuh-control start
/usr/sbin/sshd -D -e &
spid=$!
suricata -D -i eth0 -S /etc/suricata/rules/soc-lab.rules -l /var/log/suricata --pidfile /run/soc-lab-suricata.pid --set unix-command.enabled=yes
if test -x /usr/local/sbin/start-soc-web.sh; then /usr/local/sbin/start-soc-web.sh; fi
if test -f /usr/local/lib/soc-lab/process_observer.py; then python3 /usr/local/lib/soc-lab/process_observer.py --watch-artifacts & fi
wait -n "$rpid" "$spid"
''')
# Do not kill PID0 on an early startup failure.
p=D/'containers/endpoint/entrypoint.sh';s=p.read_text().replace('kill "${spid:-0}" "$rpid" 2>/dev/null || true;', 'if test -n "${spid:-}"; then kill "$spid" 2>/dev/null || true; fi; kill "$rpid" 2>/dev/null || true;');p.write_text(s)
write(D/'containers/kali/Dockerfile','''FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends nmap hydra hping3 netcat-openbsd openssh-client sshpass python3 curl ca-certificates libcap2-bin && if getcap /usr/lib/nmap/nmap 2>/dev/null | grep -q cap_; then setcap -r /usr/lib/nmap/nmap; fi && rm -rf /var/lib/apt/lists/*
COPY ai/src/bounded_http_load.py ai/src/dvwa_cli.py ai/src/dvwa_web_flood.py ai/src/vt_lab_artifact.py /opt/soc-lab/
CMD ["sleep","infinity"]
''')
conf=json.loads((D/'ai/src/live-config.json').read_text());conf['assets']=[{'host':'ubuntu-endpoint','ips':['172.20.0.3']}]
conf['correlation'].update(attack_chain_enabled=True,ssh_extended_chains_enabled=True,artifact_observation_enabled=True,ssh_contact_observations_enabled=True,http_load_alerts_enabled=True,syn_load_alerts_enabled=True)
write(D/'ai/src/live-config.json',json.dumps(conf,indent=2)+'\n')
write(D/'ai/src/submission_entry.py','''"""Deployment controller; uses the host Docker daemon for the existing collector."""
import subprocess,sys,time,json
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/app')
def run(*args):subprocess.run(list(args),cwd=ROOT,check=True)
def bootstrap():
    for name in ('ubuntu-endpoint','kali-attacker','single-node-wazuh.manager-1'):
        for _ in range(150):
            r=subprocess.run(['docker','exec',name,'true'],capture_output=True)
            if r.returncode==0:break
            time.sleep(2)
        else:raise RuntimeError('Container not ready: '+name)
    # Wait for agent enrollment and analysisd, not only a running container.
    for _ in range(150):
        r=subprocess.run(['docker','exec','ubuntu-endpoint','sh','-c','test -s /var/ossec/etc/client.keys && /var/ossec/bin/wazuh-control status | grep -q "wazuh-agentd is running"'],capture_output=True)
        if r.returncode==0:break
        time.sleep(2)
    else:raise RuntimeError('Agent enrollment not ready')
    run('python','setup_web_lab.py')
    run('python','configure_web_live.py')
    run('python','setup_recon.py','--container','ubuntu-endpoint')
    run('python','setup_suricata_web.py','--container','ubuntu-endpoint')
    run('python','setup_scenario_fim.py','--sensor','ubuntu-endpoint')
    run('python','setup_scenario_rules.py','--manager','single-node-wazuh.manager-1')
    run('python','setup_process_observer.py','--sensor','ubuntu-endpoint','--username','soctest','--watch-artifacts')
    run('python','setup_attack_chains.py','--ssh-extended','--http-flood','--syn-flood')
    run('python','setup_wazuh.py','--manager','single-node-wazuh.manager-1')
    run('python','lab_doctor.py','--config','live-config.json','--model','/model','--runtime','--bridge')
    print('BOOTSTRAP_VERIFIED: import dashboards/soc-ai-attack-chain-unified.ndjson in Saved objects; configure VT separately if needed.',flush=True)
def monitor():
    run('python','lab_doctor.py','--config','live-config.json','--model','/model','--runtime','--bridge')
    dest='/sessions/monitor-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run('python','-u','lab_live.py','--model','/model','--config','live-config.json','--output-dir',dest,'--publish-wazuh','--publish-observations','--summary-seconds','1','--interval','1','--grace','90','--heartbeat-seconds','10')
if __name__=='__main__':
    {'bootstrap':bootstrap,'monitor':monitor}[sys.argv[1]]()
''')
write(D/'.env.example','LAB_SSH_PASSWORD=123456\n')
write(D/'.dockerignore','runtime/\nmodel/\n.env\n**/__pycache__/\n**/*.pyc\n.git/\n')
write(D/'model/README.txt','Copy the verified six-file bundle into mlp04-quality/. Model files are not embedded in this archive.\n')
write(D/'runtime/sessions/.gitkeep','')
write(D/'scripts/Prepare.ps1',r'''[CmdletBinding()]
param([string]$ModelSource='E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$dst=Join-Path $root 'model\mlp04-quality'
New-Item -ItemType Directory -Path $dst -Force | Out-Null
foreach($n in @('features.json','model.json','model-weights.npz','preprocessor.json','golden.json','golden-predictions.json')) {
 $to=Join-Path $dst $n
 if(-not (Test-Path -LiteralPath $to)) { Copy-Item -LiteralPath (Join-Path $ModelSource $n) -Destination $to }
 if(-not (Test-Path -LiteralPath $to -PathType Leaf)) {throw "Missing model file $n"}
}
if(-not (Test-Path (Join-Path $root '.env'))) {Copy-Item (Join-Path $root '.env.example') (Join-Path $root '.env')}
Push-Location $root
try {
 & docker compose config --quiet
 if($LASTEXITCODE -ne 0){throw 'Compose validation failed'}
 Write-Host 'PREPARED. No containers started; existing DockerData and volumes unchanged.'
} finally {Pop-Location}
''')
write(root/'Model-Training/README.md','''# Model Training (outside Compose)
Source includes soc_ai/train.py, prepare.py, dashboard.py, web/dashboard.html and shared modules/tests.
Create a separate Python3.12 environment. Install torch2.11.0 from the CPU wheel index and requirements-tested.txt. Start the UI with `python -m soc_ai dashboard --help` to see supported arguments. Datasets and training runs are not included. Copy the evaluated model bundle into SOC-AI-Lab/model/mlp04-quality only after verification. The demo never retrains automatically.
''')
write(root/'Tai-Lieu/DONG-GOI-VA-CHAY-VI.md','''# Bộ triển khai SOC AI — candidate1

Đây là bản dựng để kiểm thử, CHƯA được chạy end-to-end trên Docker Desktop của người dùng. Không coi YAML parse thành công là nghiệm thu deployment. Bộ model đã kiểm chứng vẫn cần chép từ máy người dùng. Không có private key hoặc VT API key cá nhân. Wazuh4.14.7 dùng cấu hình official tag v4.14.7; các mật khẩu mặc định lab trong cấu hình official KHÔNG phải mật khẩu cá nhân. Chỉ bind các cổng Wazuh vào127.0.0.1.

## Cấu trúc
SOC-AI-Lab: runtime Compose/AI/model/config. Model-Training: nguồn train/UI riêng ngoài Compose. Tai-Lieu: tài liệu ngoài Compose. Archive không chứa dataset, .venv, cache, log cũ, checkpoint hoặc DockerData. Model cuối đặt trong model/mlp04-quality và mount read-only. Session ghi ra runtime/sessions.

## Chuẩn bị trên máy hiện tại
Giải nén vào E:\\SOC-Lab\\Bai-Nop (giữ nguyên thư mục model đã chép). Chạy `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Prepare.ps1` tại SOC-AI-Lab. Lệnh chỉ chuẩn bị file và validate Compose, không start/xóa container.

Các container lab cũ dùng trùng tên và dải172.20.0.0/24. KHÔNG chạy `up` trên cùng Docker daemon khi container cũ còn giữ tên/network. Để dựng thử an toàn, dùng máy/Docker context sạch. Không xóa container/volume cũ chỉ để vượt lỗi name conflict. Không chép E:\\DockerData vào bộ nộp. Vị trí DockerData do Docker Desktop của từng máy quản lý.

## Dựng trên máy sạch
1. Docker Desktop Linux containers, Compose v2, Internet và tài nguyên đủ cho Wazuh + AI (khuyến nghị Docker RAM>=8GB, dung lượng trống>=30GB; thực tế phụ thuộc image). Đặt vm.max_map_count>=262144 cho Linux VM theo hướng dẫn Wazuh.
2. Chạy Prepare.ps1 và kiểm tra sáu file model.
3. `docker compose -f generate-indexer-certs.yml run --rm generator` tạo certificate MỚI. Không lấy certificate/key cá nhân từ máy cũ.
4. `docker compose build` tải base images và dependencies. Ubuntu26.04/packages apt và kali-rolling có thể thay đổi theo thời gian; chưa pin toàn bộ transitive dependencies/digest. Đây chưa phải reproducible offline build. DVWA được installer tải về từ upstream, cần kiểm thử lại phiên bản thực tế.
5. `docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard ubuntu-endpoint kali-attacker`
6. `docker compose --profile setup run --rm bootstrap` cài DVWA/rules/observer và chạy Doctor. Chỉ tiếp tục nếu exit0 và BOOTSTRAP_VERIFIED.
7. Import dashboards/soc-ai-attack-chain-unified.ndjson vào Wazuh Saved objects với Overwrite, mở https://localhost. Chưa tự động import trong candidate1.
8. `docker compose --profile ai run --rm ai` bật monitor foreground. Ctrl+C kết thúc, đợi session đóng. Mở Kali Bash khi cần từ terminal riêng; không nhập session ID. Tài liệu này không cung cấp payload hoặc lệnh tấn công.

## Giới hạn phải biết
AI controller dùng Docker CLI + bind Docker socket để tương thích collector/installers hiện có. Điều này cấp quyền quản lý Docker daemon cho controller; socket:ro không giới hạn Docker API. Chỉ chạy controller nguồn tin cậy của lab, không dùng kiến trúc này làm sandbox đa người dùng. Chuyển sang shared-volume collector không có socket là công việc tách riêng, chưa thực hiện trong candidate1.

Endpoint entrypoint khởi động agent, rsyslog, SSH và Suricata; web/observer được bootstrap cài. Sau restart endpoint phải chạy bootstrap lại và Doctor, không giả định observer luôn sống. Restart có thể mất heartbeat/rules hotreload; cần kiểm tra thực tế.

VT là tùy chọn, chưa bật tự động: cấu hình key riêng sau khi nghiệm thu core; không dùng lại key cá nhân trong bundle. Chưa xuất index lịch sử, DB DVWA cũ, account registry Wazuh cũ hoặc lịch sử dashboard. Đây là dựng môi trường sạch, không phải backup chính xác toàn bộ lab cũ.

## Điều kiện nghiệm thu
Model golden verify pass; agent active; Suricata SID collection thực sự thấy packet; web/observer Doctor pass; smoke event vào Wazuh; dashboard nhận stage/summary đúng phiên; correlation6bước không dừng do6000bytes; idle95s tách episode; Ctrl+C lưu session; restart test; không lộ VT key. Các mục này chưa được candidate1 thực hiện end-to-end.
''')
write(root/'Tai-Lieu/KIEM-TRA-DONG-GOI.json',json.dumps({'compose_config_validated':True,'bash_syntax_checked':True,'python_compile_checked':True,'powershell_syntax_checked':True,'archive_sha256_manifest_checked':True,'docker_images_built':False,'clean_machine_end_to_end_verified':False,'model_supplied_locally_and_not_in_archive':True},indent=2))
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
write(root/'PACKAGE-MANIFEST.json',json.dumps({'status':'candidate-not-end-to-end-verified','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'model_in_archive':False,'files_sha256':manifest},indent=2))
out=R/'downloads/SOC-AI-Submission-Kit-Candidate1-20261021.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(root.rglob('*')):
  if p.is_file():z.write(p,str(p.relative_to(root)))
assert zipfile.ZipFile(out).testzip() is None
h=hashlib.sha256(out.read_bytes()).hexdigest();out.with_suffix('.zip.sha256').write_text(h+'  '+out.name+'\n');print(out,out.stat().st_size,h)
