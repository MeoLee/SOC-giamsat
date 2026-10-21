# 0.4.9.1 — Sửa bộ cài Wazuh, tiếp tục monitor và test chain thủ công

## Lỗi trong output bạn gửi

Docker hoạt động và 22 source tests đều đạt. Bộ cài dừng ở `setup_wazuh.py`:
`Wazuh-logtest error when connecting with wazuh-analysisd`, sau đó báo không
khớp đủ 14 rule. Thông báo này chứng minh logtest không kết nối được analysisd;
chưa chứng minh rule XML sai hoặc model lỗi. Bộ cài đã khôi phục cấu hình cũ.
Do PowerShell dừng ngay, `setup_attack_chains.py` và `Install-Kali-Tools.ps1`
phía sau chưa chạy trong lần này.

`wazuh-logtest` hiện đại là client kết nối tới analysisd đang chạy. Bộ cài cũ
gọi nó trước restart: có thể không kết nối được, hoặc kiểm tra rule cũ trong
bộ nhớ thay vì rule mới trên đĩa.

Bản vá áp dụng cho cả `setup_wazuh.py` và `setup_scenario_rules.py`:

1. Giữ collision checks, backup riêng và kiểm tra cấu hình `-t`.
2. Nếu có `wazuh-logtest-legacy`, kiểm tra chính các file rule mới offline.
3. Restart rồi đợi `wazuh-db`, `wazuh-analysisd`, `wazuh-logcollector` chạy.
4. Nếu chỉ có logtest hiện đại, kiểm tra fixture **sau restart**; chỉ retry lỗi
   kết nối lúc khởi động, tối đa 3 lần. Rule khớp sai vẫn bị từ chối.
5. Chỉ ghi marker thành công sau validation/readiness; khi lỗi, restore và thử
   restart cấu hình cũ. Nếu rollback restart cũng lỗi, in riêng lỗi đó và giữ
   nguyên nguyên nhân ban đầu. Không tự bật `rule_test` hay bỏ kiểm tra.

Readiness/fixture chưa xác nhận toàn bộ đường Wazuh Indexer/Dashboard.

## 1. Tải và giải nén bản vá

Dành cho máy **đã giải nén 0.4.9** như output của bạn. Dừng monitor cũ bằng
Ctrl+C nếu đang chạy. PowerShell Windows:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-Installer-Fix-0491.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.9.1-Installer-Fix-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
foreach ($file in @('wazuh_install_checks.py', 'setup_wazuh.py', 'Start-SOC-Monitor.ps1', 'Install-Kali-Tools.ps1')) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Thiếu $file. Kiểm tra đã giải nén bản 0.4.9 đúng thư mục gốc."
    }
}
& $py -m unittest -v test_wazuh_install_checks
if ($LASTEXITCODE -ne 0) { throw 'Test bộ cài chưa đạt; giữ output.' }
```

ZIP vá có cấu trúc phẳng: giải nén trực tiếp vào project, không vào thư mục
con. Không chứa model/dataset/live-config. [Full source 0.4.9.1](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9.1-Research-20261021.zip)
có thư mục ngoài `SOC-AI-v0.4-research/`; dùng nếu cần cài source đầy đủ.

## 2. Chạy lại các bước bị ngắt

Vẫn trong PowerShell trên:

```powershell
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Bridge chưa đạt; giữ output, chưa bật monitor.' }
& $py .\setup_attack_chains.py
if ($LASTEXITCODE -ne 0) { throw 'Cấu hình chain chưa đạt.' }
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Kali-Tools.ps1
if ($LASTEXITCODE -ne 0) { throw 'Helper Kali chưa cài xong.' }
```

Kỳ vọng có `WAZUH_CORE_READY` rồi `WAZUH_BRIDGE_INSTALLED`. Không restart thêm
bằng tay. Nếu vẫn lỗi, giữ toàn bộ output và chạy hai lệnh chỉ đọc:

```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
docker exec single-node-wazuh.manager-1 tail -n 80 /var/ossec/logs/ossec.log
```

Chưa chạy scenario khi bộ cài còn lỗi. Nếu Doctor sau này báo source
`endpoint-probe.jsonl` không phải file thường, dùng bước cài probe ở
[phần chuẩn bị](scenarios-049/00-PREPARE-VI.md), không tắt kiểm tra source.

Với bài FIM/firewall, dùng bộ cài scenario đã vá ở bước tùy chọn trong tài liệu
chuẩn bị. Không cần cài FIM hoặc probe để tạo SQLi telemetry; các source đã
khai báo trong live-config vẫn phải tồn tại và đọc được.

## 3. Dashboard và cách vận hành bạn yêu cầu

Các tính năng này có từ 0.4.9; bản 0.4.9.1 sửa installer. Nếu chưa import
0.4.9, vào Saved objects → Import → overwrite và chọn đúng:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson
```

Đúng 5 objects, một dashboard **SOC Lab A - Attack Chain**. Nếu đã import
0.4.9 thành công thì không cần import lại vì bản vá không đổi dashboard.
Event khác vẫn xem ở Threat Hunting có sẵn của Wazuh.

Bật monitor **một lần** ở PowerShell A, chờ `READY`:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1
```

Script tự tạo thư mục trong `E:\SOC-Lab\AI\monitor-sessions`. Ở PowerShell B:

```powershell
docker exec -it kali-attacker bash
```

Từ đây gõ từng lệnh Bash, không nhập SESSION hoặc tên scenario:

```bash
export TARGET=172.20.0.3
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Quan sát một chain quét cổng, rồi trong vòng 90 giây tiếp tục:

```bash
curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit"
```

Kỳ vọng khi đủ raw evidence: **Quét cổng → Dấu hiệu thử SQL injection**,
2 observed stages, cùng chain, risk 70. Bấm Chain ID để lọc chain + capture
session, xem sơ đồ mũi tên và bằng chứng các bước. HTTP 302/200 chưa chứng minh
khai thác thành công. Sau 95 giây không tạo hành vi liên quan, xem status
`quiescent` và ô vàng/mũi tên nét đứt của hướng có thể xảy ra tiếp theo.

Các gợi ý là runbook có điều kiện, chưa phải dự đoán xác suất đã train/kiểm
định. Chúng không được cộng vào observed stages hay risk. Scan không phải
điều kiện bắt buộc để phát hiện tấn công: kẻ tấn công có thể biết sẵn mục tiêu.
Giám sát có thể chỉ thấy phần giữa của một chuỗi.

Episode phân tách theo source/target/host và thời gian; security evidence
không được tái sử dụng giữa chain. Để thử bài độc lập cùng IP/đích, chờ ≥95
giây sau hành vi cuối rồi bắt đầu Nmap mới. Không thể bảo đảm tách hai tác
nhân cùng IP/đích/thời gian khi thiếu session/process evidence.

[Chuỗi SSH nhiều bước và nhánh HTTP pressure/SQLi](scenarios-049/02-ATTACK-CHAINS-VI.md).
[Đối chiếu và sửa thiết kế rule Wazuh/Suricata](scenarios-049/00-PREPARE-VI.md).
Không đổi weights/threshold, không cần train lại.

## Kiểm chứng và nguồn

- 421 tests: đạt, 2 test chỉ dành cho Windows được skip trong cloud.
- Native C Wazuh 4.14.7: 14 bridge fixtures và firewall 119254 khớp khi **không
  chạy analysisd**; 2 firewall negative controls không khớp 119254.
- Luồng modern retry/readiness/rollback có regression tests mô phỏng. Chưa
  xác nhận restart và live E2E trên Docker Desktop Windows của bạn.
- Chi tiết: [validation 0.4.9.1](validation-0491.json); kiểm chứng dashboard/
  episode/PCAP trước đó giữ trong [validation 0.4.9](scenarios-049/validation.json).

Nguồn chính thức:

- [Wazuh logtest và phiên kiểm tra rule](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
- [Wazuh rule_test configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rule-test.html).
- [Mã Wazuh 4.14.7: modern logtest client](https://github.com/wazuh/wazuh/blob/v4.14.7/framework/scripts/wazuh_logtest.py).
- [MITRE ATT&CK — Network Service Discovery T1046](https://attack.mitre.org/techniques/T1046/).
- [MITRE ATT&CK — Password Guessing T1110.001](https://attack.mitre.org/techniques/T1110/001/).
- [MITRE ATT&CK — Exploit Public-Facing Application T1190](https://attack.mitre.org/techniques/T1190/).
- [MITRE CTID Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/).

ATT&CK/Attack Flow giúp mô tả hành vi và quan hệ; điểm risk và ranh giới episode
là policy của Lab A, không phải công thức chuẩn MITRE hoặc xác suất tấn công.
