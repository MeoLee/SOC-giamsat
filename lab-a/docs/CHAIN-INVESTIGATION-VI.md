# Lab A 0.4.6: chi tiết chain và kịch bản năm bước trên Wazuh

**Cập nhật giao diện 0.4.7:** [Hồ sơ Chain mở khi bấm Chain ID](CHAIN-PROFILE-VI.md).
File NDJSON hiện hành có 9 objects thay cho 7; chỉ import file đầy đủ một lần.
Các hướng dẫn hai hành động probe và kịch bản dưới đây vẫn áp dụng.

Nếu Doctor từ chối log probe mới tạo còn rỗng, áp dụng
[Doctor empty-log hotfix](DOCTOR-EMPTY-LOG-FIX-VI.md) rồi mở Live lại.

Nếu đã import bản đầu và gặp `No mapping found for [data.event_time]`, xem
[bản sửa tương thích index cũ](CHAIN-SHARD-FIX-VI.md). Bản ZIP có đuôi
`Shard-Fix` và NDJSON hiện hành đã chứa sửa này; dashboard đã cài chỉ cần import
file repair gồm hai visualization theo hướng dẫn sửa shard.

Ảnh dashboard thật đã nhận đúng chain quét cổng, medium/40/T1046/1 stage.
Ảnh Lab B có nhiều stage vì các case trong đó chứa nhiều hành vi; thêm cột
không tự biến một ca quét cổng thành một chuỗi thực thi lệnh hoặc tải file.

Bản này bổ sung **SOC Lab A - Chain Investigation**, một dashboard riêng trong
Wazuh, và kịch bản `chain-extended` gồm năm bước có bằng chứng:

```text
Quét cổng → sai mật khẩu nhiều lần → đăng nhập đúng → lệnh shell → tải file mẫu
 T1046          T1110.001              T1078          T1059.004      T1105
```

Các ID là ứng viên ATT&CK, không phải khẳng định hành vi độc hại. Đây là một bài
tập có kiểm soát, không phải full kill chain và không xác nhận bị chiếm quyền.
Không có stage C2: một HTTP GET hoặc việc có file mới không đủ bằng chứng C2.

## Dashboard hiển thị những gì

Import file `dashboards/soc-ai-chain-investigation.ndjson`: 7 Saved objects có
ID riêng, không ghi đè 5 object của dashboard 0.4.5 mà bạn đang chỉnh sửa.
Gồm các panel:

1. Chính sách điểm và cách đọc bằng chứng.
2. **Attack Chain Detail - latest revision**: Chain ID, risk, techniques, chuỗi
   hành vi, kết luận, số stage và lần cập nhật.
3. **Chain context and score breakdown - latest revision**: IP nguồn/đích,
   host, user, thời điểm đầu/cuối, thời lượng, số evidence event duy nhất, số
   password failures, điểm nền và bonus recon.
4. **Chain evidence - expand a revision for full text**: nội dung từng bước và
   đường dẫn hồ sơ bằng chứng. Bấm mũi tên bên trái dòng để mở Table/JSON.
5. Lịch sử các lần chuyển trạng thái; các dòng là revision, không phải số vụ.

Để đọc nội dung dài giống popup ở ảnh Lab B, trong panel **Chain evidence**,
mở mũi tên bên trái dòng rồi tìm:

| Trường | Nội dung |
|---|---|
| `data.chain_stage_details` | Mỗi bước, thời gian, technique, số bằng chứng, ngưỡng phát hiện; lệnh hoặc URL/hash nếu có |
| `data.activity` | Lý do ghép các bằng chứng |
| `data.conclusion`, `data.attack_summary` | Kết luận và phạm vi |
| `data.attack_chain_json` | Graph tóm tắt dạng JSON string |
| `data.evidence_file` | Đường dẫn `correlation-cases.json` trên Windows, giữ đầy đủ stage/evidence links |
| `data.endpoint_evidence_scope` | `controlled_lab_probe_only` nếu có hai bước probe |

Lọc một `data.chain_id` để điều tra. Có thể tạm pause auto refresh khi đọc dòng
đã mở. Time picker vẫn lọc theo `timestamp` Wazuh. Hai bảng tóm tắt lấy revision
mới nhất theo `data.event_time`: UTC chuẩn hóa, giữ microsecond. Điều này tránh
chọn nhầm revision khi nhiều cập nhật chung một millisecond của `timestamp`.
Không ép mapping, cộng hoặc lấy trung bình điểm qua các revision.

## Cài bản cập nhật

1. Dừng Live, sao lưu thư mục source hiện tại. Nếu đang chỉnh dashboard 0.4.5
   như ảnh, bấm **Save** để giữ bố cục bạn muốn.
2. Giải nén bản vá `SOC-AI-Lab-A-v0.4.6-Chain-Investigation-Shard-Fix-20261020.zip`, chép
   nội dung trực tiếp vào `E:\SOC-Lab\AI\SOC-AI-v0.4-research` và ghi đè.
   Bản vá không chứa `live-config.json`, weights, dataset hoặc venv.
3. Kiểm tra source:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_lab_endpoint test_chain_dashboard test_wazuh_realtime test_lab_correlation test_lab_recon test_recon_diagnostic test_wazuh_scenarios
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra source chưa đạt; giữ output.' }
```

4. Trong Wazuh, **Dashboards Management → Saved objects → Import**:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-chain-investigation.ndjson
```

5. Import 7 objects, mở **Dashboards → SOC Lab A - Chain Investigation**.
   Có thể import lại cùng 7 ID nếu cần; dashboard cũ vẫn giữ nguyên.

Event 0.4.5 có thể thiếu các chi tiết mới. Mở một phiên Live mới sau cập nhật.
Không cần train lại, restart Wazuh hay thay XML bridge rule.

## Bật ghi nhận hai hành động trên endpoint, chỉ cần cài một lần

Hai bước mới dùng helper root-owned thực hiện đúng hai hành động cố định dưới
tài khoản SSH không phải root: `/bin/sh -c "id; uname -s"` và `curl` tải một
file mẫu 33 byte từ Kali. Không thực thi lệnh tùy ý do người dùng nhập, không
tải malware, không đổi SSH/PAM/lockout policy hoặc cài dịch vụ nền thường trực.

Máy Ubuntu cần có user `soctest`, Python 3.8+ và curl; Kali cần Python 3.8+,
nmap và sshpass hiện có. Lệnh kiểm tra trước và cài:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
docker exec ubuntu-endpoint id soctest
if ($LASTEXITCODE -ne 0) { throw 'Chưa có tài khoản lab soctest.' }
& $py .\setup_chain_telemetry.py --username soctest
if ($LASTEXITCODE -ne 0) { throw 'Cài probe chưa đạt; giữ thông báo lỗi.' }
```

Bộ cài thêm helper vào `/usr/local/lib/soc-lab` của hai container, tạo
`/var/log/soc-lab/endpoint-probe.jsonl` ở Ubuntu và thêm source `endpoint` vào
`live-config.json`. Config gốc có backup `live-config.json.before-chain-probe-*`.
Không xóa/truncate log có sẵn. Cài lại cùng phiên bản được hỗ trợ; helper bị
sửa thủ công hoặc đường dẫn xung đột sẽ được giữ lại và báo lỗi để kiểm tra.

**Giới hạn thu thập:** log này ghi hai hành động của helper trong bài tập.
User lab có quyền ghi log của chính mình; đây không phải audit agent chống sửa
log và không giám sát mọi lệnh hay mọi file transfer. SSH auth vẫn lấy từ log
server độc lập. Muốn giám sát hành vi bất kỳ ngoài helper cần bổ sung auditd/
eBPF/process telemetry phù hợp với host, không suy từ SSH mã hóa hoặc rule level.

## Chạy kịch bản năm bước

Chỉ chạy trong hai container lab hiện có. Không chạy kịch bản khác đồng thời.

**PowerShell A — Live:**

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$caseName = 'chain-five-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Wazuh-Live.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -Case $caseName
```

Đợi READY, sao chép SESSION mới, giữ A chạy. Nếu chưa cài source endpoint,
runner sẽ dừng trước kịch bản và yêu cầu cài rồi mở Live mới.

**PowerShell B — runner:**

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$capture = (Read-Host 'Dán SESSION mới từ cửa sổ A, không thêm ngoặc kép').Trim()
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('chain-five-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
Write-Host ('Dashboard filter: data.session_id: "' + (Split-Path -Leaf $capture) + '"')
& $py .\wazuh_scenarios.py run --scenario chain-extended --username soctest --capture $capture --output $evidence
if ($LASTEXITCODE -ne 0) { throw 'Chain chưa hoàn tất; giữ operator.json và lỗi chi tiết.' }
```

Nhập mật khẩu **đúng** của soctest khi SSH prompt cuối yêu cầu. Không đưa mật
khẩu vào chat hoặc câu lệnh. Runner quét 1–32, thử tám mật khẩu cố ý sai, rồi
dùng một phiên SSH đúng để thực hiện cả hai probe. HTTP server chỉ bind địa chỉ
private của Kali, phục vụ một token/file cố định cho Ubuntu, tự kết thúc sau
lượt tải hoặc 120 giây; runner dọn tiến trình của lượt thử nếu bị lỗi.

Trên dashboard chọn Last 15 minutes, auto refresh 1 giây, dán filter in ở B.
Kết quả mong đợi:

| Trạng thái/bằng chứng | Rule | Stage | Điểm |
|---|---|---:|---:|
| Quét nhiều cổng | 119203 | 1 | 40 |
| Sai mật khẩu đủ ngưỡng, có scan trước đó | 119204 | 2 | 75 |
| Đăng nhập sau chuỗi sai | 119205 | 3 | 95 |
| Có shell probe cùng kết nối SSH | 119205 | 4 | 95 |
| Có file probe đúng bytes/hash và cùng token | 119205 | 5 | 95 |

Auth và shell có thể được Live nhận trong cùng một poll, nên không bắt buộc có
đủ mọi revision trung gian. Case theo tài khoản giữ cùng Chain ID khi lên 5
stage. Recon độc lập trước đó có thể còn một dòng khác; số dòng không phải số
cuộc tấn công đã xác nhận. Kỹ thuật cuối là
`T1046;T1110.001;T1078;T1059.004;T1105`. Không xuất T1071/C2 chỉ vì đã tải HTTP.

Liên kết endpoint bắt buộc cùng IP nguồn/đích, hostname asset, user và cổng
nguồn của phiên SSH đã auth success; action phải sau success trong 300 giây.
Transfer cần có shell trước đó, cùng probe ID, curl thành công và file nhận có
đúng bytes/SHA256. Nguồn thu đến lệch thứ tự vẫn được ghép theo event time.
Tải lỗi, hash sai, user/port khác hoặc quá hạn không hoàn tất bước.

**Nếu gặp lại `Connection reset by peer` hoặc lỗi Nmap:** giữ operator.json,
dừng ca; đó không phải password rejection hoặc bằng chứng đủ tám failures.
Bản này không thay PAM hay tắt bảo vệ SSH để ép test qua. Đọc cấu hình hiệu lực
bằng `docker exec ubuntu-endpoint sshd -T` và xem bước cuối trong operator.json
trước khi xử lý chính sách. Dashboard vẫn kiểm tra được bằng ca port-scan.

## Đóng ca và đối chiếu

Ctrl+C một lần ở A, đợi LIVE_DONE. Tại B:

```powershell
& $py .\wazuh_trace.py session --capture $capture `
  --operator (Join-Path $evidence 'operator.json') `
  --output (Join-Path $evidence 'wazuh-trace.json')
if ($LASTEXITCODE -ne 0) { throw 'Chưa xác nhận đủ chain; giữ report để kiểm tra.' }
```

Cần `capture_closed=true`, không thiếu rule, auth raw ≥8 password failures/60s
và success đúng cửa sổ; `endpoint_outcomes.five_stage_chain_verified=true`.
Trace đọc lại raw probe, kiểm tra liên kết auth/case và bằng chứng HTTP server
trong operator.json. `general_endpoint_audit_coverage=false` là giới hạn đúng
của bài tập, không phải lỗi. Manager/indexer/dashboard vẫn cần đối chiếu riêng.

Các file cần giữ: `session.json`, `operator.json`, `wazuh-trace.json`,
`ubuntu-auth.log`, `endpoint-probe.jsonl`, `correlation-events.jsonl`,
`correlation-cases.json` và ảnh dashboard. Full graph/evidence links ở file case
local; graph gửi Wazuh cho >3 stage bỏ danh sách evidence ID trong từng node
để giữ message dưới 6000 byte, ghi rõ `graph_evidence_ids_omitted=true`.

## Điểm được lấy từ đâu

`soc-operational-risk/0.1` là chính sách ưu tiên điều tra của Lab A, không phải
công thức MITRE, CVSS, xác suất model hoặc điểm đã hiệu chỉnh theo ground truth:
scan 40; guessing 65; success sau guessing 85; thêm 10 nếu có recon trước; chặn
95. Medium từ 40, High từ 70. Hai probe cung cấp thêm bằng chứng; giữ cap 95,
không tự cộng điểm chỉ để giống các số thập phân trong ảnh Lab B. Model, weights,
threshold và các rule 119203/119204/119205 được giữ nguyên.

## Nguồn tham khảo và phần áp dụng

Đối chiếu ngày 20/10/2026 bằng các repository chính thức dưới đây. Các trang
website trực tiếp bị proxy môi trường cloud chặn; nội dung kỹ thuật đã đọc từ
MITRE STIX, README Attack Flow và source tài liệu Wazuh trên GitHub.

1. **MITRE CTID — Attack Flow**: [README và repository chính thức](https://github.com/center-for-threat-informed-defense/attack-flow),
   [tài liệu](https://center-for-threat-informed-defense.github.io/attack-flow/).
   Attack Flow mô tả cách các kỹ thuật được kết hợp, sắp xếp để đạt mục tiêu;
   đây là nguồn tham khảo trực tiếp cho việc mô tả chuỗi/quan hệ hành động.
   Graph Lab A là định dạng nội bộ, chưa phải exporter STIX/Attack Flow tương thích.
2. **MITRE ATT&CK Enterprise**: [dữ liệu STIX chính thức](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack).
   Dùng để đối chiếu tên, phạm vi technique; không coi thứ tự các cột tactic
   là một chuỗi bắt buộc phải đi qua đủ bước.
   - [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/):
     khám phá dịch vụ/port trên host khác trong mạng lab.
   - [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/):
     reconnaissance trong quá trình nhắm mục tiêu; cần xét bối cảnh thay vì
     gán mọi port scan cùng một ID chỉ vì ảnh Lab B dùng ID đó.
   - [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/):
     đối chiếu chuỗi password failures.
   - [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/):
     ứng viên khi có success sau guessing; một login đúng không tự chứng minh
     account bị đánh cắp hoặc mục đích độc hại.
   - [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/):
     cần bản ghi shell execution, không suy từ auth success.
   - [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/):
     dùng làm ứng viên trong bài tập transfer có kiểm soát; file mẫu là vô hại,
     việc file được tải không tự chứng minh đã tải công cụ tấn công.
   - [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/):
     nói về C2 qua web; bài tập GET file này không tạo stage C2.
3. **Wazuh — MITRE ATT&CK framework**:
   [tài liệu](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html),
   [source đã đối chiếu](https://github.com/wazuh/wazuh-documentation/blob/master/source/user-manual/ruleset/mitre.rst).
   Tham khảo mapping alert và drill-down bằng chứng. Bảng custom của Lab A dùng
   `data.techniques`; việc hiển thị ở đây không tự thêm mapping native `rule.mitre`
   hoặc tự đưa các ID vào module ATT&CK mặc định của Wazuh.

Bundle Enterprise STIX dùng khi đối chiếu có SHA256
`81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`.
Tham khảo khung các pha ở mức tổng quát:
[Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html).
Không gọi chuỗi năm quan sát trong lab này là đã hoàn tất bảy pha của khung đó.

## Kiểm chứng bản phát hành

Kiểm tra logic bao gồm không ghép khác user/IP/target/SSH port/token, không
chấp nhận action lỗi/hash sai, không ghép transfer thiếu shell hoặc thiếu auth,
replay đảo thứ tự và giữ một Chain ID qua các revision. Helper đã thực thi shell
và truyền file thật giữa hai container test; hash được đối chiếu ở hai phía.
Trong phép thử helper đó, SSH_CONNECTION được cấp làm fixture để cô lập hành
động; không coi nó là xác minh một phiên SSH thật trên Windows của người dùng.

Saved objects được import/reimport và mở bằng trình duyệt trên OpenSearch
Dashboards 2.19.3 trong container test cô lập, dùng mapping custom keyword như
Wazuh. Đã kiểm tra auto refresh 75 → 95/5 stage, mở full evidence row và không
ghi đè dashboard cũ. Fixture cố ý cho các revision 3/4/5 cùng millisecond để
kiểm tra việc chọn đúng bằng chứng cuối. Không có lỗi JavaScript của trang.
81 kiểm tra liên quan đạt; bộ đầy đủ 380 kiểm tra, 378 đạt và 2 kiểm tra
Windows được bỏ qua trên Linux. Gói không tự kết nối hoặc triển khai vào máy
Windows của người dùng.
