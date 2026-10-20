# Lab A 0.4.8 — scan-rooted attack chain và một dashboard duy nhất

Cập nhật trực tiếp từ bản 0.4.6 đã có Doctor fix. **Không cần cài bản 0.4.7 trước
hoặc train lại.** Gói giữ model/threshold hiện tại và cấu hình nguồn thu của bạn.

## Hành vi mới

```text
                            ┌─ Auth failures / password guessing → success → probe (nếu có log)
Nmap / distinct-port scan ──┼─ HTTP pressure → nghi vấn DoS khi có baseline + degradation
                            └─ SQLi attempt (chưa chứng minh khai thác thành công)
```

Một Chain ID giữ từ root scan, bổ sung các nhánh khi có bằng chứng. Chọn root
cùng nguồn, **đúng IP đích và hostname**, sau root trong 600 giây; toàn chuỗi
bị chặn trong 900 giây tính từ anchor. Auth vẫn ghép theo account; probe chỉ
nối đúng phiên SSH/token theo cơ chế 0.4.6. Khác nguồn, đích hoặc ngoài cửa sổ
không được nối vào root này. Nhiều nhánh cùng IP/thời gian là **giả thuyết liên
quan**, không tự chứng minh cùng hacker hoặc brute force gây ra SQLi/DoS.

Recon thường hữu ích nhưng có thể nằm ngoài khả năng quan sát. Khi không thấy
scan, các hành vi đủ bằng chứng vẫn có case/chain độc lập, ghi
`recon_observed=false`; không bỏ sót chỉ vì thiếu bước scan.

Nếu có 7 password failures rồi SSH reset: chain giữ rõ một bước
`observed_auth_failures` làm ngữ cảnh; **chưa gán password guessing** và không
cộng bonus/diversity chỉ từ các failure rời. Khi đủ 8 failures/60 giây mới nâng
thành `repeated_auth_failures`. Không thay PAM/SSH/lockout để ép test qua.

## HTTP pressure và nghi vấn DoS

Nguồn chính: Apache TSV trên endpoint, có thời gian, IP/port, status và duration.
Chỉ đếm request server duy nhất; không cộng thêm bản sao EVE/Wazuh.

- Ngưỡng nghiên cứu mặc định: **60 request trong 10 giây** theo cùng nguồn,
  host/IP/service và origin log.
- Chỉ rate cao: `http_request_pressure`, **không gán DoS/ATT&CK chỉ từ volume**.
- `possible_http_dos` cần thêm baseline trước burst trong 120 giây: ít nhất
  10 request, trên 90% là 2xx và dưới ngưỡng chậm. Sau đó burst có ít nhất 20%
  và ít nhất 5 request trả 5xx hoặc duration ≥1 giây.
- Đây là **nghi vấn suy giảm liên quan tải**, ứng viên T1499; chưa chứng minh
  nguyên nhân, outage, ý đồ độc hại hoặc DDoS. Lỗi ứng dụng cũng có thể tạo
  cùng triệu chứng. Chưa có detector SYN flood/UDP flood/DDoS phân tán.

Baseline IDs đầy đủ được giữ trong case local; baseline là bằng chứng hỗ trợ riêng,
không cộng vào chain_evidence_count của burst/attack. Một số request ngoài cửa sổ
qualify vẫn nằm trong raw log, không tự trở thành bằng chứng của cửa sổ đó.
Ngưỡng là chính sách lab thử nghiệm, chưa được hiệu chỉnh bằng bộ đánh giá có
nhãn độc lập. MLP không tự tạo bằng chứng auth, SQLi hoặc DoS.

## Phân loại và điểm

`categories`: reconnaissance, credential_access, execution, transfer,
web_exploitation_attempt, availability_pressure, availability_degradation.
Auth context dưới điều kiện burst dùng authentication_observation.

Policy `soc-operational-risk/0.2`:

| Hành vi mạnh nhất đã quan sát | Base score |
|---|---:|
| Scan | 40 |
| HTTP pressure | 45 |
| SQLi attempt | 60 |
| Password guessing | 65 |
| HTTP pressure + degradation + healthy baseline | 75 |
| Success sau password guessing / probe liên kết | 85 |

Điểm = `min(95, max(base hành vi) + recon bonus + diversity bonus)`.
Recon bonus 10 khi có scan trước hành vi đủ điều kiện. Diversity bonus tối đa
5 khi có ít nhất hai nhóm độc lập: auth (kể cả probe của cùng nhánh), web SQLi,
availability. Không cộng điểm theo số alert, số tài khoản hay số bản sao.
Auth context riêng không tăng hai bonus. Medium 40–69, High ≥70.

Ví dụ: scan+guessing 75; scan+pressure 55; scan+SQLi 70;
scan+guessing+pressure+SQLi 80; có degradation thay pressure trong ca đó 90.
Đây là **ưu tiên điều tra**, không phải xác suất model hoặc công thức MITRE.

## Cài cập nhật

Dừng cửa sổ Live bằng Ctrl+C và đợi LIVE_DONE. Tải gói vá tích lũy
`SOC-AI-Lab-A-v0.4.8-Unified-Chains-20261020.zip` rồi giải nén trực tiếp vào:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research
```

Gói vá không chứa `live-config.json`, model, dataset, venv hoặc credentials.
Không tạo thêm thư mục con trùng tên. Sau giải nén:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'

& $py -m unittest -v test_lab_campaign test_chain_unified test_wazuh_realtime
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra source chưa đạt; giữ output.' }

& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài bridge rules chưa đạt; chưa mở Live.' }

& $py .\setup_attack_chains.py
if ($LASTEXITCODE -ne 0) { throw 'Bật chain chưa đạt; giữ output.' }
```

`setup_wazuh.py` kiểm tra collision, backup config/rules và chạy logtest trước
khi **tự restart manager**. Không cần restart thêm. Thêm 119212 (chain medium),
119213 (stage evidence), 119214 (chain high); giữ các rule cũ và input bridge.
`setup_attack_chains.py` backup live-config rồi bật detector, giữ nguồn endpoint
và context đã cài. Doctor chặn Live nếu marker bridge còn thiếu các rule mới.

## Import đúng một dashboard

**Dashboards Management → Saved objects → Import** file:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson
```

Bật **Automatically overwrite conflicts**. File chứa **5 objects và đúng 1
Dashboard**: **SOC Lab A - Attack Chain**. Không import lại các file 0.4.5/
0.4.6/0.4.7 cũ trong gói source. Sau import Ctrl+F5.

Trong cùng dashboard có danh sách active chains, hồ sơ từng nhánh, gợi ý điều
tra tiếp và lịch sử summary/stage. Bấm Chain ID để lọc đúng **Chain ID + Session
ID** ngay trong dashboard. Pause auto refresh khi đọc dài; bật lại để theo dõi
attack. Mặc định refresh 2 giây; không bảo đảm end-to-end latency 2 giây vì còn
thu log, hàng đợi, manager, Filebeat và indexer. Các event thường/model/sensor
vẫn xem trong **Threat Hunting** có sẵn, không bị xóa hoặc tắt publication.

Hồ sơ chỉ ghép stage cùng `chain_revision_id`. Nếu đang thiếu stage document,
hiện số đã nhận/tổng và yêu cầu Refresh, không dùng revision cũ lấp chỗ thiếu.
Raw graph/baseline/evidence IDs đầy đủ nằm trong `chains` ở
`correlation-cases.json`; tra `correlation-events.jsonl` để lấy `source_refs`
và đối chiếu byte offset/hash của log gốc. Wazuh giữ mẫu evidence IDs để từng
message dưới 6000 byte. Late recon có thể thay case độc lập bằng case có root:
case cũ được đánh dấu superseded; danh sách chọn latest **rồi** lọc active để
không hồi sinh revision cũ.

## Dọn các dashboard Lab A cũ, giữ một dashboard attack chain

Chỉ làm sau khi import và mở được dashboard mới. Cách tự động dưới đây backup
các **Dashboard records** cũ trước khi xóa; giữ visualization/index pattern
cũ, index, alert, Wazuh native dashboards và toàn bộ model/log.

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$url = Read-Host 'URL Wazuh Dashboard, ví dụ https://localhost hoặc https://localhost:PORT'
& $py .\manage_chain_dashboards.py --url $url --insecure --apply
if ($LASTEXITCODE -ne 0) { throw 'Dọn dashboard chưa hoàn tất; giữ output/backup.' }
```

Nhập password Wazuh **tại prompt local**, không đưa vào chat/câu lệnh. Flag
`--insecure` phục vụ HTTPS self-signed trong lab; bỏ flag khi certificate được
máy tin cậy. User mặc định admin, dùng `--username` nếu khác. Bỏ `--apply` chỉ
xem danh sách dự kiến. Backup NDJSON ở `dashboard-backups`, có thể import lại.

Tên cũ được dọn: Attack Chain & Scoring, Chain Investigation, Điều tra Chain,
Hồ sơ Chain với tiền tố SOC Lab A. Script kiểm tra dashboard mới tồn tại trước
khi xóa. Có thể làm thủ công: Saved objects → lọc type Dashboard → export các
Dashboard Lab A cũ → xóa đúng các record đó; giữ **SOC Lab A - Attack Chain**.

## Kịch bản kiểm thử

Chỉ chạy trên bridge private của hai container hiện có. Nmap giới hạn 5 probes/s,
34 cổng (1–32,80,443). HTTP load giới hạn 100 request, tối đa 20 lần bắt đầu/s,
4 concurrent, timeout 2 giây, deadline bắt đầu 10 giây; không follow redirect.

| Scenario | Sau Nmap | Kiểm tra chính |
|---|---|---|
| chain-sqli | Một GET chứa SQL syntax indicator vào DVWA | 1 ID, scan + SQLi attempt, thường 70 |
| chain-bruteforce | 8 password attempts cố ý sai cho soctest | Khi đủ raw failures: scan + guessing, 75 |
| chain-dos | 20 GET baseline rồi bounded HTTP load | Pressure thường 55; chỉ nghi DoS nếu đủ degradation |
| chain-mixed | Brute force → baseline/load → SQLi | Một root có các nhánh; thường 80 nếu đủ guessing |

Một HTTP 302 từ DVWA vẫn có thể tạo SQLi-attempt evidence; **không chứng minh
khai thác thành công**. Kịch bản không tự login DVWA, lấy dữ liệu DB hoặc tạo
malware. Apache khỏe có thể trả toàn bộ 200 dưới tải; khi đó kết quả đúng là
HTTP pressure, không ép gán DoS. Chỉ có fixtures kiểm tra nhánh degradation;
không báo đã gây DoS thành công trên máy của bạn.

**PowerShell A — mở phiên Live mới:**

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$caseName = 'chain-mixed-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Wazuh-Live.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' -Case $caseName
```

Đợi READY, giữ A chạy và sao chép SESSION. **PowerShell B:**

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$capture = (Read-Host 'Dán SESSION mới từ cửa sổ A').Trim()
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('chain-mixed-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $py .\chain_scenarios.py --scenario chain-mixed --username soctest --capture $capture --output $evidence
Write-Host ('Runner exit: ' + $LASTEXITCODE)
Write-Host ('Dashboard filter: data.session_id: "' + (Split-Path -Leaf $capture) + '"')
```

Mỗi SESSION chỉ chạy một operator. Không chạy các scenario khác đồng thời.
Nếu SSH reset ở lần thứ tám, runner dừng nhánh auth, giữ error và tiếp tục các
nhánh HTTP độc lập; report **PARTIAL/exit 2**, không coi đó là test đủ brute
force. Chain có thể thấy scan + auth context + pressure + SQLi, khoảng 75,
vẫn giữ cùng ID; không có bước success/command nếu chưa có log.

Xong, Ctrl+C A một lần và đợi LIVE_DONE, rồi tại B:

```powershell
& $py .\chain_trace.py --capture $capture --operator (Join-Path $evidence 'operator.json') `
  --output (Join-Path $evidence 'chain-replay.json')
Write-Host ('Raw verification exit: ' + $LASTEXITCODE)

& $py .\wazuh_trace.py session --capture $capture --operator (Join-Path $evidence 'operator.json') `
  --output (Join-Path $evidence 'wazuh-trace.json')
```

`chain_trace` đọc lại raw logs, kiểm tra hash đã có và rebuild bằng cùng
normalizer/detector; cần đúng một chain chứa các stage yêu cầu, khớp snapshot,
operator complete và capture completed để checks_passed. Nó không thay thế
kiểm tra manager/indexer/dashboard. Giữ operator, replay report, manager trace,
raw logs, correlation-events/cases và ảnh dashboard. Case PARTIAL vẫn phải giữ
là partial dù vài nhánh phát hiện và hiển thị thành công.

## Kết quả kiểm tra trước khi đóng gói

Xem [biên bản validation](validation-048.json). Bộ source chạy 398 test, không
có failure; 2 test filesystem riêng cho Windows được skip trên Linux. Đã kiểm
tra native OpenSearch Dashboards 2.19.3: import/lặp import đúng 5 objects,
bấm Chain ID áp filter chain + session, refresh 1 → 2 → 4 stage giữ nguyên ID,
không trộn revision khi stage chưa tới, loại latest inactive và nút quay lại
xóa filter đúng. 30 response truy vấn qua 6 shard cũ/mới không có failed shard.

Native Wazuh 4.14.7 `wazuh-logtest-legacy` match đúng 14 leaf rules, gồm các
stage documents và summary high thực tế do serializer tạo. Bộ cài trên máy
bạn vẫn chạy `wazuh-logtest` trước khi restart manager. HTTP test private gửi
đủ 100 request/4,985 giây, server khỏe trả 100 mã 200; không chứng minh DoS.
Đã kiểm tra backup/idempotence của config installer và backup trước khi dọn
Dashboard qua native API, giữ dashboard native và visualization dùng chung.

Các kiểm tra này không thay thế E2E trên máy Windows của bạn. Sau cài nên chạy
**chain-sqli trước** để kiểm tra 1 ID/2 stage/70 điểm, rồi chain-dos và cuối cùng
chain-mixed. SSH reset trong bài trước cần giữ là nhánh partial; không coi vài
alert xuất hiện là bằng chứng toàn bộ kịch bản đã thành công.

## Nguồn và phạm vi

- [MITRE CTID Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow):
  biểu diễn chuỗi/nhánh hành động; graph nội bộ chưa phải STIX/Attack Flow exporter.
- [T1046](https://attack.mitre.org/techniques/T1046/),
  [T1110.001](https://attack.mitre.org/techniques/T1110/001/),
  [T1499](https://attack.mitre.org/techniques/T1499/): đối chiếu kỹ thuật với bằng
  chứng, không dùng để tự sinh bước tiếp theo hoặc công thức điểm.
- [Wazuh ATT&CK](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html):
  custom data.techniques không tự thành rule.mitre. SQLi giữ unmapped khi chưa
  đủ bối cảnh public-facing/exploitation; volume riêng không gán technique.

Model và operating threshold không đổi. Bản này cải thiện cấu trúc correlation,
khả năng truy vết và cách điều tra; chưa phải bằng chứng model có accuracy/recall
cao hơn hoặc detector đã được kiểm định với ground truth trên production.
