# Kiểm thử AI → Wazuh Dashboard theo thời gian thực

Bản cập nhật 0.4.3 không cần train lại. Nó dùng candidate Quality hiện có và bổ
sung vận hành: điểm ưu tiên, bằng chứng sensor gửi sớm, hoạt động bình thường
ở mức thông tin, attack chain theo sự kiện và công cụ trace đường gửi. Capture
còn lỗi vẫn được ghi nhận bằng cảnh báo telemetry; không ép phải sửa offload
trước khi thử đường vận hành, cũng không dùng kết quả đó để chứng nhận accuracy.

## 1. Các nhánh phát hiện và độ trễ

```text
Auth / Suricata alert / Apache → thu log khoảng 1 giây → correlation / evidence
                                               → SQLite outbox → manager JSON
Suricata completed flow → MLP → summary khoảng 1 giây ────────────────┘
manager logcollector → analysisd → alerts.json → Filebeat → indexer → dashboard
```

- Auth failures, auth success, Suricata signatures và SQL indicators không phải
  chờ MLP hoàn tất flow. Chúng là nhánh dùng để quan sát trong lúc tấn công.
- MLP dùng counter của flow hoàn tất, nên có thể đến sau khi kết nối đóng khoảng
  một timeout sensor. Không gọi nhánh này là phát hiện từng packet tức thời.
- Interval 1 giây không bảo đảm tổng độ trễ 1 giây: Docker, log buffering,
  Wazuh, Filebeat, indexer và chu kỳ refresh dashboard đều ảnh hưởng. Đo bằng
  event ID và timestamp thật; không sửa đồng hồ log để làm latency đẹp.
- `risk_score` là ưu tiên heuristic 0–100, khác `score_max` của MLP và khác
  `rule.level` của Wazuh. Không phải xác suất tấn công đã hiệu chuẩn.

## 2. Cài cập nhật source và bridge

Giữ model/data/venv hiện có. Dừng Live cũ, chờ đóng phiên; không mở hai watcher
cùng thu một lab để tránh nhân đôi thông báo. Bản vá source lấy chênh lệch từ
0.4.2, gồm bản dashboard Quality; người đang ở 0.4.1 vẫn phải cài dashboard patch
trước hoặc dùng full 0.4.3. Sao lưu source trước khi giải nén đè.

- [Bản vá Wazuh](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4-Wazuh-Realtime-20261019.zip)
- [SHA256 bản vá](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4-Wazuh-Realtime-20261019.zip.sha256)
- [Full source 0.4.3](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.3-Research-20261019.zip)

Trong **Windows PowerShell trên máy vật lý**:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$manager = 'single-node-wazuh.manager-1'
$model = 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507'
& $py .\setup_wazuh.py --manager $manager
if ($LASTEXITCODE -ne 0) { throw 'Bridge chưa cài được; giữ toàn bộ lỗi.' }
```

Installer thêm JSON localfile và rule riêng, kiểm tra trùng ID, validate config,
chạy `wazuh-logtest` cho 11 loại sự kiện rồi restart **Wazuh Manager**. Có gián
đoạn ngắn trong lần cài này. Backup cấu hình cũ nằm tại `/var/ossec/backup/soc-ai-*`
với quyền riêng tư; khi validation/restart lỗi sẽ cố khôi phục cấu hình trước.
Không ghi đè `local_rules.xml` hoặc rule lab cũ. Thay đổi trong writable layer
của container cần đưa vào volume/Compose nếu sau này tạo lại container.

## 3. Smoke test và xác nhận index/dashboard

```powershell
$probeRoot = Join-Path 'E:\SOC-Lab\AI\wazuh-tests' ('probe-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop | Out-Null
& $py .\wazuh_trace.py smoke --manager $manager --outbox (Join-Path $probeRoot 'outbox.sqlite') --output (Join-Path $probeRoot 'probe.json')
if ($LASTEXITCODE -ne 0) { throw 'Chưa xác nhận alert từ manager; xem probe.json và console.' }
```

Cần `appended_to_manager:true` và `manager_alert_verified:true`, rule **119201**.
Đây là probe có đánh dấu test, không phải tấn công thật. Append ACK không chứng
minh đã index; `indexer_verified` vẫn false ở bước này.

Trên Wazuh Dashboard đang đăng nhập:

1. Vào **Threat hunting / Security events**, hoặc Discover với data view
   `wazuh-alerts-*`. Bỏ bộ lọc chỉ agent `001`: log bridge được đọc ở manager và
   có thể mang agent `000`.
2. Chọn **Last 15 minutes**, refresh **5 giây**. Nếu gửi lại muộn thì tăng khoảng
   thời gian theo timestamp thật.
3. Dán `dashboard_query` từ `probe.json`, dạng `data.event_id: "..."`. Cần thấy
   đúng rule 119201 và đúng event ID. Không lấy một probe cũ làm bằng chứng.
4. Muốn có bằng chứng index máy đọc được: mở **Indexer/Dev Tools**, chạy
   `GET wazuh-alerts-*/_search` với body ở `indexer_query` trong report. Lưu
   response JSON thành `indexer-response.json`, rồi:

```powershell
& $py .\wazuh_trace.py verify-index --report (Join-Path $probeRoot 'probe.json') --response (Join-Path $probeRoot 'indexer-response.json') --output (Join-Path $probeRoot 'probe-indexed.json')
if ($LASTEXITCODE -ne 0) { throw 'Response chưa có đúng probe/rule/index.' }
```

Nếu manager đã có alert mà dashboard chưa thấy, kiểm tra bộ lọc/time range và
Filebeat/indexer, không train model lại để xử lý lỗi đường gửi:

```powershell
docker exec $manager tail -n 80 /var/ossec/logs/ossec.log
docker exec $manager filebeat test output
docker logs --tail 80 single-node-wazuh.indexer-1
```

Không bỏ TLS verification hoặc gửi password indexer vào chat. Dev Tools dùng
phiên đăng nhập dashboard hiện có, không cần thêm secret vào source AI.

## 4. Khởi động Live có publication

PowerShell **A**, đứng trong source mới:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Wazuh-Live.ps1 -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' -Case normal-http-01
```

Helper dùng CPU inference, bật publication + informational observations,
interval/summary 1 giây, grace 90 giây. Đợi **READY**, ghi đường dẫn **SESSION**.
Giữ cửa sổ A chạy. `-PlanOnly` chỉ in lệnh; có thể truyền `-PythonPath` nếu
interpreter nằm nơi khác. Model cùng feature/weights đã có, không retrain.

PowerShell **B** mới, khai báo lại biến trong chính cửa sổ đó:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$capture = Read-Host 'Dán đường dẫn SESSION từ cửa sổ A, không thêm ngoặc kép'
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('normal-http-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $py .\wazuh_scenarios.py run --scenario normal-http --capture $capture --output $evidence
if ($LASTEXITCODE -ne 0) { throw 'Kịch bản chưa hoàn tất; giữ operator.json.' }
```

Script kiểm tra IP đích thuộc đúng cặp Kali/Ubuntu trên một private Docker bridge;
không tự dùng host ngoài lab. Nó ghi `operator.json` với thời gian, scope, lệnh,
return code và kết quả thực, không gán nhãn train. Mỗi capture nhận đúng một
operation; chọn `chain` khi muốn nhiều giai đoạn trong cùng phiên. Dùng SESSION
mới cho mỗi ca độc lập, không chỉ đổi tên một capture đã đóng.
Không chạy các kịch bản khác song song trong cùng phiên chẩn đoán.

## 5. Bộ kịch bản và tiêu chí quan sát

| Scenario | Thao tác có giới hạn | Cần xem trên Wazuh |
|---|---|---|
| `normal-http` | 12 GET health/login, khoảng 1 request/giây | 119210 HTTP observation; 119207 sau completed flow; ghi mọi false positive nếu có |
| `normal-ssh` | 5 login đúng, chạy whoami/date/uptime, giữ 5 giây rồi tự thoát | 119208 auth success; 119207/119202 theo quyết định MLP; không có 119204/119205 từ success-only |
| `ssh-negative` | 1 lần sai rồi 1 lần đúng | 119208; không đủ burst 8 nên không tạo chain password-guessing trong capture sạch |
| `port-scan` | TCP connect cổng 1–32, tối đa 5 probe/giây | 119209 chữ ký sensor và 119203 recon nếu rule đang nạp khớp; MLP có thể out-of-scope ở flow ngắn |
| `single-port` | 24 kết nối cổng 22, không thử password | Context distinct-port không được gọi là multi-port scan; SYN rule cũ có thể báo vì chỉ đếm SYN — ghi hạn chế đó |
| `ssh-burst` | 8 mật khẩu cố ý sai, một tài khoản test | Auth log thật có ≥8 failures/60 giây; 119204 và risk 65 khi không có recon trước |
| `ssh-success` | 1 login đúng | Control 119208 trong phiên sạch; không tự thành 119205 |
| `chain` | Scan → 8 lần sai → nhập đúng một lần | 119203/119204 → 119205; attack_chain có recon → failures → success; risk tối đa 95, compromise vẫn false |
| `web-sqli` | 1 GET có UNION SELECT vào DVWA | 119206 nếu Apache/Suricata có indicator; có thể 119209; không khẳng định khai thác thành công hoặc MLP biết SQLi |
| `http-burst` | Cửa sổ khởi tạo 10 giây, tối đa 50 GET, không quá 5/giây | Ghi status/latency/observations; một nguồn không được gắn thành benchmark lớp DDoS |

`plan --scenario chain` chỉ mô tả, không gọi Docker/phát traffic. Để chạy ca
khác, thay scenario và mở Live với `-Case` mới trước. Không có script phát tán,
persist, lấy dữ liệu hoặc thay đổi firewall. Kịch bản chỉ tác động các dịch vụ lab.

### Tài khoản và công cụ cho SSH/chain

Dùng tài khoản riêng `soctest`, không đổi mật khẩu user đang dùng. Chuẩn bị một
lần trong PowerShell B; nhập mật khẩu thật ở prompt `passwd`, không lưu vào script:

```powershell
docker exec -u 0 ubuntu-endpoint id soctest
if ($LASTEXITCODE -ne 0) {
    docker exec -u 0 ubuntu-endpoint useradd -m -s /bin/bash soctest
    if ($LASTEXITCODE -ne 0) { throw 'Không tạo được tài khoản lab riêng.' }
}
docker exec -it -u 0 ubuntu-endpoint passwd soctest
docker exec -u 0 kali-attacker apt-get update
if ($LASTEXITCODE -ne 0) { throw 'Không cập nhật được package list Kali.' }
docker exec -u 0 kali-attacker apt-get install -y --no-install-recommends sshpass nmap netcat-openbsd curl
if ($LASTEXITCODE -ne 0) { throw 'Công cụ Kali chưa sẵn sàng.' }
```

Runner dùng password sai cố định được ghi rõ là test; không phải password thật.
Mỗi kết nối chỉ một prompt, tối đa 8 lần, có timeout. Lượt login đúng yêu cầu
nhập password trực tiếp, không ghi password vào operator log. Runner dừng nếu
thấy PAM faillock/tally2 trực tiếp trong cấu hình đã đọc; không tự tắt lockout.
Lệnh SSH tự kết thúc sau remote command để tránh quên đóng phiên cuối.

Chạy `chain` trong một Live SESSION mới:

```powershell
$capture = Read-Host 'SESSION của Live đang chạy cho chain-01'
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('chain-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $py .\wazuh_scenarios.py run --scenario chain --username soctest --capture $capture --output $evidence
if ($LASTEXITCODE -ne 0) { throw 'Kịch bản chưa hoàn tất; giữ bằng chứng.' }
```

Tám lần gọi client không tự chứng minh tám failure. Sau ca phải đối chiếu log
auth server trong cùng source/account/time window. Nếu mất kết nối, bị lockout
hoặc quá cửa sổ thời gian, ghi đúng kết quả chưa đạt, không giảm ngưỡng để ép pass.

### SQLi

Runner chỉ kiểm tra attempted SQL syntax. DVWA redirect sang trang login vẫn
không phải khai thác thành công. Muốn kiểm chứng ứng dụng trả dữ liệu SQLi phải
đăng nhập DVWA hợp lệ và review response riêng theo [SCENARIOS](SCENARIOS-VI.md).
Không chia sẻ session cookie hoặc khẳng định MLP có lớp SQLi.

## 6. Quan sát và chấm kết quả trên dashboard

Filter tất cả sự kiện AI:

```text
data.soc_ai_producer: "soc-ai-live"
```

Filter một phiên:

```text
data.session_id: "TEN_SESSION_DANG_TEST"
```

Các trường nên thêm làm cột hoặc mở trong event detail: `rule.id`,
`rule.description`, `data.soc_ai_kind`, `data.security_outcome`, `data.source_ip`,
`data.target_ip`, `data.username`, `data.risk_score`, `data.risk_level`,
`data.score_max`, `data.case_id`, `data.attack_chain`, `data.evidence_count`.
Điểm là dữ liệu event; kiểu mapping indexer cần được kiểm tra trước khi tạo
biểu đồ số/range query trên trường custom. Có thể lọc `data.risk_level:"high"`
và dùng `rule.level` chuẩn Wazuh cho phân bố severity.

| Rule | Ý nghĩa | Điểm heuristic thường gặp |
|---|---|---:|
| 119201 | Probe kết nối có đánh dấu test | Không dùng chấm phát hiện |
| 119202 | MLP possible_attack, chưa xác minh | 35 |
| 119203 | Recon evidence | 40 |
| 119204 | Password failures đủ ngưỡng | 65; 75 nếu có recon trước |
| 119205 | Login đúng sau burst failures | 85; 95 nếu có recon trước |
| 119206 | SQL syntax indicator | 60; 70 nếu có recon trước |
| 119207/119208/119210 | Flow/auth/HTTP observation | 0 hoặc 15 cho một auth failure đơn lẻ |
| 119209 | Chữ ký Suricata, chưa xác minh | 50 |
| 119211 | Counter lỗi sensor tăng | 20, loại telemetry warning |

Các stage là bằng chứng có thứ tự theo cùng actor/host/account và cửa sổ thời
gian, không phải mô hình học tự suy ra quan hệ nhân quả. Chuỗi có `case_id`,
stage/evidence ID và JSON graph trong `data.attack_chain_json`. Graph là JSON
string để tương thích decoder Wazuh không nhận array of objects. Bản cấu trúc
đầy đủ nằm ở `correlation-cases.json`; evidence gốc nằm ở correlation-events/raw.

Ca 119203 ban đầu có thể có case ID riêng; khi ghép vào auth chain, recon được
tham chiếu bằng evidence ID. Chuyển tiếp 119204 → 119205 giữ case ID của burst.
MLP đơn lẻ không tự tạo chain hoặc gán confirmed compromise. Context vẫn shadow,
không âm thầm thay rule/MLP hoặc đẩy mọi context signal thành sự cố.

Sau từng ca, Ctrl+C **một lần** ở A và đợi `LIVE_DONE` hết grace. Trong B:

```powershell
$trace = Join-Path $evidence 'wazuh-trace.json'
& $py .\wazuh_trace.py session --capture $capture --operator (Join-Path $evidence 'operator.json') --output $trace
```

Report có counts theo rule, alert thực từ manager, các rule kỳ vọng chưa thấy,
và riêng SSH có counts/danh sách outcome từ native auth. `tail_limited:true`
nghĩa chỉ đọc 4 MiB cuối alerts, không được suy ra rule không tồn tại ở phần
trước. Không có automatic pass từ tên scenario; kiểm tra capture coverage,
sensor warning, native auth và đúng event trên index/dashboard.

Gửi ZIP capture + thư mục evidence + report smoke/indexer để phân tích. Không
gửi mật khẩu/cookie/indexer credentials. Các raw capture này là test phát triển;
nếu đã dùng kết quả để điều chỉnh, giữ phiên mới cho lần đánh giá cuối.

## 7. Giới hạn kiểm chứng

Các kiểm thử source kiểm tra: publish sensor trước completed flow, informational
observations, cùng entity khi ghép chain, không feedback từ AI output vào nguồn,
điểm/graph, reset/delta counter, từ chối target ngoài bridge, bounded commands,
raw auth dedup/scope và xác nhận index đúng event/rule/index. Bộ đầy đủ được chạy
từ gói giải nén trước khi phát hành. Chưa chạy Wazuh Manager/indexer của máy
Windows từ cloud: chỉ gọi thành công end-to-end sau probe và kiểm tra dashboard
thật của người vận hành. Những kiểm thử này không chứng minh accuracy MLP.
