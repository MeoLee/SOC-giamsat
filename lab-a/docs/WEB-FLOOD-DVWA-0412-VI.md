# 0.4.12 — Web flood vào DVWA, bằng chứng Apache/Suricata và Wazuh

## Thiết kế và mức kết luận

Bài tập gửi GET có giới hạn vào **`http://172.20.0.3/dvwa/login.php`** từ
Kali. Đây là route PHP thật của DVWA, không phải `/soc-lab-health`. Không cần
mật khẩu DVWA; không gửi form, SQLi, file, cookie hay lệnh hệ thống.

| Bằng chứng | Kết luận / rule |
|---|---|
| Suricata thấy60 GET `/dvwa/` trong10s theo cặp nguồn/đích | SID9900104: HTTP request-rate indicator; bridge119209 level8. Chưa chứng minh tác động |
| Apache ghi ít nhất60 request cùng nguồn/host/IP/port/origin/method/path trong10s | `119217`, level8 — Medium: web flood / áp lực HTTP |
| Điều kiện trên + baseline khỏe cùng route + ít nhất20% và tối thiểu5 request5xx hoặc chậm | `119218`, level12 — High: nghi vấn HTTP DoS có suy giảm |
| MLP dự đoán DoS, hoặc chỉ có client timeout/HTTP200/302 | Không đủ để tạo kết luận DoS có suy giảm |

Đây là **ngưỡng chính sách của Lab A**, không phải ngưỡng do MITRE/Wazuh quy
định và chưa được hiệu chỉnh bằng dữ liệu production. Không tạo Critical từ
bài flood này. Request-rate của Suricata và Apache là hai nguồn quan sát,
không cộng số lượng hai nguồn vào cùng bộ đếm.

Baseline dùng tối đa20 request trước burst, trong120s, tối thiểu10 mẫu;
chỉ dùng response đã hoàn tất trước onset và cùng **host/IP/port/origin/
method/path**. Baseline khỏe khi dưới10% request có status ngoài200–399
hoặc duration>=1s. Ngưỡng chậm mặc định là **max(1s,5×baseline p95)**.
HTTP4xx không tự tính thành suy giảm DoS. P95 dùng nearest-rank, không phải
trung bình hoặc xác suất. `%D`/`duration_us` của Apache có đơn vị microsecond.

Để tách baseline1req/s khỏi flood, detector chia chuỗi theo gap tối đa0.5s
(`http_pressure_gap_us=500000`), rồi xét cửa sổ tối đa10s trong đoạn đó.
`window_rate_rps=request_count/10` là tốc độ quy đổi theo cửa sổ cấu hình,
không phải tổng request/s toàn mạng hoặc số lượng do client khai báo.

Apache chỉ ghi request hoàn tất. Khi server ngừng nhận hoặc chưa trả lời,
log có thể đến muộn/thiếu; **không suy ra không có DoS từ việc thiếu log**.
Chữ ký mạng hỗ trợ quan sát GET, nhưng không thay thế health check/tài nguyên
server. Bản này không phát hiện đầy đủ SYN flood, Slowloris, UDP, HTTP/2,
HTTPS được mã hóa hoặc DDoS từ nhiều nguồn. Với HTTPS cần telemetry giải mã/
reverse proxy phù hợp. T1499 là ứng viên theo bằng chứng, chưa gán cơ chế
CPU/memory exhaustion hoặc ý đồ tấn công chỉ từ latency.

## 1. Cập nhật — PowerShell Windows

Dừng AI bằng Ctrl+C, đợi LIVE_DONE. Bản vá phẳng dành cho0.4.11 đã cài được
VT/EICAR; cũng dùng được khi đã import bản đổi nhãn0.4.11.1. Bản vá giữ nhãn
**Chuyển file độc qua SSH** và chú thích EICAR. Không ghi đè live-config,
model, dữ liệu hoặc API key; không chạy lại setup_virustotal.py.

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$zip = Join-Path $env:TEMP 'SOC-AI-DVWA-Web-Flood-0412.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.12-DVWA-Web-Flood-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
```

Cài helper vào Kali, cập nhật rule đã kiểm chứng, rồi bật tính năng:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Kali-Tools.ps1
if ($LASTEXITCODE -ne 0) { throw 'Chưa cài được helper Kali.' }

& $py .\setup_suricata_web.py --container ubuntu-endpoint
if ($LASTEXITCODE -ne 0) { throw 'Rule Suricata chưa đạt; giữ output.' }

& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Rule Wazuh chưa đạt; giữ output.' }

& $py .\setup_attack_chains.py --http-flood
if ($LASTEXITCODE -ne 0) { throw 'Chưa bật được detector HTTP flood.' }
```

Suricata kiểm tra cấu hình và PCAP positive/control trước khi backup, thay
rule nguyên tử và gửi SIGUSR2 để hot reload. File `-S` hiện có và SYN/recon
observations được giữ. Có thông báo `RULE_BACKUP` để truy vết.
Wazuh kiểm tra rule rồi **tự restart manager một lần**, dùng cơ chế restart
đã sửa timeout; không restart thủ công lần nữa. Các integration VT được giữ.
Nếu installer báo lỗi, dừng trước traffic. Doctor sẽ chặn Live nếu đã bật
HTTP flood nhưng bridge chưa có119217/119218.

## 2. Cập nhật dashboard

Wazuh → Dashboards Management → Saved objects → Import:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson
```

Bật **Automatically overwrite conflicts**, import5 objects; giữ cùng ID và
tên **Attack Chain**. Không tạo bản sao và không import dashboard lịch sử.
Xóa filter Chain ID/Session cũ; chọn Last15 minutes, refresh2–5s.

## 3. Bật AI — PowerShell A

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Start-SOC-Monitor.ps1 `
    -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
    -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Đợi READY. AI tự lưu session, thu Apache/Suricata và gửi Wazuh. Không train
lại model; MLP completed-flow được giữ riêng với detector bằng chứng HTTP.
Không dùng dự đoán làm ground truth. Giữ monitor chạy trong toàn bài.

## 4. Một kịch bản: baseline → scan → web flood → recovery

PowerShell B:

```powershell
docker exec -it kali-attacker bash
```

Từ đây gõ từng dòng trong **Bash Kali**. Chờ95s nếu vừa chạy case khác.

```bash
export TARGET=172.20.0.3
export OUT=$(mktemp -d /tmp/dvwa-web-flood.XXXXXX)
```

**Baseline**:20 GET, tối đa1 lần bắt đầu/s, một kết nối đồng thời:

```bash
python3 /opt/soc-lab/dvwa_web_flood.py baseline --target "$TARGET" --output "$OUT/baseline.json"
```

Phải hoàn tất20 request và status200/3xx. Nếu404/403/5xx/timeout hoặc exit2,
kiểm tra DVWA/network trước; chưa chạy flood. Helper không follow redirect,
không lưu cookie hoặc mật khẩu. Không lấy baseline `/soc-lab-health` thay
cho baseline DVWA.

**Scan**: tạo bước recon để bài có hai hành vi cho Attack Chain:

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

**Flood**: trong90s sau scan, gửi400 GET, tối đa40 lần bắt đầu/s,8 kết nối,
timeout2s. Đoạn tải thường khoảng10s khi server đáp ứng tốt:

```bash
python3 /opt/soc-lab/dvwa_web_flood.py flood --target "$TARGET" --requests 400 --rate 40 --concurrency 8 --output "$OUT/flood.json"
```

Helper có hard bounds: tối đa1000 request,100 starts/s,16 kết nối; thời gian
bắt đầu request theo cấu hình tối đa20s, deadline phát tải tối đa25s; sau đó
chờ request đang chạy với timeout mỗi request tối đa3s. Không catch-up burst, không chạy vô hạn. Ctrl+C dừng gửi và chờ các
request đang chạy kết thúc theo timeout. Mỗi pha ghi tiến độ và JSON riêng.
`phase_completed` chỉ cho biết phần phát tải hoàn tất; `dos_success_proven`
luôn false. Client timeout/5xx là dữ liệu cần đối chiếu, không phải nhãn AI.

**Recovery**: một kết nối,20 GET ở1req/s trên cùng route:

```bash
python3 /opt/soc-lab/dvwa_web_flood.py recovery --target "$TARGET" --output "$OUT/recovery.json"
```

Không tăng tải chỉ để buộc xuất hiện High. Nếu DVWA xử lý được400 request
mà không tăng5xx/latency vượt điều kiện, bài vẫn đạt phần phát hiện **web
flood / áp lực HTTP**. Muốn nghiên cứu sức chịu tải cao hơn phải đo tài nguyên
và giữ bounds của helper; không làm giả5xx, latency, nhãn hoặc giảm threshold
để trình diễn DoS thành công.

## 5. Kỳ vọng và đọc số liệu

Cửa sổ A có dòng `[HTTP-LOAD]` với route, request/window, p95,5xx và baseline.

| Kết quả thực tế | Threat Hunting | Attack Chain |
|---|---|---|
| Lưu lượng cao, server vẫn khỏe/thiếu baseline |119217 level8; có thể thêm119209/SID9900104 | Scan → Web flood / áp lực HTTP; score55 cho hai bước mặc định |
| Có baseline khỏe và suy giảm đạt ngưỡng |119218 level12 | Scan → Nghi vấn HTTP DoS — dịch vụ suy giảm; score85 cho hai bước mặc định |
| Client timeout nhưng thiếu request hoàn tất trên Apache | Đọc indicator mạng và raw logs | Có thể chưa đủ node hoặc không đủ kết luận DoS; không coi thiếu alert là chứng minh không bị ảnh hưởng |

Trong Threat Hunting (bỏ filter AI/session cũ nếu đang che kết quả):

```text
rule.id: "119217" or rule.id: "119218" or (rule.id: "119209" and data.signature_id: "9900104")
```

Các field cần đọc: `http_route`, `http_method`, `request_count`,
`window_seconds`, `window_rate_rps`, `burst_p50_us`, `burst_p95_us`,
`baseline_request_count`, `baseline_p95_us`, `slow_us`, `server_5xx_count`,
`server_5xx_ratio`, `slow_request_count`, `healthy_baseline_observed`,
`baseline_comparison_scope` và `service_degradation_observed`.

Bấm Chain ID trong Attack Chain để xem mũi tên, badge request/p95/5xx và
chi tiết đầy đủ. Các revision cùng case là cập nhật, không phải số cuộc tấn
công mới. Phục hồi là metric đối chứng; không tự thêm stage tấn công.

Chain scan→flood có ít nhất hai bước nên được giữ sau idle90s và hiện giả
thuyết tiếp theo. Nếu chỉ chạy flood đơn lẻ, ứng viên một bước tự ẩn sau90s
theo chính sách đã thống nhất; alert và raw logs vẫn còn trong Threat Hunting/
folder session. Lúc kết thúc, Ctrl+C tại A và đợi LIVE_DONE.

Để gửi kết quả kiểm tra, giữ3 JSON trong `$OUT`, output `[HTTP-LOAD]`, các
alert119217/119218 hoặc sensor indicator và session raw. Không cần gửi API
key VT. Có thể đóng phiên rồi chạy manual_chain_review.py để đối chiếu replay;
replay không tự xác minh rendering hay việc dịch vụ thật đã bị DoS.

## Nguồn và mức kiểm chứng

- [MITRE ATT&CK T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/).
- [T1499.003 — Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/): tham khảo cơ chế; không tự gán sub-technique khi chưa có bằng chứng tài nguyên.
- [Wazuh rule classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html).
- [Apache mod_log_config — `%D` và LogFormat](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats).
- [Suricata thresholding](https://docs.suricata.io/en/latest/rules/thresholding.html).
- [DVWA upstream](https://github.com/digininja/DVWA).

Rule được kiểm thử bằng Suricata8.0.3, Wazuh4.14.7, replay và giao diện native
OpenSearch Dashboards với fixture có positive/control. Client GET/timeout
được kiểm thử trên HTTP server thật cục bộ có route fixture. **Chưa benchmark
sức chịu tải trên Ubuntu/DVWA của bạn**, chưa chứng minh độ chính xác detector
production. Xem `validation-0412.json` để phân biệt kiểm thử phần mềm với kết
quả lab thật. Không chứa model weights mới hoặc thay đổi firewall/PAM/SSH.
