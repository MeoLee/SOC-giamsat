# Phản hồi sớm tiếp xúc SSH và diễn giải MLP — 0.4.14.1

## Nguyên nhân và phạm vi sửa

Nhánh MLP chấm completed flows: SYN đã xuất hiện không đồng nghĩa flow đã được Suricata xuất, vì vậy dự đoán có thể đến muộn theo timeout đóng flow. Trong bản0.4.14, ngữ cảnh một cổng SSH chỉ được thêm khi đã có bằng chứng shell/socket. Điều này làm dashboard không hiện bước thăm dò một cổng khi người dùng đang quan sát riêng bước đầu.

Bản sửa:
- Tạo ứng viên **Tiếp xúc SSH — ứng viên chưa xác minh** ngay từ SYN SID9900003 vào22, không cần completed flow, brute-force hay Reverse Shell.
- Console `[SSH-CONTACT]` và Wazuh119221 level3 là quan sát trung tính, risk0. Không gán Nmap/malicious recon từ một SYN; SSH hợp lệ và health check có thể giống vậy.
- Ưu tiên consume/correlate và giao outbox bằng chứng trước bước suy luận completed-flow.
- Khi đủ hành vi tiếp theo, giữ cùng Chain ID để nâng ứng viên thành chuỗi; phiên/account/target khác không dùng chung xác thực. Các nhánh cùng episode chỉ liên quan theo thời gian, không khẳng định nhân quả.
- Retransmission/duplicate EVE không tăng connection_count hoặc kéo dài idle. Normal auth có source port trùng thì rút ứng viên đó, không giữ thành chuỗi tấn công bình thường.
- Singleton tự ẩn sau90s (kiểm tra sau95s). Model summary đến muộn không làm sống lại ứng viên. Chuỗi nhiều bước được giữ như trước.

Một cổng không đủ để kết luận quét nhiều cổng. Nếu đạt ngưỡng distinct ports, dùng bước Recon cũ; không hạ ngưỡng đó xuống1.

## Vì sao top class BENIGN vẫn từng xuất hiện ở rule119202?

`predicted_label` là argmax của các lớp. Quyết định binary lại dùng tổng điểm của tất cả lớp khác BENIGN, so với threshold của model. Ví dụ BENIGN0.4 là lớp cao nhất nhưng tổng lớp khác0.6 vẫn có thể vượt threshold0.5. Điểm này chưa được hiệu chuẩn thành xác suất.

Bản sửa console thành `top_class=...`, ghi rõ cách diễn giải. Rule119202 hiển thị **Chưa xác định loại tấn công (lớp điểm cao nhất: BENIGN)** khi tình huống trên xảy ra, kèm score_max và threshold; không còn câu `prediction: BENIGN` bị hiểu thành kết luận traffic lành tính trong một cảnh báo tấn công.

Không sửa weights, class order, threshold hoặc TCP timeout; không ép model gọi tất cả TCP22 là PortScan. Bản vá sửa đường phản hồi quan sát và cách diễn đạt, chưa chứng minh model hết false positive/negative. Để đánh giá model cần đối chiếu ai-input-flows.jsonl và ai-predictions.jsonl của đúng phiên, không lấy tên thao tác làm nhãn mọi flow.

## Cài đặt

ZIP phẳng gộp các thay đổi từ0.4.13.2, gồm0.4.14 và bản sửa này; dùng được nếu đã cài0.4.14. Giữ config/model/VT key. Dừng monitor Ctrl+C, đợi kết thúc trước khi giải nén.

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-SSH-Early-04141.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.14.1-SSH-Early-Contact-20261021.zip' -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài Wazuh rules chưa đạt; giữ output.' }
& $py .\setup_attack_chains.py --ssh-contact
if ($LASTEXITCODE -ne 0) { throw 'Bật quan sát SSH chưa đạt; giữ output.' }
```

Wazuh tự restart một lần và kiểm tra. Không cần chạy lại Suricata nếu SID9900003 đã hoạt động; ảnh người dùng gửi đã có native SYN observations. Không cần cài lại process observer đang khỏe; source và rule Reverse Shell0.4.14 được giữ. Nếu chưa cài process observer, bản sửa contact vẫn dùng được; bổ sung process telemetry riêng theo tài liệu0.4.14 khi cần.

Import `dashboards/soc-ai-attack-chain-unified.ndjson` vào Saved objects, bật overwrite; vẫn một dashboard **Attack Chain**. Bật monitor:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Đợi READY. Dashboard Last15minutes, refresh2–5s. Quan sát khi thao tác đang diễn ra và trước90s; không đợi model rồi mới kiểm tra singleton. Threat Hunting:

```text
rule.id: "119221"
```

Để xem lời giải thích model mới: `rule.id: "119202"` và chọn thời gian sau cập nhật. Alert cũ không được viết lại.

## Độ trễ và chẩn đoán

Không cam kết mọi alert xuất hiện trong1s. Tách thời gian SYN ở sensor → AI collection → outbox/manager → indexer → dashboard. Console SSH-CONTACT không cần MLP có dự đoán. Nếu đã có dòng này nhưng dashboard chưa có dữ liệu, kiểm tra outbox/pending/indexer/filter thay vì sửa threshold model. Nếu không có, kiểm tra cờ ssh_contact_observations_enabled, Doctor, raw EVE mới, đúng asset/sensor và SID9900003.

Read-only kiểm tra cờ:
```powershell
(Get-Content .\live-config.json -Raw | ConvertFrom-Json).correlation |
    Select-Object attack_chain_enabled, ssh_contact_observations_enabled, chain_idle_seconds
```

Code chỉ tạo contact cho host đã cấu hình, sensor đúng host, đíchTCP22; không gán các flow đảo chiều/cổng khác thành SSH contact. Thời gian ngắt chuỗi và giới hạn visibility giữ nguyên. Alert thấp không phải bằng chứng đã tấn công.

## Nguồn

- Suricata flow/EVE: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- MITRE Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- Wazuh rule classification: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html

Validation trong validation-04141.json: fixture kiểm tra quan sát trước inference, native Wazuh và dashboard; không phải đo latency/FPR trên máy Windows của người dùng.
