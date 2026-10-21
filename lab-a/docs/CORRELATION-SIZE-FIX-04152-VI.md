# Sửa monitor dừng vì correlation event vượt6000bytes — 0.4.15.2

Log người dùng ghi nhận chain6bước risk95 và PROCESS-EVIDENCE shell_socket_outbound_verified, sau đó RuntimeError Correlation event exceeds6000bytes. Đây là lỗi đóng gói legacy correlation summary trong live_activity.py, không phải chứng cứ rằng thao tác SSH không chạy hoặc detector không nhận ra socket. Wazuh pending0 chỉ chứng minh outbox đã giao các bản tin đã enqueue trước đó, không xác minh mọi alert/index/dashboard.

Bản sửa giữ nguyên full event trong live-activities.jsonl và full case/evidence trong correlation-cases.json. Chỉ bản sao gửi Wazuh được lược dần graph JSON, chi tiết lặp và metadata verbose nếu vượt6000UTF-8bytes. Event có delivery_compacted=true, delivery_omitted_fields và full_event_id/full_event_local_file để tra bản gốc. Nếu metadata tùy ý vẫn quá lớn, gửi minimal summary có ID, trạng thái, endpoints, score/severity và cờ rõ ràng. Không tăng giới hạn buffer Wazuh hoặc cắt JSON thô giữa chừng. Chain stage/summary và Critical15 không đổi.

## Cài trên0.4.15.1

Monitor hiện tại đã dừng vì lỗi; giữ nguyên session và outbox, không xóa. Nếu còn monitor khác chạy, Ctrl+C đợi LIVE_DONE trước khi giải nén. ZIP vá phẳng chỉ bổ sung bản sửa này; không thay config, rule, model hoặc VT key. Không cần import lại dashboard/cài observer/cài Wazuh.

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-Correlation-Size-04152.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.15.2-Correlation-Size-Fix-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
$sum = Join-Path $env:TEMP 'SOC-AI-Correlation-Size-04152.sha256'
Invoke-WebRequest -UseBasicParsing -Uri ($url + '.sha256') -OutFile $sum
$expected = ((Get-Content -LiteralPath $sum -Raw).Trim() -split '\s+')[0]
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expected) { throw 'ZIP checksum mismatch' }
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
    -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
    -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Kiểm tra Doctor pass; quan sát phiên mới và lọc đúng data.session_id. Không tái thực thi dữ liệu/payload từ session cũ trong quá trình cài. Không viết lại alert cũ hoặc tuyên bố đã khôi phục giao nhận cho phiên đã lỗi.

Kiểm thử có trường hợp six-stage correlation, đường dẫn Windows dài, metadataUnicode nhiều byte, optional field100KB, bảo toàn original event, giới hạn serialized bytes và tiếp tục publisher. Chưa kiểm chứng trên máy Windows thật của người dùng; không thay đổi hành vi tấn công hay cung cấp lệnh khai thác.
