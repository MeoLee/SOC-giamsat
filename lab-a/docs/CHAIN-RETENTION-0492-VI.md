# 0.4.9.2 — Chỉ lưu lâu dài các chain đã có nhiều bước

## Quy tắc hiển thị mới

| Dữ liệu đã quan sát | Trong lúc còn chờ | Hết ngưỡng idle |
|---|---|---|
| Một bước | Hiển thị như ứng viên tạm thời | Tự ẩn khỏi danh sách và hồ sơ chain; không hiện giả thuyết tiếp theo |
| Ít nhất hai bước | Hiển thị chuỗi đang hình thành | Giữ chain, sơ đồ, bằng chứng, risk; trạng thái tạm lắng và gợi ý điều tra |

Ngưỡng vẫn dùng `correlation.chain_idle_seconds`, mặc định **90 giây** từ
`last_seen` của bằng chứng, nên chờ **95 giây** là đủ để thử. Nếu bạn tự đặt
ngưỡng khác, thời điểm ẩn sẽ theo cấu hình đó; bản vá không ghi đè live-config.

Một loạt packet/request không tự biến thành nhiều bước. Các node giả thuyết
cũng không được tính là bước đã quan sát. Chain nhiều bước là giả thuyết liên
quan có bằng chứng, chưa khẳng định mọi bước độc hại hoặc cuộc tấn công đã
hoàn tất. Không bắt buộc phải quan sát Nmap trước mới phát hiện hành vi khác.

Bản vá **không xóa alert/index, raw log hay correlation-cases.json**. Hành vi
đơn lẻ vẫn tra cứu ở Threat Hunting và folder session. Phần lịch sử ở cuối
Attack Chain dashboard chỉ hiện revision của chain có từ hai bước.

## Cách ngắt và xử lý bằng chứng đến trễ

- Sau khoảng ngắt đủ ngưỡng, một hành vi mới được detector xếp vào episode
  khác; bước đơn lẻ cũ không được kéo vào chỉ để tạo chain nhiều bước.
- Một log đến trễ có timestamp thuộc episode cũ vẫn có thể chứng minh rằng
  episode đó thực sự từng có hai bước. Khi ấy hồ sơ được hiệu chỉnh và hiện
  lại. Đây là bổ sung bằng chứng cũ, không nối hành vi mới sau khoảng ngắt.
- Dashboard tự xét tuổi ứng viên bằng timer một giây. Vì thế bản ghi một bước
  của phiên monitor cũ cũng tự ẩn, kể cả khi monitor không còn chạy hoặc auto
  refresh đang pause. Đồng hồ trình duyệt và sensor cần đồng bộ để tính tuổi.
- Monitor mới phát summary `chain_status=expired_singleton`,
  `chain_active=false`, `chain_display_state=expired_singleton` đúng một lần
  cho mỗi revision/trạng thái. Chain nhiều bước vẫn active để được lưu trong
  danh sách dù trạng thái hoạt động là `quiescent`.
- Dashboard lấy revision mới nhất trước khi lọc; revision active cũ không được
  dùng thay cho revision inactive/đã hết hạn. Nguồn/đích/host/episode vẫn tách
  như 0.4.9; chưa thể phân biệt tuyệt đối hai tác nhân chung IP/đích/thời gian.

## Cập nhật từ bản 0.4.9.1 bạn vừa cài thành công

1. Ctrl+C cửa sổ monitor, chờ lưu phiên xong (`LIVE_DONE`).
2. Chạy trong PowerShell Windows:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-Chain-Retention-0492.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.9.2-Chain-Retention-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_chain_retention
if ($LASTEXITCODE -ne 0) { throw 'Test retention chưa đạt; giữ output.' }
```

ZIP vá phẳng, giải nén trực tiếp vào project; không tạo thư mục con. Không đổi
model, threshold, credentials, live-config, rules hoặc Docker permissions.
Không cần train, chạy lại setup_wazuh, restart manager hoặc reindex.

3. Trong Wazuh: Saved objects → Import → bật overwrite → chọn:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson
```

Vẫn đúng **5 objects, một dashboard SOC Lab A - Attack Chain**, cùng ID. Mở
lại dashboard, Ctrl+F5. Xóa filter Chain ID/session cũ nếu muốn xem toàn bộ.
Những singleton cũ cũng được lọc khỏi danh sách và lịch sử; không cần xóa index.

4. Mở **phiên monitor mới**:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1
```

Chờ READY. Từ đó vẫn gõ lệnh thủ công trong Kali Bash, không nhập SESSION.

## Kiểm tra nhanh chính sách, chưa sang kịch bản tấn công tiếp theo

Giữ monitor chạy. Để một bài trước ngừng hoạt động ít nhất 95 giây. Trong
Kali chỉ quét cổng một lần, không chạy thêm SSH/SQLi/HTTP load:

```bash
export TARGET=172.20.0.3
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Lúc đầu ứng viên mới có một bước scan, risk 40. Sau đó:

```bash
sleep 95
```

Kỳ vọng ứng viên một bước biến mất khỏi Attack Chain dashboard; không còn ô
quét cổng hoặc giả thuyết tiếp theo của ứng viên đó. Alert scan vẫn tìm được
trong Threat Hunting. Chain nhiều bước của các bài trước vẫn được giữ nếu
còn trong time filter và chưa bị thay thế bởi revision khác.

Khi muốn tiếp tục kịch bản 1 đã gửi (scan → SQLi), thực hiện hai hành vi liên
tiếp trong ngưỡng idle. Khi đủ hai bước, chain đó được lưu sau khoảng nghỉ.
Tài liệu này không yêu cầu chạy kịch bản tiếp theo.

## Kiểm chứng

- 430 tests: đạt, 2 test tích hợp filesystem Windows được skip trong cloud.
- Native OpenSearch Dashboards 2.19.3: import/overwrite 5 objects; ứng viên một
  bước tự ẩn sau 95 giây giả lập với auto refresh pause và không có log mới.
- Chain scan → SQLi có hai node, một liên kết, risk 70 vẫn tồn tại sau một giờ
  giả lập, giữ riêng một node giả thuyết; không xóa document trong index.
- Lịch sử native trả đúng ba document của revision hai bước (hai stage và một
  summary). Các shard cũ thiếu field được query với unmapped sort an toàn.
- Chưa xác nhận bản cập nhật trực tiếp trên Docker Desktop Windows của bạn.

[Chi tiết validation](validation-0492.json).
[Hướng dẫn vận hành và kịch bản nền](SCENARIO-RESEARCH-049-VI.md).
