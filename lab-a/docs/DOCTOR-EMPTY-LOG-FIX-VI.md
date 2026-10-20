# Doctor từ chối endpoint-probe.jsonl rỗng

Khi mở Live, model, bridge và năm nguồn cũ đạt, nhưng nguồn endpoint mới báo
`Log source is not a regular file`. GNU stat hiển thị `%F` của file 0 byte là
`regular empty file`, trong khi Doctor ban đầu chỉ chấp nhận `regular file`.
Đây là lỗi kiểm tra loại file: log probe mới tạo được phép rỗng trước kịch bản.

Bản sửa dùng `%f` — inode mode dạng hexadecimal — và `stat.S_ISREG`, không phụ
thuộc dung lượng hoặc ngôn ngữ của mô tả `%F`. Thư mục, FIFO, socket, thiết bị,
file không tồn tại hoặc lỗi Docker vẫn không đạt. File rỗng được chấp nhận
không có nghĩa đã có hoạt động hoặc đủ coverage; báo cáo vẫn ghi rõ giới hạn.

## Cập nhật

Áp dụng sau gói 0.4.6 Shard-Fix đang dùng. Tải
`SOC-AI-Lab-A-v0.4.6-Doctor-Fix-20261020.zip` và giải nén nội dung vào:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research
```

Gói chỉ sửa Doctor và test/tài liệu/checksum. Không thay model, live-config,
log container, probe, scoring hoặc Saved objects. Không cần import dashboard
lại hay chạy lại bộ cài probe. Sau giải nén mở Live ở cửa sổ A:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$caseName = 'chain-five-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Wazuh-Live.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -Case $caseName
```

Đợi `checks_passed=true`, nguồn endpoint bytes=0 được phép, rồi đợi READY và
SESSION mới. Giữ A chạy; tại B dùng kịch bản `chain-extended` trong
[hướng dẫn năm bước](CHAIN-INVESTIGATION-VI.md). Nếu Doctor vẫn báo không phải
file thường, đọc loại thật thay vì tự tạo/sửa đường dẫn:

```powershell
docker exec ubuntu-endpoint stat -Lc '%F|%f|%s' -- /var/log/soc-lab/endpoint-probe.jsonl
```

## Kiểm chứng

13 test trong `test_integration_contracts` đạt, gồm file rỗng/không rỗng và các
loại không được chấp nhận. Đã chạy Doctor cũ/mới với GNU stat thật: bản cũ từ
chối file rỗng, bản mới nhận cả hai file, vẫn từ chối thư mục. File rỗng giữ
nguyên 0 byte sau kiểm tra; không thêm bản ghi giả hoặc thay nội dung log.
Đây là kiểm tra Doctor trong môi trường cloud; phiên Live thật trên Windows
của người dùng còn cần chạy tiếp.
