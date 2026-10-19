# Sửa lỗi cài bản 0.4 trên Windows — 19/10/2026

Log người dùng xác nhận Python3.12.10, torch2.11.0+cpu và các dependencies đã cài thành công. `run_checks.py` nhận diện317 ca, có một failure và một error; không phải pip/CUDA thiếu.

## Nguyên nhân đã xác định

1. ZIP0.4 ban đầu bị thiếu `soc_ai/web/dashboard.html` do bộ đóng gói lọc theo đuôi file và bỏ sót HTML. Dashboard trả400 khi không đọc được asset. Đã tái hiện nguyên lỗi bằng cách chạy test dashboard từ ZIP cũ giải nén trên Linux.
2. Test context ghi text bằng newline của hệ điều hành, nhưng so byte offset với chuỗi LF cố định. Windows ghi CRLF nên offset thực10bytes thay vì9. Offset của runtime đúng; fixture test sai. Test đã sửa để ghi byte rõ ràng và kiểm tra cả LF/CRLF trên mọi hệ điều hành.

## Cài bản vá, không cài lại Python

Đóng các cửa sổ dashboard/test đang chạy. Trong PowerShell trên máy Windows:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$patch = Join-Path $env:TEMP 'SOC-AI-v04-Windows-Fix.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4-Windows-Fix-20261019.zip' -OutFile $patch
Expand-Archive -LiteralPath $patch -DestinationPath (Get-Location).Path -Force -ErrorAction Stop
& 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe' .\run_checks.py
if ($LASTEXITCODE -ne 0) { throw 'Kiểm thử còn lỗi; giữ toàn bộ phần FAILED/ERROR để phân tích.' }
```

Patch bổ sung asset, sửa test và cập nhật tài liệu/checksum. Không sửa model weights, code train/inference, cấu hình live, dataset hoặc venv. Không cần train lại hay tải lại torch.

Mong đợi `Ran 317 tests` và `OK`. Hai test Win32 đã đạt trong log Windows cũ; cloud Linux vẫn bỏ qua hai test đó. Chưa gọi toàn bộ bản sửa là đã được kiểm tra trên Windows thật cho đến khi nhận kết quả chạy lại của người dùng.

## Tải mới

Nếu chưa cài0.4, dùng ZIP0.4.1 thay vì bản0.4 đầu tiên. Thư mục giải nén vẫn là `SOC-AI-v0.4-research` để giữ hướng dẫn và đường dẫn tương thích. Version hotfix dành cho đóng gói/test; architecture, feature hash và model format không đổi.

Bộ phát hành mới lấy toàn bộ file source được Git theo dõi, không lọc bỏ extension của asset; bắt buộc có dashboard HTML và kiểm tra CRC/nội dung/hash. Bộ317 test phải chạy từ **thư mục giải nén ZIP**, gồm HTTP dashboard thật, trước khi phát hành.
