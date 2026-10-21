# Ghép nhánh SSH background với ngữ cảnh tài khoản — 0.4.15.1

Ảnh hai Chain ID cho thấy nhánh authentication và execution đang tách nhau. Chưa có raw session để xác nhận nguyên nhân chính xác trên máy người dùng. Kiểm thử tái hiện được một nguyên nhân trong code0.4.15: có nhiều Accepted SSH cùng tài khoản, shell detached không còn exact session identity; phần xác thực có context case riêng, còn socket behavior lập process case riêng.

Bản sửa nối follow-up vào **một ngữ cảnh xác thực duy nhất** cùng source IP, target IP/host, username và episode. Phải có Accepted thật trước follow-up, gap<90s và tổng episode<900s theo config. Giữ nguyên process/session proof fields; không biến environment hint hoặc ambiguous session thành native SSH proof. Mũi tên ghi same_account_episode_hypothesis và tooltip giải thích tiếng Việt. Không nối khác user, khác endpoint, qua idle95s, nhiều ngữ cảnh cạnh tranh hoặc khi trùng bước có process metadata khác. Không thể phân biệt tuyệt đối hai tác nhân đồng thời dùng cùng account/IP chỉ từ các log này.

Threat Hunting tiếp tục giữ alert từng sự kiện; **alert chain summary**119212/119214/119222 thể hiện liên kết, không thay thế alert gốc. Dashboard Attack Chain dùng summary/stage revision chung. Critical15 không đổi; descriptions mới vẫn English, nội dung hướng dẫn Attack Chain Vietnamese. Không đổi MLP, không thêm payload/hướng dẫn tấn công.

## Cài

Dừng monitor Ctrl+C, đợi LIVE_DONE. ZIP phẳng gộp từ0.4.13.2, bao gồm0.4.15. Nếu chưa cài observer/rule0.4.15, làm đầy đủ [SSH-EXTENDED-CHAIN-0415-VI.md](SSH-EXTENDED-CHAIN-0415-VI.md) sau khi giải nén ZIP mới. Nếu đã cài0.4.15, không cần cài lại rule/observer cho riêng bản sửa này.

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$zip = Join-Path $env:TEMP 'SOC-AI-SSH-Followup-04151.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.15.1-SSH-Followup-Link-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
$sum = Join-Path $env:TEMP 'SOC-AI-SSH-Followup-04151.sha256'
Invoke-WebRequest -UseBasicParsing -Uri ($url + '.sha256') -OutFile $sum
$expected = ((Get-Content -LiteralPath $sum -Raw).Trim() -split '\s+')[0]
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expected) { throw 'ZIP checksum mismatch' }
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
& $py .\setup_attack_chains.py --ssh-extended
if ($LASTEXITCODE -ne 0) { throw 'Chain configuration failed' }
```

Wazuh Management → Saved objects → Import `dashboards\soc-ai-attack-chain-unified.ndjson`, **Overwrite existing objects**, không tạo bản sao. Mở Attack Chain, Last15minutes. Phiên cũ và alert cũ không được viết lại; lọc data.session_id của phiên mới khi so sánh.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
    -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
    -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Doctor phải pass. Quan sát trước khi mở SSH mới. Không nhập session ID ở Kali. Khoảng nghỉ≥90s vẫn chủ động tách episode theo yêu cầu trước đây; bản sửa không tăng timeout để che lỗi.

Một cổng22 chỉ là tiếp xúc SSH, không đủ chứng minh scan nhiều cổng. Password đúng nằm đầu wordlist có thể thành công ngay; không đảm bảo có đủ failures để gán brute-force. Các sự kiện thực vẫn được thể hiện bằng tên trung tính đúng bằng chứng.

Nếu tiếp tục tách, Ctrl+C đợi LIVE_DONE rồi dùng manual_chain_review.py theo hướng dẫn0.4.15; gửi report và correlation-cases.json, không gửi API/private key. Cần raw timestamps để phân biệt phân chia đúng do idle90s với lỗi liên kết.
