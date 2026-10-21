# 0.4.10.1 — Sửa bộ đọc rule ID từ logtest

Trong output bạn gửi, rule SQLi đã khớp **119215 level 12**. Bộ cài lại báo
thêm `9900101` trong danh sách matched vì regex cũ tìm `id:` ở mọi chỗ, bao
gồm trường decoded `signature_id: '9900101'` ở Phase 2. Đây là lỗi bộ đọc
kết quả, không phải rule SQLi sai hoặc Docker/API key lỗi.

Bộ cài đã restore cấu hình/rule cũ và dừng trước restart. Các bước sau trong
hướng dẫn FIM/VT chưa chạy trong lần này. Không cần sửa XML hoặc bỏ validation.

Bản sửa chỉ lấy dòng `Rule id` (legacy) hoặc `id` (modern) **trong Phase 3**;
không nhận signature_id, event_id, rule_id hoặc field id trong Phase 2. Thiếu,
thừa hoặc sai rule thực sự vẫn bị từ chối. Dùng chung cho bridge, scenario
rules và bộ cài VirusTotal vì cả ba nhúng helper này vào remote payload.

## Máy đã giải nén bản 0.4.10 và đang gặp lỗi này

Chạy tại PowerShell Windows; giữ monitor dừng trong lúc cài:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-Logtest-Parser-Fix.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.1-Installer-Parser-Fix-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_wazuh_install_checks
if ($LASTEXITCODE -ne 0) { throw 'Test bộ đọc chưa đạt; giữ output.' }
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Bridge chưa đạt; giữ toàn bộ output.' }
```

Kỳ vọng `CANDIDATE_RULES_VERIFIED_OFFLINE` (khi có legacy), rồi
`WAZUH_CORE_READY` và **`WAZUH_BRIDGE_INSTALLED`**. Bộ cài tự restart; không
restart thêm. Sau đó tiếp tục **bước 2 — FIM** trong
[hướng dẫn VT-01](VIRUSTOTAL-01-VI.md#2-bật-fim-có-scope-và-rule-của-thư-mục-lab),
rồi nhập key cục bộ ở bước 3. Không gửi API key hoặc ossec.conf qua chat.

Không train, không import lại dashboard. ZIP vá phẳng chỉ cập nhật source,
tests, hướng dẫn và manifest; không có model/key/live-config.

## Nếu chưa cập nhật từ 0.4.9.2

Dùng gói tích lũy đã sửa
[SOC-AI-Lab-A-v0.4.10.1-Severity-VT-20261021.zip](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.1-Severity-VT-20261021.zip)
và làm từ đầu hướng dẫn VT-01 hiện tại. Không cần giải nén 0.4.10 trước gói
này. Không dùng gói tiny parser fix để nâng trực tiếp từ 0.4.9.2 vì nó không
chứa toàn bộ tính năng VT mới.

## Kiểm chứng

- Production `RuleCheck.before_restart()` chấp nhận đúng 15 rule từ chính
  output lỗi đã gửi sau khi sửa parser; log cá nhân không được đóng gói.
- Cùng parser khớp đủ 22 kết quả trong output native Wazuh 4.14.7 đã kiểm tra
  ở bản 0.4.10, gồm các signature ID và VirusTotal rules.
- Regression tests bao phủ legacy/modern, CRLF, field id ở Phase 2, không có
  Phase 3, và một rule thật bị thừa; không chỉ dùng regex khác trong harness.
- Toàn suite: 443 tests, không lỗi; 2 test filesystem Windows skip trong cloud.
- Chưa chạy lại installer hoặc gọi VirusTotal trực tiếp trên Windows của bạn.

[Validation](validation-04101.json).
