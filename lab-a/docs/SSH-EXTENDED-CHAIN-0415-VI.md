# Liên kết hành vi SSH, artifact và shell socket — 0.4.15

Bản cập nhật chỉ bổ sung giám sát/phát hiện và giao diện; không cung cấp payload hoặc hướng dẫn thực hiện kịch bản tấn công. Chưa kiểm chứng trên máy Windows của bạn; kết quả kiểm thử container được ghi riêng trong validation-0415.json.

## Thay đổi

- Giữ quan sát các password failures dưới ngưỡng và các phiên SSH Accepted kế tiếp theo đúng source IP, target IP/host, account và episode. Mặc định 8 failures/60s vẫn giữ nguyên. Wordlist bốn dòng không bảo đảm có bốn failures: có thể thành công sớm hoặc lỗi kết nối. Thiếu ngưỡng thì hiển thị ngữ cảnh, không gọi brute-force.
- Ghi metadata file đóng ghi/rename vào các thư mục theo dõi; quan sát executable interpreter và đối số đường dẫn script; hỗ trợ shell đã mất ancestry SSH sau khi chạy background. Không lưu nội dung file, toàn bộ argv hoặc mật khẩu.
- Reverse-shell behavior phải có executable shell thực, stdin/stdout cùng socket TCP ESTABLISHED và SYN đi ra khớp tuple/sensor/thời gian. Port 4444, listener, SSH success, chuỗi `bash -i` hoặc tên file riêng lẻ đều không đủ.
- Liên kết SSH phân biệt actual PID/ancestry đã quan sát với environment hint hoặc account/peer/time hypothesis. Không có SSH ancestry vẫn phát hiện được hành vi socket khi đủ bằng chứng, nhưng không giả định chắc chắn phiên nào đã tạo ra nó.
- Rule119220 và chain Critical119222 lên **level15**, risk95 theo chính sách lab. Đây là ưu tiên ứng cứu, không phải bằng chứng đăng nhập trái phép, khai thác thành công hoặc leo thang đặc quyền. Bằng chứng UID0 cũng không tự chứng minh quá trình leo thang.
- Rule119223 file metadata level3;119224 interpreter/script level7;119225 cron change level7. Cron change chưa chứng minh persistence đã chạy.
- Mô tả rule do hệ thống quản lý và diễn giải AI live dùng **tiếng Anh**; nhãn/giải thích trong **Attack Chain** dùng tiếng Việt, giữ nguyên field names. Alert cũ trong index không được viết lại. DoS vẫn là nhãn hiển thị; raw model class order/weights không đổi.
- Giữ một dashboard Attack Chain, ID cũ; các bước có mũi tên, hồ sơ chi tiết và gợi ý bước tiếp theo. Gợi ý là runbook chưa quan sát, không phải dự báo đã hiệu chuẩn. Giữ singleton idle90s tự ẩn; chain nhiều bước giữ lịch sử.

## Cài đặt

Dừng monitor bằng Ctrl+C, đợi LIVE_DONE. ZIP vá phẳng gộp thay đổi từ0.4.13.2, dùng được trên0.4.14/0.4.14.1. Không giải nén bản Research đầy đủ đè config đang dùng.

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$zip = Join-Path $env:TEMP 'SOC-AI-SSH-Extended-0415.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.15-SSH-Extended-Chain-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
$sum = Join-Path $env:TEMP 'SOC-AI-SSH-Extended-0415.sha256'
Invoke-WebRequest -UseBasicParsing -Uri ($url + '.sha256') -OutFile $sum
$expected = ((Get-Content -LiteralPath $sum -Raw).Trim() -split '\s+')[0]
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expected) { throw 'ZIP checksum mismatch' }
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
& $py .\setup_process_observer.py --sensor ubuntu-endpoint --username soctest --watch-artifacts
if ($LASTEXITCODE -ne 0) { throw 'Observer installation failed; keep output.' }
& $py .\setup_attack_chains.py --ssh-extended
if ($LASTEXITCODE -ne 0) { throw 'Chain configuration failed; keep output.' }
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Wazuh installation failed; keep output.' }
```

Không cần cài lại Kali tools, Suricata hoặc nhập VT key cho bản này nếu chúng đã chạy đúng. Observer cần chạy lại sau khi sensor container restart; installer không đổi SSH/PAM/sudo, không tạo user và không cấp đặc quyền cho soctest. Các flag HTTP/SYN đã bật trong config được giữ lại.

Nếu giảng viên muốn chính sách lab coi **3 password failures thực/60s** là password guessing, có thể chủ động đặt ngưỡng dưới đây. Đây là đổi chính sách detection, không cải thiện hoặc huấn luyện MLP; không cần làm để có các bước failures/Accepted trong chain:

```powershell
& $py .\setup_attack_chains.py --ssh-extended --failure-threshold 3
if ($LASTEXITCODE -ne 0) { throw 'Threshold configuration failed' }
```

## Cập nhật Wazuh Dashboard

Management → Saved objects → Import:
`E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson`

Bật **Overwrite existing objects**; không chọn tạo bản sao. Kết quả phải import5objects thành công, mở dashboard **Attack Chain**. Không import các file dashboard lịch sử investigation/shard-fix. Dùng Last15minutes và bật refresh khi xem live. Bấm Chain ID để lọc hồ sơ, tạm Pause refresh khi đọc nội dung dài.

## Bật giám sát và kiểm tra

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
    -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
    -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Doctor phải pass, observer health có artifact_watch_enabled=true, /tmp nằm trong artifact_watch_paths, queue_overflows=0. Session folder tự tạo như trước; phía Kali không phải nhập session ID. Bắt đầu quan sát trước khi có phiên SSH mới. Bạn tự thực hiện bài tập đã được giao; tài liệu này chỉ hướng dẫn bên giám sát.

Chuỗi quan sát có thể gồm:
**Tiếp xúc SSH / Recon → failures → SSH Accepted → file script xuất hiện → interpreter gọi script → shell gắn socket đi ra**.
Không bắt buộc đủ mọi bước; chỉ hiện bước có bằng chứng. Một cổng22 không chứng minh scan nhiều cổng hoặc nhận diện riêng Nmap; hiển thị tiếp xúc SSH trung tính. SYN chỉ xuất hiện khi Suricata active rule và interface thực sự thấy packet.

Threat Hunting lọc:
`rule.id: (119220 or 119222 or 119223 or 119224 or 119225)`.
Đối chiếu data.session_id, data.chain_id, artifact_path/hash, process_id, source_port, ssh_session_link_method và các proof flags.119220/119222 có thể là cùng hành vi ở event và chain summary, không phải hai cuộc tấn công.

Sau bài tập, Ctrl+C đợi LIVE_DONE rồi replay phiên mới nhất, không phải nhập đường dẫn session:

```powershell
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$report = Join-Path 'E:\SOC-Lab\AI' ('chain-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
& $py .\manual_chain_review.py --root 'E:\SOC-Lab\AI\monitor-sessions' --manager single-node-wazuh.manager-1 --output $report
if ($LASTEXITCODE -ne 0) { Write-Warning 'Review needs investigation; preserve report and session.' }
```

Nếu còn thiếu bước, gửi report và correlation-cases.json của đúng phiên, cùng health.json của observer đã che thông tin riêng. Không gửi API key hoặc private key. Report không tự xác minh indexer/dashboard chỉ vì manager đã nhận.

## Phạm vi và giới hạn

Root-owned /proc polling100ms có thể bỏ sót tiến trình ngắn; permission_denials và missing watch paths phải được đọc như giới hạn, không coi là coverage hoàn chỉnh. Inotify chỉ theo dõi trực tiếp /tmp, /var/lib/soc-lab/fim và hai thư mục cron nếu tồn tại; không recursive. Chỉ file thường single-link không symlink, tối đa1MiB; /tmp/FIM lọc đuôi .sh/.py/.pl/.php/.bin. Không giám sát mọi dạng thực thi/payload. Hash là nội dung tại thời điểm quan sát, không bảo đảm nội dung CPU đã thực thi.

SSH mã hóa: file xuất hiện + owner + auth/time là liên hệ giả thuyết, **không chứng minh SCP đã truyền**, actor hoặc maliciousness. Mỗi nhánh giữ riêng account và process/session identity; trường hợp nhiều nguồn hoặc nhiều phiên không phân giải được thì không ép gán một actor. Cùng source/target/time không bảo đảm cùng tác nhân thực; cần thêm audit/transport telemetry để phân biệt các chiến dịch đồng thời cùng tài khoản. Khoảng nghỉ≥90s tách episode theo chính sách hiện tại.

Không thay weights, labels/raw class order, training data hoặc coi diễn tập là bằng chứng model chính xác. Những lịch sử đã thu trước khi bật observer không có bằng chứng mới để tự khôi phục các bước bị thiếu.

## Nguồn tham khảo

- Wazuh rule classification: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
- Wazuh rules syntax: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- MITRE ATT&CK Unix Shell T1059.004: https://attack.mitre.org/techniques/T1059/004/
- Password Guessing T1110.001: https://attack.mitre.org/techniques/T1110/001/
- Ingress Tool Transfer T1105: https://attack.mitre.org/techniques/T1105/ (không áp dụng tự động chỉ từ file xuất hiện)
- Cron T1053.003: https://attack.mitre.org/techniques/T1053/003/ (change không tự chứng minh cron chạy)
- Linux /proc và inotify: https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html ; https://man7.org/linux/man-pages/man7/inotify.7.html

Level15/điểm95 ở đây là chính sách local theo yêu cầu lab, không phải quy định MITRE rằng mọi reverse shell có cùng mức rủi ro.
