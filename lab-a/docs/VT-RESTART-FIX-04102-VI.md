# 0.4.10.2 — Sửa timeout khi restart Manager trong bộ cài VT

## Đọc đúng kết quả đã gửi

Mẫu offline khớp đúng **87105 level 12** và có
`CANDIDATE_RULES_VERIFIED_OFFLINE`. Sau đó `wazuh-control restart` vượt giới
hạn 60 giây của bộ cài. Bộ cài khôi phục config cũ rồi restart rollback;
dòng `Remote integrations not configured. Clean exit.` xuất hiện trong lần
khởi động cấu hình đã khôi phục. Đây chưa phải kết quả gọi VirusTotal thật.

Traceback chứng minh timeout; chưa đủ để khẳng định dịch vụ khởi động hỏng.
Ngoài việc restart thật có thể chậm, `subprocess.run(capture_output=True)`
còn phải chờ EOF trên pipe: daemon con giữ stdout/stderr có thể kéo dài chờ
dù PID của lệnh điều khiển đã kết thúc.

Bản sửa dùng chung cho bridge/scenario/VT:

- Restart ghi output vào **file riêng mode 0600**, chờ PID `wazuh-control`
  thay vì EOF của daemon. Các lệnh `-t` vẫn có giới hạn 60 giây riêng.
- Cho phép tối đa **240 giây**, in tiến độ mỗi 10 giây; sau đó vẫn kiểm tra
  core processes và, với VT, phải có `wazuh-integratord` chạy.
- Đọc native control lock trước khi thay config/rule và trước restart; không
  xóa lock hoặc kill daemon để vượt kiểm tra.
- Nếu quá hạn mà control PID **vẫn đang chạy**, báo `RESTART_PENDING`, giữ
  candidate đã qua validation, không phát marker thành công, không restore
  hoặc chạy thêm restart chồng lên tiến trình đầu. Không tự kill dịch vụ.
- Với control đã kết thúc nhưng trả lỗi hoặc readiness không đạt: vẫn restore
  cấu hình cũ và thử restart rollback; giữ nguyên lỗi gốc nếu rollback cũng lỗi.
- Output VT in ra console được che key. File log restart là private; không
  upload log/config nguyên bản có thể chứa secret.

## Cập nhật máy đã có 0.4.10 hoặc 0.4.10.1

Giữ monitor dừng. Chạy tại PowerShell Windows:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-VT-Restart-Fix.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.2-VT-Restart-Fix-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_restart_control test_wazuh_install_checks test_severity_virustotal
if ($LASTEXITCODE -ne 0) { throw 'Test restart chưa đạt; giữ output.' }
& $py .\setup_virustotal.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'VT chưa hoàn tất; giữ output đã che key, chưa chạy bài file.' }
```

Vì lần cài trước đã rollback về cấu hình không có VT, **cần nhập lại API key
một lần tại prompt ẩn**. Không đưa key vào command line/chat. Đợi các dòng:

```text
WAZUH_RESTART_BEGIN
WAZUH_RESTART_COMPLETED
WAZUH_CORE_READY
VIRUSTOTAL_CONFIGURED
```

Có thể có `WAZUH_RESTART_WAITING` khi mất hơn 10 giây. Đợi bộ cài hoàn tất;
không mở cửa sổ khác chạy restart/installer song song. Không cần chạy lại
bridge/FIM/scenario nếu các bước đó đã thành công trước đó, không import
lại dashboard và không train.

Sau `VIRUSTOTAL_CONFIGURED`, key nằm trong ossec.conf của Manager theo native
Wazuh. Những lần demo sau chỉ cần file mới/VTID mới, không nhập key lại, trừ
khi đổi key hoặc mất/reset cấu hình. Tiếp tục **bước 4** rồi các bước control/
EICAR trong [VT-01](VIRUSTOTAL-01-VI.md); chưa chuyển sang kịch bản khác.

## Nếu thấy RESTART_PENDING

Đây là trạng thái chưa hoàn tất, không phải cài thành công. Không retry hoặc
restart ngay. Chờ control PID hiện tại kết thúc, giữ output đã che key và
kiểm tra chỉ đọc từ PowerShell:

```powershell
docker exec single-node-wazuh.manager-1 sh -c 'cat /var/ossec/var/start-script-lock/pid 2>/dev/null || true'
docker exec single-node-wazuh.manager-1 tail -n 80 /var/ossec/logs/ossec.log
```

Không xóa lock, kill tiến trình hoặc upload ossec.conf. Sau khi control cũ đã
kết thúc, mới kiểm tra `wazuh-control status` và xử lý dựa trên kết quả. Không
coi riêng một dòng Completed/Started là đã xác nhận API key/quota/indexer.

Nếu chưa nâng từ 0.4.9.2, dùng gói tích lũy
[0.4.10.2 Severity-VT](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.2-Severity-VT-20261021.zip)
thay vì tiny fix này, rồi làm hướng dẫn VT-01 hiện tại từ đầu.

## Kiểm chứng

- 451 tests, không lỗi; 2 test filesystem Windows skip trong cloud.
- Test subprocess thật: control Python kết thúc trong khi daemon-like child
  giữ stdout 5 giây; helper trả về theo PID control, không chờ child đóng pipe.
- Tests cho timeout thật, Ctrl+C trong lúc control còn chạy, native lock sống/
  stale, không kill hoặc khởi động lần hai; VT giữ candidate khi pending,
  restore và giữ lỗi gốc khi restart đã kết thúc nhưng validation thất bại.
- Embedded payload vẫn trong giới hạn command line Windows. Không đổi mức
  severity, XML rules, model, dataset hoặc nội dung bài EICAR.
- Chưa chạy restart thực tế trên Docker Desktop Windows hoặc gọi VT bằng key
  của bạn. Key/quota/FIM→VT→Indexer vẫn cần xác nhận qua VT-01.

[Validation](validation-04102.json).
