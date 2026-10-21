# Phát hiện chuỗi hành vi SSH — 0.4.14

Bản này chỉ phát triển hệ thống phòng thủ theo kịch bản người dùng cung cấp. Không cung cấp lệnh thực hiện tấn công, không tạo tài khoản/mật khẩu yếu, không cài listener, không cấp sudo và không cài payload/helper thực thi trên nạn nhân.

## Các hành vi và bằng chứng

| Bước hiển thị | Điều kiện | Giới hạn |
|---|---|---|
| Quét cổng / khám phá dịch vụ | SYN vào nhiều cổng đạt ngưỡng recon hiện có | Một SYN/cổng22 không chứng minh Nmap hoặc malicious recon |
| Tiếp xúc dịch vụ SSH — chưa xác nhận Recon | SYN tới22 trước auth, không trùng source port của auth đã biết, cùng nguồn/đích trong60s | Chỉ thêm ngữ cảnh khi có hồ sơ shell/socket; không gán T1046 hoặc cộng điểm Recon |
| Thử sai mật khẩu nhiều lần | Auth server ghi đủ password failures theo nguồn, host, IP đích, account và cửa sổ cấu hình | Không dựa vào tên công cụ, wordlist, MLP hay reset/timeout |
| Các lần sai mật khẩu — ngữ cảnh | Có failures nhưng chưa đạt ngưỡng | Không gọi brute-force |
| Đăng nhập thành công sau chuỗi thất bại | Accepted sau burst đạt ngưỡng | Không tự chứng minh mật khẩu bị đoán hoặc đăng nhập trái phép |
| Phiên SSH xác thực thành công | Accepted có PID, account, IP/source port, nhưng không có burst đủ ngưỡng | Chỉ thêm trong hồ sơ shell/socket được đối chiếu |
| Reverse Shell — shell gắn socket đi ra | Shell executable thật, stdin/stdout cùng socket TCP ESTABLISHED, /proc ancestry khớp PID SSH Accepted, account/IP/source port khớp, SYN đi ra khớp local/peer IP và port | Chưa xác nhận ý đồ, C2, persistence hay leo thang |

Kịch bản đính kèm quét riêng cổng22: hệ thống không giả vờ đã quan sát quét20 cổng. Nếu không có bằng chứng mạnh hơn, chỉ hiển thị tiếp xúc SSH. Nếu mật khẩu đúng được thử ngay đầu thì có thể không có failures; không ép tạo bước brute-force. Giữ nguyên failure_threshold hiện có (mặc định8); không hạ ngưỡng chỉ để hợp tên kịch bản.

Chuỗi đủ bằng chứng có thể hiện:
**Quét cổng → Thử sai mật khẩu → Đăng nhập thành công → Reverse Shell**.
Chuỗi với một cổng/không đủ failures hiển thị đúng các quan sát thực có, kèm giới hạn.

## Telemetry mới

- `process_observer.py`: collector root-owned, poll /proc mỗi0.25s, ghi `/var/log/soc-lab/process-observer/events.jsonl` và heartbeat mỗi2s. Không ghi argv, password hoặc toàn bộ environment; chỉ đọc SSH_CONNECTION để đối chiếu với auth server.
- Process identity = boot ID + PID + start ticks; ghi executable, real/effective UID, parent identities, FD socket và IP/port.
- Root SSH privilege-separation monitors có thể chặn đọc /proc/exe khi Docker không có CAP_SYS_PTRACE. Chỉ lấy PID trung gian khi UID0, kernel comm thuộc sshd và nằm dưới ancestor có executable sshd được xác minh; sau đó vẫn phải khớp auth log PID/account/source port. Không dùng tên process để xác định shell.
- `lab_process_chain.py`: ghép bằng chứng socket, SYN direction và phiên SSH; giữ nhánh riêng cho các phiên concurrent, không lấy nhãn model làm bằng chứng.
- SYN sử dụng SID9900003 hiện có, theo cả hai hướng. Không cần signature nhận diện payload trong SSH vì payload mã hóa.
- `lab_doctor.py`: kiểm tra source, heartbeat, quyền sở hữu code/log và Wazuh rule119220. Nếu container restart làm collector dừng, Doctor sẽ báo lỗi; chạy lại setup_process_observer trước khi bật monitor.
- Auth parser giữ PID, hỗ trợ dạng publickey `ssh2:` và password `ssh2`.

Giới hạn: IPv4 RFC1918; callback phải về cùng IP nguồn phiên SSH; không hỗ trợ NAT làm thay tuple, IPv6, callback sang bên thứ ba, shell dùng pipe/PTY/socket khác nhau, hoặc process ngắn hơn nhịp polling. Không đủ visibility thì không nâng bằng chứng. Không thêm CAP_SYS_PTRACE, không tắt bảo vệ /proc. Root-owned log không phải audit chống sửa đổi khi host đã bị chiếm root.

## Wazuh và điểm ưu tiên

- Rule119220 level12 (High), chỉ khớp event `reverse_shell_evidence` có đủ bốn cờ: kernel_process_observation, stdin_stdout_same_socket, native_ssh_session_verified, outgoing_syn_verified.
- Không tạo Critical/level15 hoặc khẳng định leo thang từ kịch bản này.
- Base Reverse Shell85; scan đạt điều kiện có bonus10, cap95. Ngữ cảnh một cổng không có recon bonus. Risk là ưu tiên điều tra, không phải xác suất.
- Chain dùng cùng host/IP nguồn/đích, account, PID và source port phiên SSH. Nhánh đồng thời có parent IDs riêng. Cùng scan/episode chỉ tạo quan hệ giả thuyết giữa các nhánh.
- Idle90s vẫn chia episode; singleton tự ẩn, chain nhiều bước được giữ. Gợi ý sau khi tạm lắng là runbook nét đứt, chưa quan sát và không cộng stage/risk.
- Giữ nhãn hiển thị DoS và tích hợp VT/HTTP/SYN trước đó.

## Cài bản cập nhật phòng thủ

1. Dừng monitor bằng Ctrl+C, đợi kết thúc. Đóng dashboard AI local nếu đang mở.
2. Tải ZIP phẳng và giải nén vào project đang dùng:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-SSH-Detection-0414.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.14-SSH-Chain-Detection-20261021.zip' -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

3. Cài rule và collector phòng thủ. `soctest` là tài khoản đã có trong lab; tham số này chỉ kiểm tra account hiện hữu, không tạo hoặc thay password, không giới hạn observer vào account đó. Observer theo dõi mọi phiên SSH non-root phù hợp điều kiện.

```powershell
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài Wazuh rules chưa đạt; giữ output.' }
& $py .\setup_process_observer.py --sensor ubuntu-endpoint --username soctest
if ($LASTEXITCODE -ne 0) { throw 'Cài process observer chưa đạt; giữ output.' }
```

Installer Wazuh tự restart và kiểm tra. Observer có backup code/config, kiểm tra collision/quyền, heartbeat và rollback khi startup thất bại; không chỉnh SSH/PAM/sudo. Không train lại hoặc nhập lại VT key. Không chạy lại installer Suricata nếu SID9900003 đã cài thành công từ bản trước.

4. Wazuh Management → Saved objects → Import `dashboards/soc-ai-attack-chain-unified.ndjson`, bật overwrite. Chỉ dashboard **Attack Chain**, không import các dashboard lịch sử.
5. Bật monitor:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Đợi Doctor/READY. Các phiên SSH tồn tại trước khi bắt đầu thu thập có thể thiếu auth/SYN nên không được ghép đầy đủ. Không thu hồi log cũ và đoán bằng chứng đã thiếu.

## Xem kết quả và chẩn đoán

- Attack Chain → Last15minutes, refresh2–5s, chọn Chain ID xem tên bước → mũi tên, phiên, chứng cứ và chi tiết. `pid`, `process_id`, `effective_uid`, `sshd_pids`, `source_port`, `local_ip/local_port`, `peer_ip/peer_port`, `outgoing_syn_verified` giữ tên thuộc tính tiếng Anh.
- Threat Hunting: `rule.id: "119220"`. Không lọc agent.name=ubuntu-endpoint cho alert bridge mang manager.
- Console `[PROCESS-EVIDENCE]` cho biết đã đối chiếu shell/socket. Không có dòng này chưa đủ kết luận không có hành vi.
- Kiểm tra heartbeat/code/source (read-only):

```powershell
docker exec --user 0 ubuntu-endpoint python3 -c "import sys,json; sys.path.insert(0,'/usr/local/lib/soc-lab'); import process_observer; print(json.dumps(process_observer.check_health()))"
(Get-Content .\live-config.json -Raw | ConvertFrom-Json).correlation |
    Select-Object failure_threshold, failure_window_seconds, chain_idle_seconds
```

Nếu Doctor báo stale/stopped, dừng monitor rồi chạy lại setup_process_observer. Theo dõi permission_denials trong health và service.log nếu /proc hạn chế. Không bỏ qua Doctor bằng cách tự đặt cờ bằng chứng.

## Kiểm chứng và nguồn

Validation được ghi riêng trong `validation-0414.json`. Native fixture dùng SSH thật + shell chỉ phát marker cố định qua socket riêng; không cung cấp bài tấn công hoặc shell tương tác. Kiểm tra /proc, syslog Accepted PID, Suricata SYN và join thực tế; không gọi đây là kiểm thử trên máy Windows/DVWA của người dùng.

- MITRE Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- MITRE Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- MITRE Unix Shell: https://attack.mitre.org/techniques/T1059/004/
- Linux proc PID FD: https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html
- Wazuh rule classification: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
