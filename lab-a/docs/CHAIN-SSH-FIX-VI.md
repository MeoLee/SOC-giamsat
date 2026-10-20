# Sửa runner chain: Nmap và mã thoát khi sai mật khẩu SSH

Bản vá 2026-10-20 dành cho source AI Lab A 0.4.3 đang dùng. Không thay model,
ngưỡng, tính điểm, rule Wazuh hay dữ liệu train. Dừng Live bằng Ctrl+C một lần,
đợi LIVE_DONE, sao lưu `wazuh_scenarios.py` rồi giải nén nội dung bản vá vào
`E:\SOC-Lab\AI\SOC-AI-v0.4-research`.

## SSH trả 255 sau một lần nhập sai

Runner cũ chỉ chấp nhận mã 5 của sshpass. Với
`NumberOfPasswordPrompts=1`, OpenSSH có thể kết thúc bằng mã 255 và stderr:

```text
soctest@172.20.0.3: Permission denied (publickey,password).
```

Đã tái hiện bằng OpenSSH server/client và sshpass trên loopback: một prompt trả
255; cho hai prompt thì sshpass trả 5. Bản sửa giữ một prompt mỗi kết nối, nhận
mã 5 hoặc mã 255 kèm dòng từ chối đúng account/IP và có phương thức password.
Mã 255 do connection refused, host key, connection closed hay lỗi khác vẫn dừng;
124 (timeout), 126 (không chạy được binary) và 0 (password sai nhưng đăng nhập
được) đều không được chấp nhận cho bước thử sai. Lỗi không mong đợi được in kèm
exit code và stderr lên console, đồng thời giữ trong operator.json.

`client_outcome: password_rejected` chỉ là kết quả phía client. Tám lệnh client
không chứng minh tám auth failure trên server; báo cáo `wazuh_trace.py session`
vẫn phải đối chiếu auth log thật theo tài khoản, nguồn và thời gian.

Sau khi vá, dùng Live SESSION mới, ví dụ `-Case chain-03`, rồi chạy scenario
`chain` với `--username soctest`. Phiên đã thất bại có marker operation; giữ
nguyên để làm bằng chứng, không xóa marker để chạy lại vào cùng capture.

## Nmap bị Operation not permitted sau khi cập nhật gói Kali

Trường hợp đã quan sát trên lab: `/usr/lib/nmap/nmap` có
`cap_net_bind_service,cap_net_admin,cap_net_raw=eip` và không được Docker cho
thực thi, exit 126. Kiểm tra trước:

```powershell
docker exec -u 0 kali-attacker getcap /usr/lib/nmap/nmap
```

Nếu có các file capabilities như trên, gỡ chúng cho binary này rồi xác nhận:

```powershell
docker exec -u 0 kali-attacker setcap -r /usr/lib/nmap/nmap
if ($LASTEXITCODE -ne 0) { throw 'Không gỡ được capabilities.' }
docker exec kali-attacker nmap --version
if ($LASTEXITCODE -ne 0) { throw 'Nmap vẫn không chạy được.' }
```

Scenario dùng TCP connect `-sT`, không cần file capabilities raw packet. Không
tự gỡ khi getcap không có kết quả; cần xem nguyên nhân khác của exit 126.
Quyền file có thể được package manager đặt lại khi nâng cấp Nmap tiếp theo.

## Xem lỗi thực của một lượt chạy

Trong PowerShell B, dùng đúng đường dẫn operator.json mà runner vừa in:

```powershell
$operatorPath = Read-Host 'Dán đường dẫn operator.json, không thêm ngoặc kép'
$op = Get-Content -LiteralPath $operatorPath -Raw | ConvertFrom-Json
$op.error
$op.steps | Select-Object -Last 1 | ConvertTo-Json -Depth 10
```

Không giảm ngưỡng correlation, không tắt PAM lockout để ép chain thành công.
