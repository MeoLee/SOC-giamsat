# VT-01 — File mới → FIM → VirusTotal hash report → High trên Wazuh

Đây là **một kịch bản**, gồm đối chứng và EICAR. Không yêu cầu nhập SESSION,
không chạy kịch bản khác cho tới khi bạn yêu cầu. EICAR là file kiểm thử vô
hại, không chạy file và không dùng malware sống.

## 1. Cập nhật và cài severity

Ctrl+C monitor hiện tại, chờ LIVE_DONE. Trong **PowerShell Windows**:

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-Severity-VT-0410.zip'
$url = 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10-Severity-VT-20261021.zip'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_severity_virustotal
if ($LASTEXITCODE -ne 0) { throw 'Test severity/VT chưa đạt; giữ output.' }
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài severity chưa đạt; giữ output.' }
```

ZIP vá phẳng dành cho bản 0.4.9.2 bạn vừa dùng; không có model, key, dataset
hoặc live-config. Bộ cài bridge kiểm tra 15 leaf rules rồi tự restart manager.
Không train lại. Dashboard Attack Chain 0.4.9.2 được giữ nguyên, không import lại.

## 2. Bật FIM có scope và rule của thư mục lab

Vẫn trong PowerShell:

```powershell
& $py .\setup_scenario_fim.py
if ($LASTEXITCODE -ne 0) { throw 'FIM chưa đạt; giữ output.' }
& $py .\setup_scenario_rules.py
if ($LASTEXITCODE -ne 0) { throw 'Scenario rules chưa đạt; giữ output.' }
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Kali-Tools.ps1
if ($LASTEXITCODE -ne 0) { throw 'Helper Kali chưa sẵn sàng.' }
docker exec ubuntu-endpoint tail -n 80 /var/ossec/logs/ossec.log
```

Chờ agent hoàn tất FIM baseline và bắt đầu realtime monitoring trước khi tạo
file. FIM installer giữ scope lab, không theo dõi toàn bộ ổ đĩa hoặc đổi
SSH/PAM. Nếu script báo folder đã có nhưng chưa được quản lý, giữ output và
dừng; không xóa folder để vượt preflight. Bài cần account `soctest` và DVWA
uploads hiện có như lab trước.

## 3. Nhập API key VirusTotal trên máy của bạn

Tạo/đăng nhập tài khoản VirusTotal, vào menu tài khoản → API key để lấy key của bạn. **Không gửi key qua
chat, không gõ key vào command line và không chụp màn hình key.** Chạy:

```powershell
& $py .\setup_virustotal.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài VT chưa đạt; giữ output đã che key.' }
```

Nhập key tại prompt ẩn, Enter. Nếu prompt ẩn không hoạt động trong terminal
của bạn, dừng và đổi sang PowerShell terminal tương tác; không dùng tham số
API key hoặc redirect file/paste key vào chat.

Kỳ vọng `VIRUSTOTAL_CONFIGURED`. Installer backup config riêng mode 0600,
kiểm tra analysisd/integratord và rule 87105, restart rồi đợi Integrator chạy.
Key được lưu trong ossec.conf của manager theo cơ chế native Wazuh; không
được ghi vào project/source ZIP hoặc argv Docker ở host. Backup có thể chứa
secret của cấu hình cũ nên giữ riêng, không upload toàn bộ backup.

Cấu hình chỉ nhận **rule 119253: file mới trong `/var/lib/soc-lab/fim/`**.
Không gửi toàn bộ nhóm syscheck, không gọi API khi sửa/xóa file, không upload
nội dung, không bật Active Response/xóa file. SHA/MD5 có thể là thông tin
nhạy cảm; ở đây chỉ tra cứu hash artifact lab bạn chủ động đưa vào thư mục.

Public API theo tài liệu Wazuh: 4 requests/phút, 500/ngày; kiểm tra quota
thực tế trên tài khoản. Chỉ chạy hai file bên dưới, cách nhau ít nhất 20 giây;
không tạo file hàng loạt hoặc thử lại liên tục khi bị rate limit.

Manager cần DNS/HTTPS tới VirusTotal. Cài thành công chưa chứng minh API key,
quota hoặc FIM→VT→Indexer hoạt động; các bước sau kiểm tra chúng.

## 4. Mở Threat Hunting

Bỏ filter `data.soc_ai_producer`, Chain ID/session của bài AI trước. Lọc:

```text
rule.groups: "virustotal"
```

Đặt Last 15 minutes, refresh 5 giây. Nếu cần xem đầu vào FIM, dùng tab khác:

```text
agent.name: "ubuntu-endpoint" and rule.id: "119253"
```

VirusTotal là luồng native Wazuh, hoạt động cả khi AI monitor chưa bật. Nếu
muốn AI tiếp tục thu session, bật lại `Start-SOC-Monitor.ps1` sau khi mọi bước
cài đã xong; không cài/restart giữa lúc đang đo một bài.

SCP mã hóa nội dung nên không kỳ vọng Suricata đọc được chuỗi EICAR từ packet;
FIM kiểm tra file sau khi đã lưu trên Ubuntu.

Hash report đơn lẻ thiếu source process/phiên tấn công; bản này không tự thêm
node malware vào Attack Chain chỉ vì trùng thời gian/IP. Trước mắt kết quả
file nằm ở Threat Hunting; cần telemetry actor/execution để ghép chain đúng.

## 5. Trong Kali: tạo và chuyển file đối chứng

Ở PowerShell khác:

```powershell
docker exec -it kali-attacker bash
```

Từ đây là **Bash Kali**, gõ từng dòng:

```bash
export TARGET=172.20.0.3
export LABUSER=soctest
export VTID=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')
export VTDIR=$(mktemp -d /tmp/soc-vt.XXXXXX)
python3 /opt/soc-lab/vt_lab_artifact.py --directory "$VTDIR" --kind control --token "$VTID"
scp "$VTDIR/vt-control-$VTID.txt" "$LABUSER@$TARGET:/var/lib/soc-lab/fim/"
```

Nhập password SSH **đúng** của soctest. File control có nội dung text lab,
hash riêng. Kỳ vọng FIM 119253 rồi VT 87103 (hash chưa có record), hoặc 87104
(found nhưng không có positives). Không coi unknown/no positives là chứng
nhận an toàn. Có thể phải chờ FIM/realtime/API/Filebeat/Indexer, không hứa
độ trễ một giây cho API ngoài.

Trong alert VT, kiểm tra `data.virustotal.source.file` đúng tên control và
`data.virustotal.source.alert_id` trỏ về `id` của alert FIM tương ứng.
Nếu chỉ có FIM mà chưa có VT, kiểm tra mục lỗi phía dưới trước khi tiếp tục.

## 6. Chuyển EICAR để kiểm tra High

Chờ ít nhất 20 giây từ lần chuyển control, rồi trong Kali:

```bash
sleep 20
python3 /opt/soc-lab/vt_lab_artifact.py --directory "$VTDIR" --kind eicar --token "$VTID"
scp "$VTDIR/vt-eicar-$VTID.txt" "$LABUSER@$TARGET:/var/lib/soc-lab/fim/"
```

Helper tạo chính xác **68 bytes** chuẩn EICAR, không overwrite hoặc execute.
Nó tạo file trong Kali, tránh phải tải một antivirus test file qua Windows.
Hash kỳ vọng:

```text
MD5    44d88612fea8a8f36de82e1278abb02f
SHA256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Kỳ vọng **119253 → 87105 level 12 → High**. Mở alert 87105 và đối chiếu:

- `agent.name`: ubuntu-endpoint.
- `data.virustotal.source.file`: đúng `vt-eicar-<VTID>.txt`.
- `data.virustotal.source.md5`: hash EICAR ở trên.
- `data.virustotal.source.alert_id`: đúng `id` alert FIM của file này.
- `data.virustotal.found`: 1; `malicious`: 1; `positives` >0; xem `total`,
  `scan_date`, `permalink` và số engines thực tế, không ép một số cố định.
- `rule.id`: 87105; `rule.level`: 12. Ô High tăng theo số alert mới.

Ô Critical **không cần tăng**: đây là thử đường phát hiện file, không phải
malware đã chạy hoặc leo thang thành công. Nếu antivirus chặn/xóa EICAR trước
khi transfer/FIM hoàn tất, ghi lại là blocked/incomplete, không tắt antivirus
để ép bài qua.

## 7. Lưu bằng chứng, kiểm tra lỗi, dọn file

Giữ ảnh alert 119253/87105 và JSON export; liên kết bằng filename/hash và
source.alert_id. `wazuh-logtest` chỉ kiểm tra rule bằng fixture, không thay
thế kiểm chứng live này. Dashboard nhìn thấy đúng alert là bước xác nhận
Indexer/rendering; file alerts.json ở manager chỉ xác nhận manager.

Nếu không có kết quả, chạy tại **PowerShell Windows**:

```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
docker exec single-node-wazuh.manager-1 tail -n 60 /var/ossec/logs/integrations.log
docker exec single-node-wazuh.manager-1 tail -n 80 /var/ossec/logs/ossec.log
```

Không gửi ossec.conf/API key. Đối chiếu:

| Hiện tượng | Cách hiểu |
|---|---|
| Không có 119253 | Chưa xác nhận FIM; xem baseline, path, agent và quyền file |
| 119253 thiếu md5_after/sha1_after | Kiểm tra check_all/hashes; native VT cần hash FIM |
| 87101 | Public API rate limit, dừng và chờ quota |
| 87102 | Key/quyền API không hợp lệ; kiểm tra tại máy, không gửi key |
| 87106 | API timeout; kiểm tra DNS/HTTPS, không gọi dồn |
| EICAR ra 87103/87104 | Chưa đạt kỳ vọng; xác minh đúng bytes/hash và source.file, giữ raw report |
| Manager có 87105 nhưng UI chưa có | Kiểm tra time filter, bỏ filter AI, Filebeat/Indexer; không tạo lại file liên tục |

Sau khi lưu bằng chứng, **Kali Bash** xóa đúng hai file bạn vừa tạo:

```bash
ssh "$LABUSER@$TARGET" "rm -- /var/lib/soc-lab/fim/vt-control-$VTID.txt /var/lib/soc-lab/fim/vt-eicar-$VTID.txt"
rm -- "$VTDIR/vt-control-$VTID.txt" "$VTDIR/vt-eicar-$VTID.txt"
rmdir -- "$VTDIR"
```

File deletion có thể tạo FIM 119252/553; không phải malware mới và không kích
hoạt VT trong cấu hình này. **Dừng tại đây; chỉ sang kịch bản tiếp khi bạn yêu cầu.**

[Xem chính sách severity và nguồn tham khảo](SEVERITY-POLICY-0410-VI.md).
[Kiểm chứng thực sự đã chạy trong cloud](validation-0410.json).
