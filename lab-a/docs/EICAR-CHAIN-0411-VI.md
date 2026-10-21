# 0.4.11 — Quét cổng → chuyển EICAR → bằng chứng VirusTotal

Một dashboard duy nhất có tên **Attack Chain**; giữ ID
`soc-ai-attack-chain-unified-v2`. Import overwrite cập nhật dashboard hiện có,
không tạo một dashboard mới. Threat Hunting tiếp tục giữ các alert thường.

## Phạm vi thay đổi

- Mũi tên xanh: scan đã đủ bằng chứng → nhận EICAR có kiểm chứng qua SSH.
- Bước nhận file ghi source/target IP, SSH source port, account, token, path,
  68 bytes, SHA256/MD5; phải khớp đúng một auth success trong 60 giây trước đó.
- FIM phải là file mới (`119253`), đúng path và cả hai hash. Liên kết với
  receiver trong khoảng -2 đến +60 giây do file được ghi trước record receiver.
- VT phải cùng agent ID/host, path, MD5 và `source.alert_id` trỏ đúng FIM alert.
  Chấp nhận kết quả trễ tối đa một giờ trong cùng capture. Phản hồi VT không
  thêm bước, không đổi thời gian hoạt động cuối, không nối hai episode.
- Cùng file có nhiều nguồn gửi/FIM ID hoặc các VT verdict mâu thuẫn thì không
  tự chọn kết quả để nâng điểm. Không ghép chỉ từ IP/thời gian trùng nhau.
- Điểm base transfer EICAR = 40; VT dương tính liên kết hợp lệ nâng base tối
  thiểu lên 75; có scan trước +10, diversity tối đa +5, cap95. Bài hai bước
  thường đi từ 50 sang85. Đây là mức ưu tiên điều tra của lab; EICAR là file
  thử antivirus, không chứng minh mã độc thực, thực thi hoặc infection.
- Sau idle90s (kiểm thử bằng95s), chain hai bước được giữ và có gợi ý nét đứt.
  Một bước rời thì tự ẩn. Gợi ý là runbook có điều kiện, không phải dự báo MLP,
  không có xác suất đã kiểm định và không cộng vào stage count/risk.

Receiver chỉ nhận đúng mẫu chuẩn EICAR; không nhận đường dẫn tùy ý, không
execute file và không ghi đè file cũ. Đây là instrumentation có kiểm soát,
không phải audit tổng quát/chống sửa log. SCP tùy ý vẫn thiếu bằng chứng liên
kết actor/file, vì vậy bài này dùng SSH stdin với receiver cố định.

## 1. Cập nhật một lần

Dừng AI bằng Ctrl+C, đợi LIVE_DONE. Tải và giải nén **bản vá phẳng**
`SOC-AI-Lab-A-v0.4.11-EICAR-Chain-20261021.zip` trực tiếp vào
`E:\SOC-Lab\AI\SOC-AI-v0.4-research` và ghi đè các file có trong bản vá.
Bản vá dành cho bản 0.4.10.2 đã cài VT thành công; không chứa live-config,
model weights, log hay API key. Không dùng ZIP full để ghi đè cấu hình đang chạy.

PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py .\setup_chain_telemetry.py --username soctest --check-eicar
if ($LASTEXITCODE -ne 0) { throw 'Receiver chưa sẵn sàng; giữ thông báo lỗi.' }
& $py .\setup_attack_chains.py
if ($LASTEXITCODE -ne 0) { throw 'Chưa bật được correlation chain.' }
```

Kỳ vọng `EICAR_CHAIN_READY` và `ATTACK_CHAIN_ENABLED`. Không cài lại VT,
không nhập API key và không restart Wazuh. Installer chỉ cập nhật probe và
bổ sung nguồn endpoint nếu thiếu; cấu hình được backup trước khi ghi.
Nếu FIM directory/Kali helper thiếu, xử lý đúng lỗi trước khi chạy traffic;
không bỏ qua doctor. Bài này giả định VT-01 đã đạt như ở lab của bạn.

Trong Wazuh → Dashboards Management → Saved objects → Import:

1. Chọn `dashboards\soc-ai-attack-chain-unified.ndjson` trong project vừa cập nhật.
2. Bật **Automatically overwrite conflicts**, không chọn tạo bản sao/new IDs.
3. Import5 objects rồi mở **Attack Chain**. Giữ ID cũ, đổi tên và cập nhật nội dung.
4. Bỏ Chain ID/Session filter cũ, chọn Last15 minutes, refresh2–5 giây.

Không import các dashboard Investigation/Shard-fix cũ ở bài này.

## 2. Bật monitor — PowerShell A

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Start-SOC-Monitor.ps1 `
    -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
    -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Đợi READY. Giữ cửa sổ này chạy đến khi có VT và đã quan sát gợi ý. AI vẫn
lưu session tự động; bên tấn công không cần nhập SESSION hay tên kịch bản.

## 3. Một kịch bản — gõ từng dòng trong Bash Kali

PowerShell B:

```powershell
docker exec -it kali-attacker bash
```

Nếu vừa chạy bài khác, chờ95s trước khi bắt đầu một case mới. Trong Kali:

```bash
export TARGET=172.20.0.3
export LABUSER=soctest
export TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
export VTDIR=$(mktemp -d /tmp/soc-chain-eicar.XXXXXX)
python3 /opt/soc-lab/vt_lab_artifact.py --directory "$VTDIR" --kind eicar --token "$TOKEN"
```

Quét34 cổng có giới hạn:

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Trong90s sau scan, chuyển file qua SSH thật và receiver cố định:

```bash
ssh "$LABUSER@$TARGET" "python3 /usr/local/lib/soc-lab/eicar_receiver.py --token $TOKEN" < "$VTDIR/vt-eicar-$TOKEN.txt"
```

Nhập password SSH đúng của soctest. SSH đọc password từ terminal ngay cả khi
stdin được redirect từ file. Kỳ vọng `EICAR_RECEIVED_VERIFIED path=... sha256=...`.
Không dùng SCP thay lệnh này nếu muốn thử bước transfer có liên kết phiên.
Không chạy file. Mỗi lần demo tạo TOKEN mới; receiver không overwrite.

Không phát thêm traffic; giữ monitor chạy. Đợi FIM → VT, có thể mất nhiều
hơn90s do API/Integrator. Kết quả VT trễ vẫn cập nhật đúng bước, không reset
idle. Quota/rate limit có thể làm thiếu report; không tạo file liên tục.

## 4. Đọc kết quả

Bấm Chain ID mới trong **Attack Chain**, kỳ vọng:

`Quét cổng / khám phá dịch vụ → Chuyển file EICAR qua SSH`

- Scan và transfer là **hai bước đã quan sát**; VT là badge/bằng chứng trên
  transfer. Chưa có VT: `awaiting_fim_and_vt`/`awaiting_vt`; đủ liên kết và
  có detections: `detected_test_file`, số detections thực tế, điểm85 cho bài này.
- Hồ sơ chi tiết giữ artifact path, source_port, SHA256/MD5, FIM alert ID,
  VT alert ID/rule/time/detections và evidence IDs để truy vết.
- Sau khi tạm lắng90s: ô vàng nét đứt gợi ý cần theo dõi thực thi/file/process.
  Đây là hành vi có thể cần điều tra tiếp, **chưa xảy ra theo bằng chứng hiện có**.
- Không có Critical từ bài EICAR. Native VT `87105` vẫn level12/High.

Threat Hunting ở tab khác (bỏ filter AI/session ở tab này):

```text
agent.name: "ubuntu-endpoint" and (rule.id: "119253" or rule.id: "87105")
```

Mở `87105`: `data.virustotal.source.file` phải đúng TOKEN,
`data.virustotal.source.alert_id` trùng `id` của FIM119253 và MD5 phải là
`44d88612fea8a8f36de82e1278abb02f`. Không ép số engines bằng66.

Nếu chỉ có scan, kiểm tra receiver có báo thành công và auth Accepted của
đúng account/source_port; nếu transfer có nhưng badge chưa VT, đọc các trạng
thái trên và kiểm tra FIM/VT liên kết. Không nâng severity để che lỗi telemetry.
Nhấn Ctrl+C ở A sau khi thu đủ bằng chứng. Có thể dùng
`manual_chain_review.py` để replay phiên đã đóng; native dashboard delivery
vẫn phải kiểm tra riêng. Bản này không ghép lại file SCP cũ không có receiver.

## Nguồn và giới hạn diễn giải

- [MITRE ATT&CK T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/).
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/):
  mapping mô phỏng cho transfer; EICAR không phải công cụ tấn công thực.
- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/):
  chỉ gợi ý hướng điều tra, không gán bước thực thi từ việc nhận file.
- [Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/):
  biểu diễn hành vi và quan hệ; không phải thứ tự bắt buộc hay bộ dự báo.
- [Wazuh VirusTotal integration](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html).
- [Wazuh4.14.7 native integration source](https://github.com/wazuh/wazuh/blob/v4.14.7/integrations/virustotal.py):
  `source.alert_id`, file và hash làm tham chiếu nguồn; không upload nội dung.
- [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/).

ATT&CK không yêu cầu mọi kẻ tấn công phải scan trước; scan có thể ngoài tầm
quan sát. Không tuyên bố full kill chain, thành công khai thác, infection hoặc
xác suất bước kế tiếp chỉ vì thấy scan + file test. Chính sách điểm là của Lab A.
