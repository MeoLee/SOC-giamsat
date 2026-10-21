# 0.4.9 — Chuẩn bị và cách vận hành bằng Kali Bash

**Cập nhật bộ cài:** áp dụng [bản vá 0.4.9.1](../WAZUH-INSTALLER-FIX-0491-VI.md) trước khi chạy
`setup_wazuh.py` hoặc `setup_scenario_rules.py`; giữ các bước vận hành bên dưới.

Tài liệu dựa trên `kich_ban.txt` người dùng gửi; đã đối chiếu ruleset Wazuh
4.14.7 và mã nguồn Lab A. Đây là bản sửa đề xuất kiểm thử, không phải báo cáo
các cuộc tấn công đã thành công trên máy Windows của bạn.

## Những điểm đã hiệu chỉnh

| Nội dung file gốc | Kết quả đối chiếu / cách dùng |
|---|---|
| 5157 là rule port scan | Không thấy ID này trong ruleset Wazuh 4.14.7 đã đối chiếu. Lab A dùng SYN SID 9900003 rồi đếm **cổng đích khác nhau**, tạo 119203 và chain 119212/119214. |
| SSH brute force luôn là 5712 | 5712 theo các lần thử tài khoản **không tồn tại** qua 5710. Password failures thông thường có thể vào 5760 → 5763; 5720 là nhánh khác. Đọc rule thực tế, không coi mọi lỗi 255/reset là sai mật khẩu. |
| 550 là file mới | 554 là thêm, 550 là thay đổi, 553 là xóa. Custom 119250–119253 chỉ phân loại artifact trong thư mục lab. |
| 2502 là firewall drop | 2502 là syslog authentication failures. Nhóm firewall là 4100; 4101 mặc định có no_log. Custom 119254 cần kernel log thật đã decode và đúng prefix/port. |
| Web flood dùng if_matched_sid 31108 | 31108 level 0 là ignored simple requests. Không dùng làm bộ đếm này. Lab A đếm Apache TSV, chống đếm bản sao, yêu cầu baseline/degradation trước khi nghi DoS. |
| SQLi 200/302 = khai thác | Chỉ chứng minh có request/response. Helper DVWA kiểm tra **kết quả hai cột cố định**, không dump DB. |
| FIM chứng minh web shell/leo quyền/persistence | FIM chỉ chứng minh file thay đổi. Cần log thực thi, actor/session, quyền hiệu lực và kiểm chứng hành động. |
| SSH flow cho biết reverse shell | SSH mã hóa; flow không cho biết command. Probe hiện tại chỉ ghi hai hành động cố định; chưa phải audit mọi tiến trình. |
| DoS rồi SQLi nghĩa là gây nhiễu thành công | Cùng thời gian là giả thuyết liên quan. Chưa chứng minh DoS, mục đích đánh lạc hướng hoặc DB compromise. |

Không cài VirusTotal hoặc Active Response trong bản này. Không dùng msfvenom
hay file ELF độc hại để kiểm tra FIM; file text hoặc PHP probe cố định đã đủ
để kiểm tra đường thu log tương ứng.

## Một lần cập nhật

Dừng Live cũ bằng Ctrl+C, đợi `LIVE_DONE`. Giải nén gói cập nhật tích lũy
`SOC-AI-Lab-A-v0.4.9-Manual-Chain-20261021.zip` trực tiếp vào:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research
```

Không tạo thêm thư mục con. Gói nâng trực tiếp từ 0.4.6 Doctor-Fix hoặc 0.4.8;
không chứa model weights, dataset, credentials hoặc `live-config.json`.

Chạy ở **PowerShell Windows**:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
docker info
if ($LASTEXITCODE -ne 0) { throw 'Mở Docker Desktop/Linux containers trước.' }
& $py -m unittest -v test_chain_episodes test_scenario_research test_lab_campaign test_chain_unified
if ($LASTEXITCODE -ne 0) { throw 'Source test chưa đạt.' }
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Bridge chưa đạt; chưa chạy Live.' }
& $py .\setup_attack_chains.py
if ($LASTEXITCODE -ne 0) { throw 'Cấu hình chain chưa đạt.' }
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Kali-Tools.ps1
if ($LASTEXITCODE -ne 0) { throw 'Cài helper Kali chưa đạt.' }
```

Giữ nguyên MLP và operating threshold. Không train lại để chạy các bài này.
Hai script cài dưới đây **tự restart** thành phần cần thiết sau validation;
không restart thêm trong lúc đang thu dữ liệu.

Nếu làm bài file/PHP, cài FIM và các rule bổ sung:

```powershell
& $py .\setup_scenario_fim.py
if ($LASTEXITCODE -ne 0) { throw 'FIM chưa đạt; giữ output và backup.' }
& $py .\setup_scenario_rules.py
if ($LASTEXITCODE -ne 0) { throw 'Scenario rules chưa đạt; giữ output và backup.' }
docker exec ubuntu-endpoint tail -n 60 /var/ossec/logs/ossec.log
```

Chờ log hoàn tất scan FIM đầu tiên và bắt đầu realtime monitoring trước khi tạo
file. FIM chỉ bổ sung `/var/lib/soc-lab/fim` và DVWA uploads. Không bật theo dõi
toàn `/tmp`, không bật report_changes chứa nội dung file. Thư mục marker mới
root-owned, group `soctest` được ghi để tải file qua SSH; không đổi quyền DVWA
uploads hoặc SSH/PAM. Installer backup ossec.conf, validate trước restart và
restore khi lỗi. File/directory đã tồn tại nhưng không có marker quản lý sẽ
được giữ nguyên và installer dừng để tránh đổi quyền nhầm.

Nếu làm bài 5 bước có probe shell/file, thêm:

```powershell
& $py .\setup_chain_telemetry.py --username soctest
if ($LASTEXITCODE -ne 0) { throw 'Endpoint probe chưa sẵn sàng.' }
```

Không chạy lại `setup_web_lab.py` chỉ để test: nó là bộ dựng Apache/DVWA, không
cần thiết nếu `/soc-lab-health`, Apache TSV và DVWA hiện đã hoạt động.

Kiểm tra cấu hình thực tế, báo cáo không in password/cookie:

```powershell
$report = Join-Path $env:TEMP ('soc-readiness-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
& $py .\scenario_readiness.py --output $report
Write-Host $report
```

Báo cáo readiness chỉ kiểm tra cấu hình/thực thi/readability; chưa xác nhận
live delivery hay packet completeness. Nếu IP container khác 172.20.0.3/.4,
đối chiếu `docker inspect` và assets trước khi chạy các lệnh bên dưới.

## Cập nhật đúng dashboard đang dùng

Saved objects → Import → Automatically overwrite conflicts → chọn:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-attack-chain-unified.ndjson
```

Đúng **5 objects, 1 dashboard**, cùng ID với bản 0.4.8. Mở **SOC Lab A - Attack
Chain**, Ctrl+F5. Nếu còn dashboard Lab A lịch sử, dùng hướng dẫn/script cleanup
trong [bản 0.4.8](../ATTACK-CHAINS-048-VI.md); giữ Threat Hunting native.

Ô xanh/mũi tên liền: bước và liên kết đã quan sát. Mũi tên giữa nhánh và root
chỉ là liên quan theo nguồn/đích/episode, không phải bằng chứng nhân quả.
Ô vàng/mũi tên nét đứt: hướng tiếp theo **chưa quan sát**. Bấm Chain ID để lọc
đúng chain + capture session và xem đầy đủ từng bước bên dưới; click arrow /
cuộn chuột trong sơ đồ khi có nhiều nhánh. Field headers/IDs giữ tiếng Anh.

## Bật monitor một lần

**PowerShell A trên Windows** — lệnh duy nhất để bắt đầu bài:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1
```

Script tự đặt tên `monitor-<timestamp>-<suffix>` và lưu dưới
`E:\SOC-Lab\AI\monitor-sessions`. Model mặc định là model của bạn:
`E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507`. Dùng `-Model 'đường dẫn'`
nếu chuyển model. Chờ **READY**; giữ A chạy. Không cần copy SESSION sang Kali.

**PowerShell B** mở terminal tấn công:

```powershell
docker exec -it kali-attacker bash
```

Từ đây, các lệnh trong nhóm bài là **Bash bên trong Kali**, không phải PowerShell.
Gõ lần lượt và quan sát Dashboard giữa các bước:

```bash
export TARGET=172.20.0.3
export SOURCE=172.20.0.4
export LABUSER=soctest
curl --noproxy '*' --max-time 5 -i "http://$TARGET/soc-lab-health"
```

Health cần 200 và `SOC_WEB_OK`. Có thể giữ monitor qua nhiều bài; không cần
khai báo tên kịch bản hay SESSION cho detector. Collector vẫn có giới hạn
an toàn `max_events` trong cấu hình: đây chưa phải daemon lưu vô hạn. Nếu
collector báo giới hạn/lỗi/gap, dừng, giữ dữ liệu và mở monitor mới; không
coi giai đoạn mất thu thập là không có tấn công.

## Tách các bài và hiểu trạng thái

Mặc định: `chain_idle_seconds=90`, `chain_rescan_gap_seconds=30`, cap episode
900 giây. Hành vi khác IP/target IP/hostname được tách. Đợt scan mới sau khoảng
nghỉ đủ điều kiện hoặc khoảng ngắt ≥90 giây giữa các hành vi liên quan tạo
ranh giới episode; auth/SQLi được rebuild trong episode, tránh nhóm 600 giây
cũ dán nhiều bài vào nhau. Event security không được dùng lại sang chain khác;
baseline HTTP có thể được tham chiếu hỗ trợ riêng, không đếm thành bước mới.

Để thử **hai bài độc lập từ cùng Kali sang cùng Ubuntu**, chờ ít nhất 95 giây
sau hành vi cuối rồi bắt đầu lại bằng Nmap. Không chạy hai bài song song khi
đang đánh giá khả năng tách. Các hành vi cùng IP/đích, cùng khoảng thời gian,
không có session/process evidence để phân biệt vẫn chỉ là giả thuyết liên quan;
không thể cam kết phân biệt hai hacker cùng NAT bằng các log này.

Status: `active` → `waiting` → `quiescent`. Sau 90 giây không còn bằng chứng
liên quan, hiện giả thuyết bước tiếp theo theo từng nhánh terminal. Tạm lắng
**không chứng minh cuộc tấn công kết thúc**; log đến trễ có thể tạo revision
mới. `chain_active` dùng để đánh dấu case còn được giữ, khác với status hoạt
động: case quiescent vẫn nằm trong danh sách và không bị xóa.

Gợi ý là runbook từ bằng chứng, không phải mô hình next-action đã train/hiệu
chỉnh. Không có xác suất % được kiểm định, không ép phải đi đủ mọi bước của
kill chain, không cộng bước giả thuyết vào stage count hoặc risk score.

## Kết thúc và kiểm tra bằng chứng

Xong bài, đợi sensor hoàn tất flow nếu cần xem MLP, rồi Ctrl+C ở PowerShell A
một lần và chờ `LIVE_DONE`. Mở PowerShell mới:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$report = Join-Path $env:TEMP ('manual-chain-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
& $py .\manual_chain_review.py --manager single-node-wazuh.manager-1 --output $report
Write-Host $report
```

Tool tự tìm capture mới nhất trong monitor-sessions; không đọc tên bài từ
attacker để ghép chain. Kiểm tra hashes, raw replay, gap/partial, snapshot và
chain/stage delivery ở manager. Nó **không** xác nhận indexer/rendering hoặc
ý đồ/khai thác thành công. Với bài control chỉ có HTTP bình thường, thêm
`--expect-no-chain`. Nếu output exit 2, giữ report/raw; không sửa cờ complete.

Bằng chứng nằm ở `monitor-sessions\<monitor-name>\raw\<capture-id>`:
`session.json`, `correlation-events.jsonl`, `correlation-cases.json`,
`live-activities.jsonl`, `ai-predictions.jsonl`, raw auth/EVE/Apache/Wazuh,
và outbox. Session là provenance của collector, không phải tên chuỗi bắt buộc.
Một capture có thể có nhiều Chain ID độc lập.

## Nguồn chính

- [Wazuh 4.14.7 SSH rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0095-sshd_rules.xml)
- [FIM rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0015-ossec_rules.xml), [FIM configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)
- [Web rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0245-web_rules.xml), [firewall rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0900-firewall_rules.xml)
- [Suricata thresholding](https://docs.suricata.io/en/latest/rules/thresholding.html): volume là dấu hiệu, không tự chứng minh scan/DoS.
- [MITRE Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow), [ATT&CK](https://attack.mitre.org/): biểu diễn kỹ thuật/nhánh, không cung cấp công thức risk hoặc thứ tự bắt buộc.
