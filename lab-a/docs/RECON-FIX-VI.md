# AI Lab A 0.4.4: phân biệt SYN burst và quét nhiều cổng

**Cập nhật sau kiểm thử Live:** [phân tích HTTP burst, sửa flow ID bị Wazuh thêm
`.000000` và ghi nhận một MLP false positive](HTTP-BURST-REVIEW-20261020-VI.md).
Ca HTTP đã không còn 119203. Sửa ID không thay weights hoặc threshold MLP.

## Vấn đề được xác nhận

Lượt HTTP burst kiểm soát tạo 33 GET bình thường tới cổng 80, đều HTTP 200 và
33 flow đều được MLP đánh giá BENIGN. Rule 9900001 rev 2 vẫn tạo cảnh báo vì
`threshold:type both, track by_both, count 20, seconds 10` đếm số lần khớp SYN
theo cặp IP; nó không đếm số cổng đích khác nhau. Correlation cũ tin rule này
và tạo 119203, nên phần sensor/correlation đã báo nhầm reconnaissance.

## Bản sửa hoạt động thế nào

- Thay đúng rule 9900001 đã được người dùng cung cấp bằng rule thu quan sát SYN
  9900003, loại misc-activity. Giữ các rule SQLi và rule khác trong cùng file -S.
- Correlation đếm ít nhất 20 cổng TCP đích khác nhau trong cửa sổ trượt 10 giây,
  cùng nguồn, IP đích và sensor. Nhiều kết nối tới 80/443/22 không đủ điều kiện.
- Dùng timestamp packet trong EVE và giữ các event ID/source refs thật. Bản
  Wazuh giải mã được chuẩn hóa và gộp với EVE, không tăng số cổng vì nhiều view.
- Phát 119203 khi đạt ngưỡng, không đợi completed flow hoặc MLP. Mỗi cửa sổ
  chỉ tạo một proof để tránh nhân đôi cảnh báo và tăng bộ nhớ theo bình phương.
- 9900001 cũ chỉ là chỉ báo tần suất SYN khi replay; nó không tự tạo case recon
  hoặc tăng điểm chain. Các capture cũ thiếu 9900003 không chứng minh được bản
  sửa đã hoạt động: cần kiểm thử lại với rule mới.
- Quan sát SYN không được bridge đẩy thành 119209 mức cảnh báo. Wazuh native
  có thể vẫn ghi các observation ở mức thông tin. SQLi và chữ ký tấn công khác
  vẫn dùng 119209; port scan sau bản này cần kiểm tra 119203.
- Các trường trên case: distinct_destination_ports, destination_port_sample,
  port_threshold, port_window_seconds và recon_detection_method. Số cổng là số
  quan sát tại cửa sổ kích hoạt; không phải tổng mọi cổng trong toàn phiên.
- Điểm recon vẫn 40, chain/SQLi giữ chính sách điểm hiện có. Model, feature hash,
  threshold MLP và dữ liệu train không thay đổi. Context completed-flow vẫn ở
  shadow; đây là nhánh SYN riêng của correlation.

Hai tham số correlation có mặc định `recon_port_threshold=20` và
`recon_port_window_seconds=10`. Chúng tách biệt với `context.port_threshold` /
`context.port_window_seconds` của nhánh completed-flow shadow. Không cần sửa
live-config.json để dùng mặc định mới.

## Cài bản vá

Dừng Live, chờ LIVE_DONE. Giải nén nội dung bản vá trực tiếp vào
`E:\SOC-Lab\AI\SOC-AI-v0.4-research`. Gói vá từ 0.4.3 cũng chứa các bản sửa SSH
và HTTP status trước đó. Giữ model, venv, raw và bằng chứng cũ.

Trong PowerShell B:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_lab_recon
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra source chưa đạt.' }
& $py .\setup_recon.py --container ubuntu-endpoint
if ($LASTEXITCODE -ne 0) { throw 'Cài rule chưa đạt; giữ toàn bộ lỗi.' }
```

Installer kiểm tra Suricata -T, chạy PCAP cô lập rồi dùng chính detector Python
trên kết quả EVE: scan 32 cổng phải khớp; HTTP 33 request và single-port 24 lần
không tạo recon; hai mẫu SQLi vẫn phải khớp. Sau đó mới backup, thay file nguyên
tử và yêu cầu hot reload SIGUSR2. Lỗi validation không thay file đang chạy;
rule khác mẫu đã review hoặc trùng SID bị từ chối. Backup nằm cạnh file rule,
dạng soc-lab.rules.before-recon-<timestamp>, quyền 600.

Cần thấy RECON_PCAP_VALIDATED và SURICATA_RECON_RULES_VALIDATED_AND_RELOAD_REQUESTED.
Đây là kiểm tra PCAP và yêu cầu reload; vẫn cần ca Live dưới đây để chứng minh
rule mới đang tạo quan sát trên interface thật. Doctor/Live kiểm tra file rule
mới có mặt trước khi chạy, không coi việc đó là bằng chứng capture hoạt động.

Không phải train lại hoặc chạy setup_wazuh.py: bridge hiện tại đã có rule 119203.

## Sửa lỗi bộ cài cộng trùng hai EVE output

Báo cáo `recon-diagnostic-20261020-110212.json` xác nhận lab ghi cùng alert vào
`eve.json` và `eve-alerts.json`. Bộ cài cũ đọc glob `eve*.json`, nên nhóm scan
được đếm 64 alert cho 32 kết nối, HTTP 66 cho 33, SSH 48 cho 24. Mỗi file riêng
có đúng 92 alert SYN và hai alert SQLi. Lỗi nằm ở bước đọc kết quả PCAP của bộ
cài; người dùng chưa cần mở Live ở bước này.

[Bản vá bổ sung cho máy đã có 0.4.4](../../downloads/SOC-AI-Lab-A-v0.4.4-EVE-Installer-Fix-20261020.zip)
đổi bộ cài sang kiểm tra riêng `eve.json`, đúng nguồn Live đang đọc. Giữ nguyên
hai EVE output, YAML và rule SQLi. Vẫn kiểm tra chính xác 32/33/24 quan sát trong
nguồn này; không gộp/xóa bản ghi trong nguồn để làm kiểm tra đạt. Thiếu `eve.json`,
thiếu SYN hoặc thừa SYN trong chính file đó vẫn làm cài đặt dừng.

Giải nén gói vá trực tiếp vào `E:\SOC-Lab\AI\SOC-AI-v0.4-research`, ghi đè source,
rồi chạy `test_lab_recon test_recon_diagnostic` và `setup_recon.py` như sau:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_lab_recon test_recon_diagnostic
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra source chưa đạt.' }
& $py .\setup_recon.py --container ubuntu-endpoint
if ($LASTEXITCODE -ne 0) { throw 'Cài rule chưa đạt; giữ toàn bộ output.' }
```

Gói vá này dành cho source 0.4.4 đã giải nén; không cần cài lại các gói cũ, train
lại hoặc restart Wazuh. Cần thấy `RECON_PCAP_VALIDATION_SOURCE: eve.json`,
`RECON_PCAP_VALIDATED` và `SURICATA_RECON_RULES_VALIDATED_AND_RELOAD_REQUESTED`.
Sau đó mới mở Live và kiểm thử HTTP burst/quét cổng bên dưới.

## Chẩn đoán lỗi PCAP khác

Nếu unit test đạt nhưng installer dừng ở
`PCAP SYN count differs from known generated attempts`, rule đang chạy chưa
được thay: lỗi xảy ra trước backup, atomic replace và SIGUSR2. Không bỏ điều
kiện kiểm tra này hoặc coi đây là cài thành công. Thông báo cũ chưa chỉ rõ nhóm
scan/HTTP/single-port nào bị lệch và số lượng thực tế, nên chưa đủ để kết luận
nguyên nhân trên máy người dùng.

Helper bổ sung `diagnose_recon.py` chạy cùng PCAP và candidate rule với YAML
hiện tại, chỉ trong thư mục tạm. Nó không gọi installer thay rule, không gửi
signal/restart và không phát traffic tới lab. Chạy sau khi tải helper vào cùng
thư mục source 0.4.4:

```powershell
& $py .\diagnose_recon.py --container ubuntu-endpoint --output 'E:\SOC-Lab\AI\wazuh-tests\recon-pcap-diagnostic.json'
if ($LASTEXITCODE -ne 0) { throw 'Chẩn đoán chưa hoàn tất; giữ output và JSON nếu có.' }
```

JSON cho biết từng nhóm kỳ vọng 32/33/24 kết nối, số alert, số kết nối duy nhất,
cổng thiếu, kết nối lặp và số alert theo từng file EVE. Chẳng hạn hai EVE output
cùng ghi alert có thể làm số bản ghi gấp đôi trong khi số kết nối giữ nguyên;
đây chỉ là một khả năng để phân biệt bằng dữ liệu, không phải kết luận cho lab.
`live_rules_unchanged=true` và `reload_requested=false` xác nhận helper không
cài rule. Exit code 0 chỉ cho biết đã thu chẩn đoán; phải đọc các số trong JSON.
Helper vẫn cộng các output để chỉ ra bản ghi trùng; `all_counts_and_ports_match`
của helper không phải kết luận cài đặt. Bộ cài đã sửa kiểm tra riêng `eve.json`.
Không cần gửi model, mật khẩu hoặc toàn bộ EVE thật để chẩn đoán PCAP mẫu này.

## Kiểm thử lại hai ca độc lập

PowerShell A, bắt đầu HTTP burst:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Wazuh-Live.ps1 -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' -Case http-burst-02
```

Đợi READY, lấy SESSION mới. PowerShell B:

```powershell
$capture = Read-Host 'SESSION của http-burst-02, không thêm ngoặc kép'
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('http-burst-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $py .\wazuh_scenarios.py run --scenario http-burst --capture $capture --output $evidence
if ($LASTEXITCODE -ne 0) { throw 'Scenario chưa hoàn tất.' }
```

Kết thúc kịch bản, Ctrl+C một lần tại A, chờ LIVE_DONE, rồi B:

```powershell
& $py .\wazuh_trace.py session --capture $capture --operator (Join-Path $evidence 'operator.json') --output (Join-Path $evidence 'wazuh-trace.json')
```

HTTP cần có 119210, không có 119203. Báo cáo phải có unexpected_rule_ids rỗng,
recon_observation_coverage.coverage_sufficient true, distinct_destination_ports
bằng 1 và qualifying_port_sweep_windows bằng 0. Không suy ra thành công chỉ vì
không thấy cảnh báo: coverage kiểm tra số kết nối SYN thực đã chuẩn hóa trong
đúng source/target/time window so với số request runner thực sự phát. Điều này
vẫn không chứng nhận packet capture đầy đủ hoặc accuracy tổng quát.

Sau khi đóng ca HTTP, PowerShell A mở phiên mới với `-Case port-scan-02`.
Trong B dùng SESSION mới, evidence directory mới và `--scenario port-scan`:

```powershell
$capture = Read-Host 'SESSION của port-scan-02, không thêm ngoặc kép'
$evidence = Join-Path 'E:\SOC-Lab\AI\wazuh-tests\evidence' ('port-scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $py .\wazuh_scenarios.py run --scenario port-scan --capture $capture --output $evidence
if ($LASTEXITCODE -ne 0) { throw 'Scenario chưa hoàn tất.' }
```

Cần thấy 119203 khi đang quét, distinct_destination_ports ít nhất 20 trong
port_window_seconds=10, risk_score=40. Đóng và xuất trace như ca HTTP. Không
đòi 119209 cho các quan sát SYN. single-port là ca đối chứng bổ sung: 24 kết
nối đến 22 cũng không được tạo 119203; SSH auth/MLP đánh giá riêng.

## Phạm vi xác minh

Đã chạy installer hai lần trong container cô lập dùng Suricata 8.0.3 thật,
image jasonish/suricata@sha256:3f7b2f06e4667e4149deb34c52f278213a4a9b74bf926939aa5cbfc6c595dca0.
Suricata -T, PCAP dương/đối chứng, bảo toàn SQLi và yêu cầu hot reload đã đạt.
Đã quan sát log daemon hoàn tất reload trong kiểm tra này. Đây không phải kết
quả cài trên Windows lab người dùng hoặc bằng chứng Wazuh Dashboard của bản mới.

Bản sửa bộ cài EVE đã tái hiện lỗi cũ bằng cấu hình ghi alert vào hai file
`eve.json` và `eve-alerts.json` trên Suricata 8.0.3. Bộ cài mới đạt hai lần liên
tiếp với cấu hình mặc định và hai lần với hai EVE output; cả bốn lần đều hoàn
tất hot reload, giữ rule SQLi và đạt PCAP dương/đối chứng. 21 bài kiểm tra recon
và chẩn đoán đạt, gồm hồi quy không dùng mirror để che thiếu/thừa bản ghi trong
nguồn chính. Việc cài và hai ca Live trên Windows vẫn cần được người dùng chạy.
