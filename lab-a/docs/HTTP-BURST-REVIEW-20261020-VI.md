# HTTP burst 20/10/2026: sửa ID trùng và ghi nhận một MLP false positive

## Kết quả từ capture thật

Nguồn: `http-burst-review.zip`, SHA256
`adb4cdaa3183a32254f442c418a9b53111534fd2821cc45027f24456602f4cc2`.
Session: `20261020T044025Z-live-observe-9d8cc3`.

- Runner hoàn tất 33 GET cố định tới `/soc-lab-health`, cả 33 trả HTTP 200.
- EVE có 33 HTTP, 33 SYN observation và 33 completed flow; 33 prediction.
- Không có 119203 hoặc cửa sổ quét ít nhất 20 cổng/10 giây. Chỉ cổng đích 80.
- Wazuh manager có 7 HTTP summary (119210), 8 summary dưới ngưỡng (119207),
  một model summary possible_attack (119202). Summary không tương đương một
  request: phải đếm prediction/flow riêng. Dashboard người dùng đã hiển thị.
- MLP có 32 quyết định dưới ngưỡng, một false positive trên traffic kiểm soát:
  1/33 = 3,03% trong riêng phiên này. Đây không phải FPR tổng quát hay accuracy.

## Vì sao trace cũ đếm 66 kết nối

Mỗi SYN xuất hiện dưới hai dạng ID, ví dụ:

```text
Suricata native: 1034010540483425
Wazuh decoded:  "1034010540483425.000000"
```

Trong 33 cặp, mọi trường identity khác đều giống nhau; chỉ flow_id và source
refs/event_id khác. Code cũ chấp nhận hai chuỗi khác nhau, làm Correlator và
trace đếm 66. Đây là lỗi chuẩn hóa các view của cùng sự kiện, tách biệt với lỗi
bộ cài trước đó cộng cả eve.json và eve-alerts.json khi kiểm tra PCAP.

Bản sửa chuẩn hóa ID nguyên và chuỗi số nguyên có phần thập phân toàn số 0
thành cùng chuỗi chữ số. Không chuyển qua float, không làm tròn phần lẻ, không
đổi sensor/IP/port/time để gộp các kết nối khác nhau. Float, boolean, phần lẻ
khác 0 và dạng exponent bị từ chối. Generic flow normalizer/feature/model không
thay đổi; chuẩn hóa này chỉ phục vụ SYN evidence/correlation.

Correlator mới gộp hai view và giữ cả source refs. Trace cũng hỗ trợ capture
đã ghi bởi code cũ: chỉ chuẩn hóa trong bộ nhớ, giữ nguyên raw/normalized log,
event IDs lịch sử và báo riêng số view gộp. Replay chính capture đã gửi đạt:

```json
{
  "normalized_syn_observations": 33,
  "observed_connections": 33,
  "normalized_syn_event_ids_read": 66,
  "duplicate_syn_views_merged": 33,
  "expected_minimum_connections": 33,
  "coverage_sufficient": true,
  "distinct_destination_ports": 1,
  "qualifying_port_sweep_windows": 0
}
```

## Cảnh báo MLP 119202

Flow `1034010540483425`, source port 42032 tới TCP/80, là request đầu tiên.
HTTP evidence của cùng flow là GET `/soc-lab-health`, status 200. Model weights
SHA256 `0fcf7de3e1985440b7bfe1b8b6771df08a09837a87fcb7f55a9272316b89982d`.

| Trường | Giá trị |
|---|---:|
| Score lớp BENIGN, cũng là lớp lớn nhất | 0,75806296 |
| Score lớp Bot | 0,24121594 |
| Attack score = 1 - score BENIGN | 0,24193704 |
| Ngưỡng đang dùng | 0,003683865 |
| Quyết định | possible_attack |

Vì score vượt ngưỡng nên 119202 được phát dù argmax là BENIGN. Bridge đã chuyển
đúng quyết định model; sự kiện này là false positive trên request bình thường
được kiểm soát, không phải bằng chứng Bot hoặc tấn công thành công.

Flow này kéo dài 50,381 ms, response có 5 packet/576 byte. 32 flow còn lại có
4 packet/510 byte response; median duration toàn phiên là 0,450 ms. Không thấy
ts_gap/tc_gap trên 33 completed flow. Các khác biệt này gợi ý cần kiểm tra độ
nhạy với biến thiên normal traffic; chưa chứng minh yếu tố nào gây thay đổi
score. ZIP không chứa weights hiện tại để chạy kiểm tra can thiệp lên feature.

Không tăng threshold chỉ để làm phiên test này đạt, không gán prediction làm
nhãn train. Lưu phiên này làm bằng chứng đánh giá. Nếu cải thiện model sau vòng
test, thu các phiên train/validation độc lập gồm normal HTTP với độ trễ, kích
thước response và lần truy cập đầu đa dạng hơn, cùng normal SSH; chọn threshold
trên validation rồi đánh giá bằng các phiên test mới. Tiếp tục đo recall của
attack để tránh giảm báo nhầm bằng cách bỏ sót tấn công.

## Áp dụng bản vá ID

Gói `SOC-AI-Lab-A-v0.4.4-Flow-ID-Fix-20261020.zip` là patch phẳng cho source
0.4.4, gồm cả sửa bộ cài EVE trước đó. Áp dụng sau khi phiên Live đang chạy đã
kết thúc. Giải nén trực tiếp vào `E:\SOC-Lab\AI\SOC-AI-v0.4-research`.

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_lab_recon test_lab_correlation test_recon_diagnostic test_wazuh_realtime test_wazuh_scenarios
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra source chưa đạt.' }
```

Nếu đã cài SID 9900003 thành công, không cần chạy lại setup_recon.py hoặc
setup_wazuh.py. Không đổi weights, threshold, feature contract, venv hay rule
Wazuh. Khởi động lại Live với source mới ở phiên test tiếp theo.

Có thể kiểm tra lại capture cũ tại cửa sổ B bằng report mới, không ghi đè report
ban đầu:

```powershell
$capture = 'E:\SOC-Lab\AI\wazuh-tests\http-burst-recheck-20261020-114021\raw\20261020T044025Z-live-observe-9d8cc3'
$evidence = 'E:\SOC-Lab\AI\wazuh-tests\evidence\http-burst-20261020-114329'
$report = Join-Path $evidence ('wazuh-trace-idfix-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
& $py .\wazuh_trace.py session --capture $capture --operator (Join-Path $evidence 'operator.json') --output $report
```

66 bài kiểm tra liên quan đạt, bao gồm ID lớn hơn 2^53, gộp provenance, thiếu
kết nối vẫn không đạt coverage và không làm tròn ID có phần lẻ. Historical
replay thực tế đạt 33 kết nối, không sửa file bằng chứng. Capture mới trên
Windows cần xác nhận hành vi Live sau cập nhật; model false positive vẫn còn.
