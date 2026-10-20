# Sửa Live dừng khi ghép mã HTTP dạng số và chuỗi

Bản vá 2026-10-20 cho AI Lab A 0.4.3. Gói Live SQLi Fix cũng chứa bản sửa runner
SSH cùng ngày; không cần cài lại bản vá SSH trước khi áp dụng gói này.

## Hiện tượng và bằng chứng

Trên lab Windows, một request SQLi thử nghiệm trả HTTP 302 đã tạo các rule
119206, 119209, 119210 và các rule Wazuh 31103/86601 trên Dashboard. Sau đó Live
dừng với lỗi:

```text
ERROR: '<' not supported between instances of 'int' and 'str'
```

Đã tái hiện cùng lỗi tại build_web_cases: native Suricata/Apache có status là số
302, trong khi bản ghi EVE được Wazuh giải mã có thể chứa chuỗi "302". Bản ghi
Wazuh đến muộn khiến bộ đếm HTTP status sắp xếp hai kiểu dữ liệu khác nhau.

## Thay đổi

- Chuẩn hóa HTTP status 100–599 thành số nguyên trước khi tạo event identity.
  Bản EVE gốc và bản Wazuh tương đương vì thế vẫn được gộp với đủ source refs.
- Giữ status thiếu là unknown, không điền 0; loại bản ghi có boolean, float,
  chuỗi sai định dạng hoặc status ngoài phạm vi vào correlation-errors.jsonl.
  Các bản ghi hợp lệ tiếp theo vẫn được xử lý.
- Bộ đếm cũng hiểu bản normalized cũ có status dạng chuỗi, cộng đúng các view
  tương đương mà không sửa evidence gốc. Đây là số view bằng chứng, không phải
  số HTTP request duy nhất.
- Không thay model, feature hash, threshold, risk policy, rule Wazuh hay nhãn
  train. HTTP 302 vẫn chỉ là chuyển hướng; SQLi attempt không chứng minh đã khai
  thác thành công. MLP hiện không có lớp SQLi.

## Cài trên Windows

Nếu Live đã tự thoát về PowerShell thì không cần nhấn Ctrl+C thêm. Nếu còn một
Live khác chạy, dừng bằng Ctrl+C một lần và đợi LIVE_DONE. Sao lưu các file
source trước khi giải nén nội dung ZIP trực tiếp vào:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research
```

lab_web.py và lab_correlation.py phải nằm ngay tại root source. Không xóa raw,
outbox, model, venv hoặc sửa trạng thái phiên lỗi thành completed.

Kiểm tra bằng Python CPU hiện có:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_lab_web test_wazuh_scenarios
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra bản vá chưa đạt.' }
```

Sau đó mở Live với `-Case web-sqli-02`, lấy SESSION mới và chạy lại scenario
web-sqli theo WAZUH-REALTIME-VI.md. Cuối phiên nhấn Ctrl+C một lần, đợi LIVE_DONE,
rồi xuất wazuh_trace.py session. Cần xem 119206/119209 cùng session, không có
TypeError mới và capture đóng sạch. Giữ phiên web-sqli-01 làm bằng chứng lỗi;
cảnh báo đã được gửi trước khi dừng không biến phiên đó thành phiên hoàn chỉnh.

## Phạm vi kiểm chứng

Kiểm tra hồi quy phát lại native EVE + Apache trước, rồi bổ sung Wazuh decoded
và full_log sau, xác nhận không dừng và không đếm trùng các view EVE. Cũng kiểm
tra status không hợp lệ, status thiếu và replay dữ liệu normalized cũ. Các
kiểm tra trong cloud không thay thế lượt chạy Live trên Windows của người dùng.
