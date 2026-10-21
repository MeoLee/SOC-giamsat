# Nhãn hiển thị DoS — 0.4.13.2

Bản vá chỉ cập nhật cách hiển thị, không thêm Reverse Shell, không sửa weights, threshold hoặc thứ tự lớp đã train.

- Console AI và model_summary gửi Wazuh: predicted_label=DoS; model_predicted_label lưu tên lớp gốc để đối chiếu.
- Inference JSON bổ sung predicted_label_display và class_scores_display; predicted_label/class_scores gốc giữ tương thích model, benchmark và dữ liệu nghiên cứu.
- Biểu đồ AI tạo mới hiển thị DoS, kể cả tên lớp trên confusion matrix/F1/class counts. Không đổi số liệu hoặc kết quả đánh giá.
- Dashboard AI hiển thị log/chuỗi ký tự bằng DoS; mô tả Attack Chain và scenario cập nhật DoS.
- Các alert Wazuh, JSON, ảnh biểu đồ đã lưu trước cập nhật không được viết lại. DoS là nhãn hiển thị theo yêu cầu, không xác nhận tác động dịch vụ hoặc ý đồ.
- Kèm sửa installer đọc trùng EVE 0.4.13.1. Không cần chạy lại installer nếu đã thành công.

Dừng monitor Ctrl+C, đợi kết thúc; đóng dashboard AI local nếu đang chạy. Giải nén ZIP phẳng vào project, import dashboards/soc-ai-attack-chain-unified.ndjson với overwrite, mở lại AI/local dashboard. Không cần setup_wazuh, restart manager, train model hoặc nhập VT key. Rule119202 dùng predicted_label nên tự hiển thị DoS ở alert mới.

PowerShell:
```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$zip = Join-Path $env:TEMP 'SOC-AI-DoS-Display-04132.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.13.2-DoS-Display-20261021.zip' -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
Set-Location $project
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Import dashboard sau giải nén, trước khi bật monitor nếu thuận tiện. Sau READY, thử lại bài hping3 hữu hạn đã dùng. Không đảm bảo model lúc nào cũng dự đoán DoS: kết quả vẫn phụ thuộc flow; không ép model để tạo nhãn. Threat Hunting lọc `rule.id: "119202"` và thời gian sau khi cập nhật. Alert119219 riêng vẫn là bằng chứng SYN pressure, độc lập dự đoán MLP.
