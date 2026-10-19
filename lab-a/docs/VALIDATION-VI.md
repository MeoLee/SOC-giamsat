# Phạm vi kiểm chứng — 19/10/2026

## Đã chạy trong cloud

- Baseline source A: 88 tests root đạt; 36 tests core được nhận diện, 34 đạt và hai Windows integration bỏ qua.
- Bản hợp nhất: `python run_checks.py` nhận diện **164 ca: 162 đạt, hai ca Windows bỏ qua**, không có failure/error.
- Python 3.12; torch 2.11.0+cpu, numpy 2.3.5, scikit-learn 1.8.0, matplotlib 3.10.8.
- Tests bao phủ core normalize/features, train/export/golden trên synthetic data; pause/resume và RNG; checkpoint/hash; dashboard qua HTTP local và action token; retry/atomic I/O; live/correlation/web; outbox lỗi gửi/restart và producer feedback guard.
- 11 ca integration bổ sung: config Windows/asset/source ambiguity, replay traversal, ID lớn/IPv6 trong decoded Wazuh EVE, thiếu native timestamp, float ID, late/partial/cross-poll replay với provenance offsets, Doctor chỉ đọc và báo từng lỗi nguồn.

## Chưa được kiểm chứng ở đây

- Hai ca thay file/đường dẫn thật trên Windows: bỏ qua do máy cloud chạy Linux. Các mô phỏng transient lock/atomic retry vẫn đã chạy.
- GPU/CUDA trên RTX 4050; venv thực trên máy Windows.
- Model bundle, dữ liệu, checkpoint thực của người dùng: upload chỉ chứa source. Không có phép đo FPR/recall mới hoặc training model thật.
- Docker endpoint/Suricata/Wazuh/DVWA, capture interface, rules thực đang nạp và pipeline tới indexer/dashboard. Các test vận chuyển/collector chủ yếu dùng mock.
- Cài mới toàn bộ lab từ Compose. Dockerfile hiện chỉ dành cho nhánh batch inference tùy chọn.

## Chạy lại

Tại project, dùng Python có dependencies của `requirements.txt`, cài torch CPU hoặc CUDA phù hợp riêng. Không chép venv Windows sang Linux.

```text
python run_checks.py
python lab_doctor.py --config live-config.json
python lab_doctor.py --config live-config.json --model MODEL_DIRECTORY --runtime --bridge
```

Doctor cuối cần chạy trên máy có containers/model. `checks_passed=true` chỉ áp dụng các kiểm tra được yêu cầu; `lab_end_to_end_verified` luôn false vì công cụ không tạo traffic hay gửi event. Kiểm tra model/golden xác nhận hợp đồng bundle, không xác nhận accuracy.

Tests hoặc Doctor chưa đạt thì giữ log và xem lỗi; không bỏ assertion, không tạo fake weights, không đổi nhãn output để làm kết quả đạt.
