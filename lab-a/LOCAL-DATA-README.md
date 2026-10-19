# SOC AI — Local Data 0.1

Hai công cụ bổ sung cho project SOC-AI-v0.2 hiện có. Không sửa weights, checkpoint,
normalizer, giao diện hoặc môi trường CUDA. Chạy từ thư mục project bằng Python
của `.venv-infer`; bước nhập/ghép chỉ cần NumPy đã cài.

## Các file

- `import_lab_normal.py`: nhập một capture SSH normal có auth.log đối chiếu.
- `prepare_lab_mix.py`: ghép cache CICIDS gốc và các phiên local độc lập.
- `test_local_data.py`: 16 kiểm thử dữ liệu, nhãn, bản ghi lặp và rò rỉ giữa split.

## Kiểm tra cài đặt

Trong Windows PowerShell mới:

```powershell
Set-Location "E:\SOC-Lab\AI\SOC-AI-v0.2"
$inferPython = "E:\SOC-Lab\AI\.venv-infer\Scripts\python.exe"
& $inferPython -m unittest test_local_data -v
```

## Nhập phiên train hiện tại

```powershell
$capture = "E:\SOC-Lab\AI\lab-data\normal-ssh-train-20261014-095541\capture-20261014T030754444399Z"
$importOutput = Join-Path "E:\SOC-Lab\AI\lab-data\imports" ("normal-train-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff"))
& $inferPython .\import_lab_normal.py --capture "$capture" --role train --output "$importOutput"
```

Capture phải có flows.jsonl và summary.json hoàn tất; thư mục cha phải có
session.json và auth.log. Công cụ đối chiếu từng flow với dòng Accepted SSH theo
IP, cổng nguồn, username và thời gian có timezone (sai số cho phép 2 giây).
Chỉ nhập TCP app_proto=ssh, từ client đến server:22; không nhập chiều ngược,
flow một gói/thời lượng bằng 0/tcp_reuse, thiếu bằng chứng hoặc bằng chứng mơ hồ.

Flow lặp cùng kết nối và khoảng thời gian, có cùng vector đặc trưng, được giữ
một bản. Nếu vector khác nhau cho cùng định danh, cả nhóm bị loại để kiểm tra.
Nhãn là BENIGN dựa trên phiên normal có kiểm soát và bằng chứng đăng nhập.
Một lần đăng nhập thành công không tự chứng minh ý định benign ngoài phiên đó.
Dự đoán AI và Wazuh rule không được dùng làm nhãn hay feature.

Kết quả:

- labeled-flows.jsonl: wrapper có nhãn, role, evidence và flow schema soc-network-flow/0.1.
- report.json: số dòng được chọn/loại, hash và nguồn dữ liệu.

`auth_counts` đếm toàn bộ file auth.log đã copy; `selected_records` chỉ đếm flow
được đối chiếu và thuộc phiên. Nếu selected_records=0, báo cáo complete=false
và lệnh trả lỗi. Chọn output mới cho mỗi lần thử, không ghi đè dữ liệu.

## Validation và test

Thu phiên mới, không sao chép hoặc chia dòng của phiên train. Dùng context
normal-ssh-validation / normal-ssh-test với lab_flow_check.py, chạy các hoạt động
normal có thời lượng và lượng đầu ra khác nhau, copy auth.log, finish bằng
`.venv-infer`. Nhập tương tự với `--role validation` hoặc `--role test`.
Giữ test chưa sử dụng để lựa chọn tham số. Đây là thử nghiệm thích nghi nhỏ;
8 mẫu train không đủ để bảo đảm mô hình hết báo nhầm.

## Ghép cache — chỉ chạy khi đã có đủ ba role

```powershell
& $inferPython .\prepare_lab_mix.py `
  --base-prepared "E:\SOC-Lab\AI\prepared-v01" `
  --local "DUONG_DAN_IMPORT_TRAIN" "DUONG_DAN_IMPORT_VALIDATION" "DUONG_DAN_IMPORT_TEST" `
  --output "E:\SOC-Lab\AI\prepared-lab-v01"
```

Thay các placeholder bằng thư mục import thật. Cache CICIDS gốc được giữ nguyên;
toàn bộ phiên local giữ cùng role. Dùng cùng phiên hoặc cùng flow nhiều lần bị
từ chối, kể cả đổi tên thư mục. Bộ ghép dùng lại cache gốc mỗi lần, không nối
chồng nhiều bản mixed. Định dạng đầu ra tương thích loader training hiện có;
preprocessor vẫn được trainer fit trên split train, không fit trên toàn bộ data.

Dataset có thêm day_names LAB để trainer báo riêng kết quả test local. Tier local
là 2, không giả làm tier ghép nhãn CICIDS strict/near_duration. Các hạn chế của
split CICIDS cũ vẫn được ghi lại. Nhãn CICIDS vẫn mang tính thử nghiệm.

## Training

Chọn prepared directory mới cho một run mới. Resume chỉ dành cho việc tiếp tục
run bị gián đoạn với cùng dữ liệu. Chưa có fine-tune trong gói này.
Nút Prepare của Dashboard hiện dùng pipeline CICIDS; bộ mixed được tạo bằng công
cụ ở trên rồi chọn đường dẫn prepared trong Dashboard.

Gói này chưa sửa lỗi DLL của môi trường CUDA, chưa thay đổi loss/class weights,
chưa thu/import local attack và chưa triển khai live inference. Khi đủ phiên,
cần so sánh với mô hình cũ: số báo nhầm normal local, khả năng phát hiện attack,
kết quả CICIDS và flow ngoài phạm vi. Không nâng ngưỡng chỉ để khớp vài mẫu đã xem.

## Xác minh trước khi phát hành

16 kiểm thử đã đạt trên môi trường phát triển; cú pháp và byte của các file Python
trong ZIP được kiểm tra. Chạy lại kiểm thử trên máy Windows trước khi nhập thật.
