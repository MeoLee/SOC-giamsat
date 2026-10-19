# Train Quality bằng giao diện HTML

Bản 0.4.2 bổ sung các trường `local_loss_fraction`, `patience` và `skip_baseline`
vào form và API dashboard. Trước đó nút Train chưa truyền các tham số Quality,
dù CLI train đã hỗ trợ. Biểu đồ, pause/save, resume và tải model vẫn dùng dashboard
hiện có. Bản cập nhật không thay weights, dataset hoặc thuật toán train.

## Cài cập nhật cho máy đã có 0.4.1

Đợi mọi lượt train đang chạy hoàn tất hoặc tạm dừng và lưu checkpoint. Đóng server
dashboard cũ trước khi chép file; đóng tab trình duyệt không dừng server/worker.
Gói vá giải nén trực tiếp vào `E:\SOC-Lab\AI\SOC-AI-v0.4-research`.

Tải [gói dashboard Quality](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4-Dashboard-Quality-20261019.zip)
và [SHA256](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4-Dashboard-Quality-20261019.zip.sha256).
Gói vá chứa các file đổi so với 0.4.1; máy cài 0.4 đầu tiên cần bản vá Windows
trước hoặc dùng gói đầy đủ 0.4.2. Giữ bản sao `soc_ai/dashboard.py` và
`soc_ai/web/dashboard.html` nếu đã tự chỉnh sửa.

## Mở dashboard trên Windows

Mở **Windows PowerShell trên máy vật lý**, đứng trong source mới. Môi trường CUDA
cũ `.venv` có thể dùng lại sau kiểm tra; không cần tải lại PyTorch nếu nó hoạt động.

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$train = 'E:\SOC-Lab\AI\.venv\Scripts\python.exe'
& $train -c 'import torch, numpy, sklearn, matplotlib; print(torch.__version__, torch.version.cuda); assert torch.cuda.is_available(); print(torch.cuda.get_device_name(0)); print(torch.ones(1).cuda().sum().item())'
if ($LASTEXITCODE -ne 0) { throw 'CUDA/dependencies chưa đạt; không khởi động train.' }
& $train -m soc_ai dashboard --root 'E:\SOC-Lab\AI' --port 8765
```

Mở `http://127.0.0.1:8765/` trên chính máy Windows. Đây là server dashboard,
không phải file HTML mở trực tiếp bằng File Explorer. Giữ cửa sổ PowerShell đó
hoạt động. Nếu trình duyệt còn giữ giao diện cũ, nhấn Ctrl+F5.

Nếu đã cài đầy đủ `.venv-ai04-cuda`, có thể thay interpreter bằng môi trường đó.
Chỉ có file `python.exe` chưa chứng minh venv đã cài đủ; lượt tải PyTorch thất bại
có thể để lại venv dở dang. Kiểm tra import và một phép tính GPU như trên trước.

## Chọn dataset và bắt đầu train trên form

Với dataset đã thu đủ ba phiên HTTP ngày 19/10/2026:

| Trường | Giá trị |
|---|---|
| Thư mục dữ liệu đã chuẩn bị | `E:\SOC-Lab\AI\quality-data\20261019T152751Z-0e65ae\prepared` |
| Thư mục run | Bấm **Run mới** để xóa lựa chọn cũ và tạo thư mục mới tự động |
| Epochs | `30` |
| Batch size | `2048` |
| Thiết bị tính toán | `cuda` |
| Chu kỳ lưu checkpoint | `30` giây |
| Số epoch chờ cải thiện | `7` |
| Tỷ trọng học dữ liệu lab | `0.20` |
| Baseline tuyến tính | **Bỏ qua** |

Nhấn **2 · Bắt đầu train**. Dataset đã chuẩn bị xong nên không bấm chuẩn bị lại.
File cohort không được dùng khi train từ prepared cache. Màn hình hiển thị epoch,
loss, validation F1, checkpoint, biểu đồ và console. Model MLP cũ vẫn được giữ để
benchmark; tùy chọn bỏ qua chỉ áp dụng baseline tuyến tính SGD trong lượt train.

`0.20` dành cho dataset base + local, không dùng cho tập hoàn toàn local. Trình
train vẫn kiểm tra hash, số mẫu local mỗi split và độ đa dạng; giao diện không
bỏ qua các điều kiện dữ liệu. Không coi đủ 120 flow là bảo đảm accuracy.

## Tạm dừng, tiếp tục và đọc kết quả

- Bấm **Tạm dừng và lưu**, chờ trạng thái đã tạm dừng/checkpoint được lưu rồi mới
  đóng server hoặc tắt máy.
- Chọn đúng run rồi bấm **Tiếp tục từ checkpoint**. Backend chỉ truyền `--resume`;
  engine khôi phục policy từ checkpoint, không lấy thay đổi trên form để đổi
  dataset/objective giữa chừng. Chọn run cũ thiếu metadata Quality đặt trường
  local về 0 thay vì kế thừa nhầm 0.20 của run khác.
- Khi hoàn tất, bấm **Kiểm tra mô hình đã xuất** và tải `metrics.json` trên giao
  diện để review local FPR cùng attack recall. Chưa tự đổi model Live.
- Không mở worker CLI và dashboard cùng ghi một run.

## Kiểm chứng bản cập nhật

Kiểm thử gửi POST thật tới dashboard localhost, khởi động worker CPU với dữ liệu
fixture có đánh dấu synthetic và kiểm tra bundle/metrics cuối cùng lưu đúng
Quality 0.20, patience 7, skip-baseline. Các ca khác kiểm tra tham số sai bị từ
chối trước khi khởi động worker và lựa chọn model cũ không kế thừa Quality.
Đây là kiểm thử chức năng, không đo accuracy hoặc xác nhận CUDA trên máy người dùng.
