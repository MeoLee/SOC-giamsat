# Training Dashboard — Hướng dẫn huấn luyện và kiểm tra kết quả

Tài liệu dành cho giao diện **Training Dashboard** đã cập nhật, sử dụng backend `soc_ai.dashboard` của project SOC-AI-v0.4-research. Phạm vi kết thúc tại huấn luyện, đánh giá và xuất/kiểm tra model. Đây là giao diện training, khác Wazuh Dashboard và dashboard Attack Chain.

## 1. Chuẩn bị

Cần có:

- Toàn bộ nguồn Python, đặc biệt thư mục `soc_ai/` và `soc_ai/web/dashboard.html`.
- Môi trường Python có các dependency phù hợp: PyTorch, NumPy, scikit-learn, Matplotlib và các dependency đi kèm của bản nguồn.
- Dữ liệu cohort hợp lệ **hoặc** một bộ dữ liệu prepared hoàn chỉnh.
- Thư mục đầu ra có quyền ghi và đủ dung lượng cho run/checkpoint.
- GPU NVIDIA tương thích nếu chọn `cuda`; nếu không, chọn `cpu`.

**Chỉ có mã nguồn và model đã xuất thì có thể xem/kiểm tra model, nhưng chưa đủ để train lại.** Muốn train, phải cung cấp dataset/prepared riêng. Dataset không tự có trong image AI suy luận hoặc file HTML.

Các đường dẫn dưới đây theo máy lab hiện tại; đổi theo vị trí trên máy triển khai. Đường dẫn giao diện nhập là đường dẫn mà **backend Python đang chạy** truy cập được, không phải đường dẫn do trình duyệt tải lên.

## 2. Mở giao diện

### 2.1. Chạy backend bằng PowerShell

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'

& $py -m soc_ai dashboard --root 'E:\SOC-Lab\AI' --port 8765
```

Giữ terminal mở, rồi truy cập:

```text
http://127.0.0.1:8765
```

Không mở `dashboard.html` bằng double-click để train. File HTML cần API của backend; mở bằng `file://` có thể hiện “Mất kết nối”. Không cần chạy AI live hoặc các container Wazuh để thực hiện training từ bộ dữ liệu đã có.

Nếu dùng môi trường GPU đã cài sẵn, thay `$py` bằng Python của môi trường đó. Backend và tác vụ training sử dụng cùng interpreter; chọn CUDA trên form không tự cài PyTorch CUDA.

### 2.2. Kiểm tra GPU khi cần

Trong terminal khác, khai báo đúng `$py` rồi chạy:

```powershell
& $py -c "import torch; print('PyTorch:', torch.__version__); print('CUDA available:', torch.cuda.is_available()); print('GPU:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU only')"
```

- `CUDA available: True`: có thể chọn `cuda` nếu bộ dependency hoạt động phù hợp.
- `False`: chọn `cpu` hoặc chuẩn bị đúng môi trường CUDA trước; không bấm train CUDA rồi coi lỗi thiết bị là lỗi dataset.

Nếu vừa thay HTML, nhấn **Ctrl+F5**. Thay HTML không thay đổi thuật toán hoặc default của backend.

## 3. Các vùng chức năng

| Vùng | Cách sử dụng |
|---|---|
| Cấu hình phiên làm việc | Chọn dữ liệu, thư mục run và hyperparameter |
| Các nút thao tác | Prepare, train, pause, resume, verify và run mới |
| Epoch / Batch / Train loss / Validation macro F1 | Theo dõi tiến độ và chỉ số đang hiển thị |
| Hoạt động hiện tại | Trạng thái, phần trăm epoch và checkpoint gần nhất |
| Biểu đồ học | Train/validation loss và validation macro F1 của các epoch đã hoàn tất |
| Báo cáo test | Chỉ số binary và bảng precision/recall/F1/support từng lớp |
| Biểu đồ báo cáo có đánh số | Xem/tải ảnh PNG, SVG |
| Nhật ký xử lý | Đọc output chi tiết và nguyên nhân lỗi |
| Quy trình thực hiện | Bảy bước, kết thúc tại xuất và kiểm tra model |

Bảy bước là: **Chuẩn bị dữ liệu → Nạp dữ liệu train → Huấn luyện → Validation mỗi epoch → Đánh giá test → So sánh baseline → Xuất và kiểm tra mô hình**. Baseline phụ thuộc lựa chọn chạy/bỏ qua. Training và validation lặp lại theo epoch, không phải mỗi mục chỉ chạy một lần.

## 4. Nhập cấu hình đúng

| Trường | Ý nghĩa và lưu ý |
|---|---|
| File dữ liệu cohort (JSONL) | Đầu vào cho nút chuẩn bị dữ liệu; phải đúng schema mà project hỗ trợ, không phải mọi CSV/JSONL đều dùng trực tiếp được |
| Thư mục dữ liệu đã chuẩn bị | Đường dẫn bộ prepared dùng để train; nếu prepare mới, chọn thư mục đầu ra chưa tồn tại |
| Thư mục run | Chọn thư mục mới chưa tồn tại, hoặc để trống để backend tạo trong `ROOT/runs/` |
| Các run gần đây | Chọn run đã có để xem báo cáo, verify hoặc resume nếu có checkpoint |
| Epochs | Số epoch tối đa; early stopping có thể dừng sớm |
| Batch size | Số mẫu mỗi minibatch; batch cuối có thể nhỏ hơn |
| Thiết bị tính toán | `cuda` hoặc `cpu`, phải phù hợp interpreter đang chạy backend |
| Chu kỳ lưu checkpoint | Ngưỡng thời gian kiểm tra lưu checkpoint; không bảo đảm khoảng cách lưu đúng tuyệt đối |
| Số epoch chờ cải thiện | Patience của early stopping theo tiêu chí chọn model |
| Tỷ trọng học dữ liệu lab | Local loss fraction; 0 ≤ giá trị < 0.5, không phải tỷ lệ chia train/test |
| Baseline tuyến tính | Chọn train thêm để đối chiếu hoặc bỏ qua; khác model MLP cũ |

### 4.1. Cấu hình tham chiếu của run cuối

Run: `mlp04-quality-20261019-232507`.

| Trường | Giá trị |
|---|---|
| Prepared | `E:\SOC-Lab\AI\quality-data\20261019T152751Z-0e65ae\prepared` |
| Epochs | 30 |
| Batch size | 2048 |
| Thiết bị | cuda — run cũ dùng NVIDIA GeForce RTX 4050 Laptop GPU |
| Patience | 7 |
| Checkpoint | 30 giây |
| Local loss fraction | 0.20 |
| Baseline tuyến tính | Bỏ qua |
| Thư mục run cho lần mới | Để trống hoặc đặt một tên mới, không ghi vào run cuối đã lưu |

Đây là thông số của lần chạy đã có metadata, không phải mặc định giao diện. Khi chạy mới, kiểm tra lại tất cả ô: UI mặc định có thể là 20 epochs, patience 5, local fraction 0 và chạy baseline. Cùng thông số không bảo đảm trọng số/metric giống tuyệt đối khi đổi dữ liệu, môi trường hoặc phần cứng.

## 5. Chọn một trong hai cách chuẩn bị dữ liệu

### Cách A — Dùng lại prepared hoàn chỉnh

Khuyến nghị nếu đã có đúng bộ prepared cần sử dụng.

1. Điền đường dẫn vào **Thư mục dữ liệu đã chuẩn bị**.
2. Kiểm tra thư mục chứa dữ liệu và `report.json` hoàn chỉnh.
3. Backend cần đọc được bộ này. Nếu trạng thái chưa cập nhật theo đường dẫn vừa nhập, tải lại trang sau khi cấu hình được lưu bằng thao tác hợp lệ; không bấm Prepare vào thư mục prepared đã tồn tại để ép cập nhật.
4. Khi giao diện xác nhận dữ liệu sẵn sàng, tiếp tục cấu hình run và train.

Backend lưu lựa chọn trong `ROOT/dashboard-session.json`. Nếu đang chọn một run cũ, prepared có thể được phục hồi từ metadata của run đó. Có thể chọn run đã dùng đúng prepared qua **Các run gần đây**, rồi bấm **Run mới** để giữ cấu hình nhưng bỏ đường dẫn run cũ.

Không chỉ chép riêng `report.json` để giả lập bộ prepared; cần toàn bộ dữ liệu tương ứng.

### Cách B — Prepare mới từ cohort

1. Nhập đường dẫn cohort JSONL hợp lệ.
2. Chọn thư mục prepared đầu ra **mới, chưa tồn tại**.
3. Bấm **1 · Chuẩn bị dữ liệu**.
4. Theo dõi tiến độ và **Nhật ký xử lý**.
5. Chờ thông báo dữ liệu sẵn sàng; không train khi prepare chưa hoàn tất.

Nút này gọi luồng prepare tiêu chuẩn từ cohort. Nó không tự thu traffic lab, tự gán ground truth hay tự tạo bộ Quality từ các folder log bất kỳ. Muốn tái lập bộ Quality, phải dùng các script chuẩn bị dữ liệu tương ứng của project và giữ đúng khai báo session train/validation/test; sau đó mở prepared đã tạo.

## 6. Bắt đầu train một run mới

1. Xác nhận prepared đúng bộ dữ liệu cần dùng.
2. Bấm **Run mới** nếu đang xem run cũ. Nút này xóa ô đường dẫn run, không tự reset toàn bộ hyperparameter.
3. Để ô **Thư mục run** trống hoặc nhập đường dẫn mới chưa tồn tại.
4. Kiểm tra epochs, batch, thiết bị, patience, checkpoint, local fraction và baseline.
5. Với bộ ghép gốc + local tương ứng run Quality, dùng `0.20` theo cấu hình tham chiếu. Với chế độ thường hoặc hoàn toàn local, không tự áp dụng 0.20; kiểm tra contract/chính sách của bộ dữ liệu.
6. Bấm **2 · Bắt đầu train**.
7. Theo dõi trạng thái; không mở thêm một job trên cùng backend/run.

Backend tạo run dạng `ROOT/runs/mlp04-...` hoặc `ROOT/runs/mlp04-quality-...` khi bỏ trống tên. Train mới vào thư mục đã tồn tại sẽ bị từ chối. Không xóa run cũ chỉ để vượt qua lỗi này.

## 7. Theo dõi quá trình học

### 7.1. Đọc các số trên màn hình

- **Epoch**: epoch đang chạy so với số tối đa.
- **Batch / epoch**: minibatch hiện tại trong epoch.
- **Train loss**: loss đang ghi nhận; không phải tỷ lệ dự đoán sai trực tiếp.
- **Validation macro F1**: chỉ số của epoch đã hoàn tất gần nhất đang hiển thị; không nhất thiết bằng chỉ số của best epoch.
- Thanh tiến độ là tiến độ epoch; hoàn tất 100% một epoch chưa đồng nghĩa hoàn tất toàn bộ training/export.

### 7.2. Đọc biểu đồ

| Quan sát | Cách diễn giải |
|---|---|
| Train và validation loss giảm, F1 tăng | Dấu hiệu thuận lợi; vẫn phải kiểm tra per-class và test |
| Train loss giảm nhưng validation loss tăng kéo dài | Có thể overfit hoặc khác biệt phân phối; xem thêm metric và dữ liệu |
| Loss dao động mạnh | Kiểm tra dữ liệu, batch và môi trường; không kết luận chỉ từ vài điểm |
| Macro F1 cao nhưng một lớp có recall thấp | Mô hình còn bỏ sót lớp đó; số tổng hợp không thay thế phân tích từng lớp |
| Không có điểm epoch đầu tiên | Có thể đang xử lý epoch đầu; xem console và tiến độ batch |

Loss là weighted loss; không so sánh trực tiếp số loss giữa các run đổi dataset/trọng số mà bỏ qua cấu hình. Với Quality, tiêu chí chọn best epoch không chỉ là macro-F1 hiển thị; xem `selection_policy`, `best_selection_score` và các thành phần trong metadata.

## 8. Tạm dừng, tiếp tục và tắt an toàn

### Tạm dừng

1. Bấm **Tạm dừng và lưu**.
2. Chờ trạng thái **Đã tạm dừng** và xác nhận checkpoint đã lưu.
3. Sau đó mới đóng backend hoặc tắt máy.

Đóng tab trình duyệt không dừng training. Không coi việc bấm Pause là checkpoint đã lưu ngay. Tạm dừng/khôi phục chi tiết áp dụng cho luồng MLP có checkpoint; các bước hậu xử lý có thể phải chạy lại khi resume.

### Tiếp tục

1. Mở backend lại với đúng root.
2. Chọn run cũ trong **Các run gần đây**, hoặc dùng đường dẫn run của backend đã lưu.
3. Xác nhận có `checkpoints/latest.pt` và nút resume được bật.
4. Bấm **Tiếp tục từ checkpoint**.

Resume khôi phục cấu hình và trạng thái huấn luyện đã lưu, không phải một run mới với các ô vừa chỉnh tùy ý. Sau khi chọn run, giao diện có thể nạp lại tham số từ metadata. Không cần prepare lại nếu dữ liệu cũ còn đầy đủ và đúng contract.

## 9. Chờ đánh giá và xuất model hoàn tất

Sau training/early stopping, hệ thống còn thực hiện đánh giá, baseline nếu bật, xuất file và verify. Chờ trạng thái hoàn tất; không dừng khi vừa xong epoch cuối.

Kiểm tra:

- Trạng thái hoàn tất, không có traceback trong console.
- Báo cáo test xuất hiện.
- File model/metrics xuất hiện trong run.
- Có thể bấm **Kiểm tra mô hình đã xuất**.

Model được xuất từ best epoch theo selection policy, không mặc định lấy epoch cuối. Run tham chiếu có best epoch 30, nhưng run mới có thể chọn epoch khác.

## 10. Đọc Báo cáo test

### 10.1. Bảng từng lớp

| Chỉ số | Ý nghĩa |
|---|---|
| Precision | Trong các dự đoán thuộc lớp này, tỷ lệ đúng là bao nhiêu |
| Recall | Trong các mẫu thật thuộc lớp này, tỷ lệ được nhận ra |
| F1 | Trung bình điều hòa của precision và recall |
| Số mẫu / support | Số mẫu thật của lớp trong tập đánh giá |

Một lớp không có support không cung cấp bằng chứng về chất lượng phát hiện lớp đó. Luôn xem lớp hiếm và false positives của BENIGN, không chỉ accuracy hoặc macro F1.

Tên hiển thị **DoS** trên UI có thể tương ứng nhãn nội bộ/dataset **DDoS**. Việc đổi tên hiển thị không đổi nhãn training hay biến model thành detector được xác minh cho mọi dạng DoS.

### 10.2. Chỉ số binary attack

- Attack precision: cảnh báo attack có bao nhiêu trường hợp thật sự attack theo nhãn đánh giá.
- Attack recall: nhận ra bao nhiêu mẫu attack thật.
- Benign false positive rate: bao nhiêu mẫu BENIGN bị đánh dấu attack.

Binary decision sử dụng tổng xác suất non-BENIGN so với threshold trong model, không nhất thiết giống lớp có xác suất cao nhất. Vì vậy có thể gặp nhãn argmax BENIGN nhưng binary decision là possible_attack.

Không chỉnh threshold theo test rồi dùng chính test đó để tuyên bố chất lượng độc lập. Test nội bộ cũng không tự chứng minh hiệu quả trên các phiên lab chưa từng thấy.

### 10.3. So sánh nhiều run

Giữ cố định bộ dữ liệu/split và ghi rõ môi trường, cấu hình, best epoch, selection policy. Đối chiếu per-class recall/precision, FPR BENIGN, thời gian và kết quả verify. Không chọn chỉ vì một run có train loss nhỏ hơn hoặc một chỉ số tổng hợp cao hơn.

## 11. Kiểm tra model đã xuất

### Qua giao diện

Chọn đúng run đã hoàn tất → bấm **Kiểm tra mô hình đã xuất** → xem kết quả và console.

### Qua CLI trên CPU

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$run = 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507'

& $py -m soc_ai predict --model $run --verify-only --device cpu
```

Kỳ vọng chương trình kết thúc thành công và in `MODEL_VERIFY_OK` cùng sai lệch golden-vector. Verify kiểm tra tính nhất quán bundle/suy luận, **không đo accuracy phát hiện tấn công thực tế**. Không tự đặt một ngưỡng khác để che lỗi nếu chương trình từ chối bundle.

## 12. Các file cần giữ

| File/thư mục | Mục đích |
|---|---|
| `model-weights.npz` | Trọng số model |
| `model.json` | Metadata, hyperparameter, best epoch, threshold, hash |
| `preprocessor.json` | Thông số tiền xử lý |
| `features.json` | Định nghĩa/contract đặc trưng |
| `golden.json`, `golden-predictions.json` | Dữ liệu kiểm tra suy luận xuất model |
| `metrics.json` | Kết quả đánh giá chi tiết |
| `history.json`, `history.jsonl` | Lịch sử học |
| `charts/` | Biểu đồ PNG/SVG |
| `requirements-lock.txt` | Dependency ghi nhận khi xuất |
| `checkpoints/latest.pt` | Phục vụ resume, không cần cho suy luận bằng bundle đã xuất |

Giao diện có nút tải một số file và ảnh, không tự tải toàn bộ run. Muốn lưu/di chuyển đầy đủ, chép cả thư mục run. Không ghép trọng số của run này với preprocessor/model.json của run khác.

## 13. Kiểm tra metadata bằng PowerShell

```powershell
$run = 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507'
$m = Get-Content "$run\model.json" -Raw | ConvertFrom-Json
$m.hyperparameters | Format-List
$m | Select-Object complete, device, gpu, best_epoch, best_selection_score, attack_score_threshold, weights_sha256 | Format-List

$actual = (Get-FileHash "$run\model-weights.npz" -Algorithm SHA256).Hash
if ($actual -ne $m.weights_sha256) { throw 'Weights hash mismatch' }
Write-Host 'MODEL WEIGHTS HASH MATCH'
```

Đây là kiểm tra metadata và hash, không thay cho golden verification hoặc đánh giá độc lập.

## 14. Xử lý lỗi thường gặp

| Hiện tượng | Cách xử lý |
|---|---|
| Mất kết nối | Kiểm tra backend/terminal còn chạy, đúng URL8765; không mở HTML bằng file:// |
| Cổng8765 bận | Chọn cổng khác bằng `--port`; mở đúng URL mới |
| ModuleNotFoundError | Kiểm tra đúng interpreter và dependency; không cài ngẫu nhiên vào Python khác |
| CUDA unavailable | Chọn CPU hoặc chuẩn bị đúng PyTorch CUDA/driver |
| CUDA out of memory | Giảm batch size ở run mới hoặc dùng CPU; không sửa checkpoint để resume với tham số khác |
| Output folder already exists | Dùng Run mới/thư mục mới; nếu muốn nối tiếp thì resume |
| Nút train chưa bật | Prepared chưa hoàn chỉnh hoặc trạng thái chưa nạp đúng; kiểm tra report/data và run đang chọn |
| Chỉ đổi ô đường dẫn mà chưa thấy dữ liệu mới | Form không tự upload file; backend cần lưu/nạp lựa chọn qua thao tác phù hợp |
| Nút verify chưa bật | Chọn run có model hoàn chỉnh; kiểm tra export/console |
| Không resume được | Kiểm tra checkpoint hợp lệ; chỉ có NPZ không đủ để resume training |
| Verify hash/feature mismatch | Giữ nguyên bundle, kiểm tra nguồn file và phiên bản code; không sửa metadata để bỏ qua |
| Chọn run cũ làm thay tham số | Bình thường: backend khôi phục cấu hình từ metadata |

## 15. Checklist bàn giao kết quả training

- [ ] Ghi rõ dataset/prepared, split policy và nguồn dữ liệu.
- [ ] Giữ đúng train/validation/test; không dùng test để chọn model.
- [ ] Ghi cấu hình thực tế từ model.json, không chép mặc định trên form.
- [ ] Ghi best epoch, selection policy, threshold và môi trường.
- [ ] Lưu metrics, history, biểu đồ và toàn bộ bundle.
- [ ] Verify CPU thành công.
- [ ] Ghi giới hạn đánh giá, đặc biệt lớp thiếu support và tính độc lập dữ liệu.
- [ ] Phân biệt training hoàn tất với chất lượng đã được kiểm chứng trên lab độc lập.
