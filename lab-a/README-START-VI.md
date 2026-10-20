# Lab A 0.4 — bản nghiên cứu cải tiến

Nếu Live dừng ở nguồn endpoint mới với `Log source is not a regular file`,
xem [bản sửa Doctor cho log rỗng](docs/DOCTOR-EMPTY-LOG-FIX-VI.md).

Đã có [bản sửa lỗi shard khi đọc index cũ](docs/CHAIN-SHARD-FIX-VI.md) cho Chain
Investigation; dùng ZIP 0.4.6 có đuôi Shard-Fix và file repair gồm hai visualization.

**Bản đóng gói hiện hành: 0.4.6.** Có [Chain Investigation, bằng chứng từng bước và kịch bản năm bước](docs/CHAIN-INVESTIGATION-VI.md), [bảng Attack Chain Detail và scoring trên Wazuh](docs/CHAIN-DASHBOARD-VI.md), [sửa SYN/recon và cài rule](docs/RECON-FIX-VI.md), [Wazuh realtime](docs/WAZUH-REALTIME-VI.md), cùng [train Quality bằng dashboard](docs/TRAIN-DASHBOARD-VI.md). Giữ model và venv hiện có. Dashboard chi tiết import riêng, giữ bảng 0.4.5; hai hành động endpoint cần cài probe có kiểm soát, không phải audit cho mọi lệnh. Không phải train lại.

Gói gồm sửa bộ cài hai EVE output và flow ID có đuôi `.000000`. Xem [kết quả HTTP burst thật](docs/HTTP-BURST-REVIEW-20261020-VI.md); model false positive được ghi nhận riêng. Nếu đã cài ZIP0.4 và gặp HTTP400/dashboard hoặc test offset10≠9, xem [bản vá Windows](docs/WINDOWS-FIX-VI.md).

Giữ nền MLP24 của A, nâng độ tin cậy dữ liệu/huấn luyện/đánh giá và bổ sung context theo cửa sổ. Đây là source và quy trình có thể kiểm chứng, **không phải weights đã được chứng minh tốt hơn model đang chạy trên máy bạn**.

| Cần làm | Mở tài liệu |
|---|---|
| Đọc quyết định thiết kế và nghiên cứu | [Thiết kế, bằng chứng và giới hạn](docs/RESEARCH-04-VI.md) |
| Cài mới / nâng cấp / train lại từ cache / train từ dữ liệu mới | [Hướng dẫn cài đặt và train](docs/INSTALL-TRAIN-VI.md) |
| Train Quality bằng giao diện HTML, biểu đồ và pause/resume | [Dashboard training](docs/TRAIN-DASHBOARD-VI.md) |
| Đẩy hoạt động/cảnh báo lên Wazuh, risk và attack chain theo thời gian thực | [Wazuh realtime](docs/WAZUH-REALTIME-VI.md) |
| Chạy kịch bản giả lập và các phép thử trên lab | [Kịch bản kiểm thử](docs/SCENARIOS-VI.md) |
| So sánh model cũ với candidate trên cùng holdout | [Benchmark](docs/BENCHMARK-VI.md) |
| Hiểu tín hiệu quét cổng / HTTP rate chạy shadow | [Context](docs/CONTEXT-VI.md) |

## Có gì thay đổi

- Kiểm tra cache trước khi train: kiểu/mã nhãn, shape, finite, split/session và SHA256; giữ chính sách checkpoint cũ khi resume.
- Chọn epoch Quality từ validation với các thành phần minh bạch, kể cả recall của lớp tấn công yếu nhất; không lấy test để chỉnh model.
- Tạo dataset mới từ các phiên có nhãn độc lập bằng `prepare_session_data.py`, không bắt buộc có cache CICIDS cũ. Lớp chưa có dữ liệu được báo rõ và mask.
- Kiểm tra chặt bundle/preprocessor/weights/golden trước inference; không đổi architecture hay 24 feature.
- Benchmark ghép cặp model cũ/candidate, tách nhãn argmax và quyết định cảnh báo; giữ invalid/out-of-scope trong coverage, kiểm tra trùng capture/nguồn train.
- Context quan sát số cổng đích khác nhau, hoặc số request Apache khi bật; ghi riêng `context-signals.jsonl`, `context-errors.jsonl`, `context-status.json`. Không sửa prediction, không gửi context sang Wazuh, không tự chặn.
- Replay kịch bản offline và đăng ký capture thật với bằng chứng độc lập. Dữ liệu giả lập có dấu synthetic và không dùng để chứng minh accuracy.

## Bắt đầu trên Windows

Giải nén ZIP thành thư mục mới `E:\SOC-Lab\AI\SOC-AI-v0.4-research`, giữ nguyên v0.2/model/data hiện có. Trong **Windows PowerShell trên máy vật lý**, mở thư mục mới:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-AI.ps1 -Mode Cpu -RunChecks
```

Lệnh dùng phạm vi process để chạy script đã tải; không đổi execution policy hệ thống. Script tạo `.venv-ai04-cpu` cạnh project; chưa train, chưa gửi traffic và chưa cài container. Đọc hướng dẫn đầy đủ nếu đã có venv hoặc cần CUDA.

Kiểm tra nhanh pipeline không cần Docker/model thật:

```powershell
$cpu = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $cpu .\lab_scenarios.py replay --output 'E:\SOC-Lab\AI\scenario-replay-04'
if ($LASTEXITCODE -ne 0) { throw 'Replay chưa đạt; xem report.' }
```

Mỗi output dùng thư mục mới. Replay xác nhận logic, không đo khả năng phát hiện thực tế.

Sau khi có model thực:

```powershell
$model = 'E:\SOC-Lab\AI\runs\mlp-lab-20261014-212857'
& $cpu .\lab_doctor.py --model $model --runtime --bridge
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra lab/model chưa đạt.' }
& $cpu -u .\lab_live.py --model $model --config .\live-config.json --output-dir 'E:\SOC-Lab\AI\live' --publish-wazuh
```

Nếu bridge chưa cài thì bỏ `--bridge` và `--publish-wazuh`, quan sát local trước. Config gói bật port context shadow; HTTP rate mặc định tắt cho đến khi đo normal baseline. Để dùng config cũ chưa có context, thêm `--context`; để tắt, thêm `--no-context`.

Thu normal/attack riêng theo phiên, chia dữ liệu phát triển và final holdout. Chỉ thử model mới sau khi đối chiếu local normal FPR, attack recall và coverage; việc train thành công hoặc golden verify không đủ để kết luận chất lượng đã cải thiện.
