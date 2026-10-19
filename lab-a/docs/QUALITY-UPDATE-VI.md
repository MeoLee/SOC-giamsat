# Sửa quy trình học và đánh giá trên dữ liệu lab

## Kết luận từ hai file đã gửi

Hai input/prediction khớp record_id và IP/cổng. Flow 40778 có 9 gói, 698 byte, duration 0.243272 giây; model gán DDoS với điểm lớp 0.922007. Flow 40762 có 10 gói, 1002 byte, duration 0.028645 giây; model gán Bot với điểm lớp 0.493427. Điểm binary non-BENIGN tương ứng 0.994082 và 0.998803, không phải xác suất hai loại tấn công đó.

flow.age=0 không gây chia cho 0: normalizer dùng flow.end - flow.start có phần lẻ. Metadata flow không chứa URI, nên riêng hai file này không chứng minh URL cụ thể; ngữ cảnh bạn khai báo là hoạt động kiểm tra bình thường. Không có bằng chứng flood hoặc ảnh hưởng dịch vụ trong hai flow.

Dữ liệu đã dùng trước đó có 8 local BENIGN train trong 384385 rows (~0.0021%), tất cả là SSH. Mô hình flow chưa học HTTP bình thường của lab. Validation toàn cục với hàng chục nghìn mẫu CICIDS có thể che nhóm local nhỏ; ngưỡng 7e-6 cũ không bảo đảm FPR trên lab. Hai mẫu mới này là dữ liệu chẩn đoán, không đưa vào một test độc lập rồi gọi kết quả là khách quan.

## Bản cập nhật làm gì

- Tạo traffic GET bình thường ở Kali, ghi client IP/cổng/thời gian/status/size, thu EVE và Apache TSV. Một số connection chứa 1/2/4 request keep-alive với nhịp nghỉ khác nhau. Chỉ health và trang login, không đăng nhập, không payload tấn công.
- Chỉ gán BENIGN khi full tuple + thời gian + số request/status/bytes + User-Agent khớp giữa client/Apache/Suricata. Connection bị tách/mâu thuẫn/bị trộn activity khác sẽ bị loại. So khớp thêm cận dưới số byte HTTP response mà client nhận với counter Suricata; nếu hụt thì loại và ghi excluded_response_bytes_underflow. Trường hợp này cần kiểm tra capture thay vì train trên dữ liệu hụt. Đây là kiểm tra cần thiết, không chứng minh capture không mất bất kỳ gói nào. Không dùng dự đoán hoặc rule ID làm nhãn.
- User-Agent luân phiên curl/browser; không chèn session tag vào request để tránh mô hình học đặc điểm của riêng bộ tạo dữ liệu. Session tag chỉ nằm trong manifest. Header curl-like, không mô phỏng đầy đủ trình duyệt thật.
- Ba phiên riêng train/validation/test. Đây là controlled baseline, không thay thế kiểm thử đa dạng trong thời gian dài. Không xáo tám mẫu của cùng phiên thành ba tập.
- Vẫn dùng cache CICIDS hiện có và các import SSH cũ, không tạo lại cohort hoặc đọc lại PCAP.
- --local-loss-fraction 0.20 đặt mục tiêu 20% tổng khối lượng weighted training loss cho local, phần còn lại vẫn học dữ liệu base. Trọng số không phải nhân bản mẫu trong file. Tỷ lệ thực tế từng batch thay đổi. Đây là cấu hình khởi đầu cần đánh giá, không phải giá trị tối ưu đã chứng minh.
- Chế độ này yêu cầu ít nhất 100 local records mỗi split và ít nhất 50 feature vectors khác nhau trong local train. Mức này là điều kiện tối thiểu kỹ thuật, không phải bảo đảm thống kê hay chất lượng triển khai.
- Chọn epoch dựa trên harmonic mean của external macro F1, local present-class macro F1 và validation attack recall. Không chỉ chọn điểm tổng bị CICIDS lấn át.
- Ngưỡng được chọn từ validation BENIGN toàn cục và từng nhóm day/session; lấy ngưỡng lớn nhất theo empirical 99th percentile. Báo cáo hiển thị trade-off recall/FPR trên test. Nếu ngưỡng làm mất recall thì phải loại candidate, không coi im lặng là cải thiện. Đây chưa phải xác suất hiệu chuẩn hoặc bảo đảm FPR <=1% ở tương lai.
- Sửa phép tính threshold/evaluation/scalar prediction về cùng float64 để nextafter không bị ép trở lại float32 khi so sánh ties. Thay đổi này không giải quyết riêng lỗi gán DDoS score cao; phần đó cần học và đánh giá lại.
- Checkpoint/resume, biểu đồ, giao diện và định dạng model tiếp tục dùng cơ chế cũ. Cũ không bật --local-loss-fraction vẫn dùng chính sách train cũ. Khi resume, cấu hình được đọc từ checkpoint, không thay chính sách giữa chừng.
- Model cũ, weights, checkpoint, config live, rule, UI không bị sửa. Runtime vẫn quan sát mọi flow đã cấu hình; IP trong công cụ thu dữ liệu chỉ là đích của phép thử có kiểm soát.

## 1. Cài bằng Windows PowerShell trên máy vật lý

Dừng AI Live bằng Ctrl+C, đợi LIVE_DONE. Nếu đang train, Pause & save trước. Giữ Docker, Ubuntu, Kali, Suricata, Apache, MariaDB hoạt động. Không chạy đồng thời sqlmap/nmap/hydra hoặc kịch bản tấn công khi thu normal.

Lưu ZIP tại E:\SOC-Lab\AI\SOC-AI-Quality-Update.zip. Mở PowerShell mới:

```powershell
$project = "E:\SOC-Lab\AI\SOC-AI-v0.2"
$patch = "E:\SOC-Lab\AI\quality-update"
$inferPython = "E:\SOC-Lab\AI\.venv-infer\Scripts\python.exe"
$trainPython = "E:\SOC-Lab\AI\.venv\Scripts\python.exe"
Expand-Archive -LiteralPath "E:\SOC-Lab\AI\SOC-AI-Quality-Update.zip" `
    -DestinationPath $patch -Force -ErrorAction Stop
& $inferPython "$patch\install_quality_update.py" --project "$project"
if ($LASTEXITCODE -ne 0) { throw "Chưa cài được bản cập nhật." }
Set-Location $project
& $trainPython -m unittest test_quality_update test_quality_training -v
if ($LASTEXITCODE -ne 0) { throw "Kiểm thử chưa đạt. Chưa thu dữ liệu hoặc train." }
```

Dùng trainPython cho kiểm thử vì có sklearn/matplotlib; không cần cài những thư viện này vào môi trường inference. Không dùng py -3 mặc định Python 3.14.

## 2. Thu normal HTTP và chuẩn bị dữ liệu — cùng cửa sổ PowerShell

Không cần mở shell Kali; công cụ tự gửi GET từ container Kali qua docker exec. Đây là thu dữ liệu, GPU có thể chưa hoạt động.

```powershell
& $inferPython .\prepare_quality_data.py --connections 120
if ($LASTEXITCODE -ne 0) { throw "Thu/ghép dữ liệu chưa hoàn tất. Giữ log lỗi." }
$plan = Get-Content -LiteralPath "E:\SOC-Lab\AI\quality-data\latest-quality-plan.json" -Raw | ConvertFrom-Json
if (-not $plan.complete) { throw "Kế hoạch chưa hoàn tất." }
$prepared = $plan.prepared
Write-Host "PREPARED: $prepared"
```

Ba lượt nối tiếp; mỗi lượt gửi 120 connection và chờ flow timeout tối đa 180 giây sau khi client xong. Bình thường khoảng 8–15 phút cho cả ba, phụ thuộc Docker/HDD; console thông báo tiến độ mỗi 10 giây. Không Ctrl+C chỉ vì đang WAITING. Nếu hết thời gian mà không khớp đủ, tool báo lỗi và giữ raw, không đánh dấu import complete.

Giới hạn hiện tại: hai trang bình thường, một client/service, các phiên gần nhau. Cần thêm normal SSH, trình duyệt, tải file hợp lệ và nhiều thời điểm sau này. Không xem 120 flow như 120 thí nghiệm độc lập về mặt thống kê. Không lấy bộ test mới để chỉnh thông số sau khi đã xem kết quả; khi dùng nó để debug, nó trở thành regression set và cần test mới cho kết luận cuối.

## 3. Train candidate mới — cùng cửa sổ PowerShell

```powershell
& $trainPython -c "import torch; print(torch.__version__); assert torch.cuda.is_available(), 'CUDA unavailable'"
if ($LASTEXITCODE -ne 0) { throw "Môi trường CUDA chưa đạt." }
$newRun = Join-Path "E:\SOC-Lab\AI\runs" ("mlp-quality-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
& $trainPython -m soc_ai train `
    --prepared "$prepared" --output "$newRun" `
    --epochs 30 --batch-size 2048 --device cuda --patience 7 `
    --checkpoint-seconds 30 --local-loss-fraction 0.20 --skip-baseline
if ($LASTEXITCODE -ne 0) { throw "Train chưa hoàn tất. Xem lỗi trước khi chạy lại." }
Write-Host "CANDIDATE: $newRun"
```

30 là trần, early stopping có thể kết thúc sớm. Mỗi epoch vẫn duyệt toàn bộ train split; batch size không làm tăng số dữ liệu được train. Không chọn --resume từ run cũ khi thay dữ liệu/chính sách. Nếu cần dừng candidate này, Ctrl+C và đợi TRAINING_PAUSED; tiếp tục bằng:

```powershell
& $trainPython -m soc_ai train --resume "DUONG_DAN_NEW_RUN"
```

Có thể xem run trên dashboard như trước; không khởi động thêm worker cho cùng run đang train.

## 4. Đọc kết quả trước khi chuyển model live

```powershell
$metrics = Get-Content -LiteralPath (Join-Path $newRun "metrics.json") -Raw | ConvertFrom-Json
$metrics.test_subsets.PSObject.Properties |
    Where-Object Name -Like "day:LAB:test:*" |
    ForEach-Object {
        [pscustomobject]@{
            Subset = $_.Name
            Benign = $_.Value.multiclass.BENIGN.support
            False_alerts = $_.Value.binary_attack.fp
            False_positive_rate = $_.Value.binary_attack.benign_false_positive_rate
        }
    } | Format-Table -AutoSize
$metrics.test.binary_attack | Format-List
$metrics.test.attack_types | ConvertTo-Json -Depth 5
Write-Host "RUN: $newRun"
```

Cần xem đồng thời FPR normal HTTP/SSH và recall/precision từng loại tấn công CICIDS. Normal-only local test chưa cho biết có bắt được tấn công local hay không. metrics.local_quality_check ghi rõ local_attack_recall_established. Không tự thay model đang chạy, không tự coi production_ready=true.

Chỉ sau khi so sánh và chấp nhận kết quả, mới thử candidate bằng `Start-AI-Live.cmd MODEL_DIRECTORY` để quan sát. Không đưa vào đóng gói nộp bài như mô hình đã được chứng minh nếu còn báo nhầm cao hoặc recall giảm nhiều.

## Đã kiểm tra ở môi trường tạo gói

19 test evidence/normalizer/host capture; 4 test threshold/training, gồm pause/resume khớp run không gián đoạn và export/verify. HTTP client chạy được trên server HTTP/1.1 local với keep-alive. Không có Docker/Suricata thật trong môi trường tạo gói; kiểm tra client–Apache–Suricata hoàn chỉnh cần chạy ở lab của bạn. Kiểm thử logic không chứng minh độ chính xác trên traffic thật.

## Nguồn phương pháp

https://scikit-learn.org/stable/modules/classification_threshold.html
https://scikit-learn.org/stable/modules/cross_validation.html
https://arxiv.org/abs/1706.04599

Temperature scaling có thể giúp hiệu chuẩn điểm, nhưng một temperature dương không thay argmax; riêng nó không biến nhãn DDoS sai thành BENIGN. Bản này không gọi điểm softmax là xác suất tấn công đã hiệu chuẩn.
