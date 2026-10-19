# Cài đặt và huấn luyện Lab A 0.4

Mở **Windows PowerShell trên máy vật lý** cho các lệnh Python/Docker dưới đây. Các lệnh Kali/Ubuntu riêng nằm trong [runbook kịch bản](SCENARIOS-VI.md). Không gõ lệnh quản trị vào cửa sổ AI Live đang chạy.

Ba đường sử dụng:

| Bạn đang có | Đường phù hợp |
|---|---|
| Source/model/cache Lab A hiện tại | Cài source cạnh bản cũ, verify model, thu/ghép local và train run mới khi cần. |
| Chưa có môi trường Python AI | Tạo venv CPU và venv CUDA riêng bằng script bên dưới. |
| Chưa có model hoặc cache | Tạo dataset từ raw EVE + nhãn có bằng chứng theo phiên, rồi train weights mới; không cần cache CICIDS cũ. |

“Từ đầu” ở đây là môi trường, dataset, weights và inference AI. Ubuntu/Kali/Suricata/Wazuh vẫn là hạ tầng SOC của Lab A. Source nhận được chưa có Compose tái tạo toàn bộ hạ tầng đó; không giả định một máy trắng đã có telemetry.

## 1. Cài source và Python

Giữ `SOC-AI-v0.2`, `.venv`, `.venv-infer`, raw, runs và checkpoints hiện có. Lưu ZIP `SOC-AI-Lab-A-v0.4-Research-20261019.zip` tại `E:\SOC-Lab\AI`, kiểm tra SHA256 với file `.sha256` đi kèm, rồi:

```powershell
$aiRoot = 'E:\SOC-Lab\AI'
$project = Join-Path $aiRoot 'SOC-AI-v0.4-research'
if (Test-Path -LiteralPath $project) { throw 'Thư mục đã tồn tại; chọn thư mục mới để giữ bản hiện hành.' }
Expand-Archive -LiteralPath (Join-Path $aiRoot 'SOC-AI-Lab-A-v0.4-Research-20261019.zip') -DestinationPath $aiRoot -ErrorAction Stop
Set-Location $project
py -3.12 --version
if ($LASTEXITCODE -ne 0) { throw 'Cài Python 3.12 chính thức rồi mở PowerShell mới.' }
powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-AI.ps1 -Mode Cpu -RunChecks
if ($LASTEXITCODE -ne 0) { throw 'Cài/kiểm tra CPU chưa đạt.' }
$cpu = Join-Path $aiRoot '.venv-ai04-cpu\Scripts\python.exe'
```

Python chính thức: https://www.python.org/downloads/windows/ . Script chỉ chọn Python 3.12, dùng venv mới và dependency trực tiếp đã kiểm thử. `-PlanOnly` in kế hoạch để đọc trước. Có thể truyền `-PythonPath` nếu không dùng launcher `py`; không cần sửa Python hệ thống.

Venv CPU chạy Live và cũng train được dataset nhỏ. Nếu đã có venv cũ với dependencies phù hợp, có thể chạy `run_checks.py` bằng venv đó trước; không cần cài đè lên nó. Giữ cùng phiên bản PyTorch khi resume checkpoint cũ.

## 2. CUDA cho RTX 4050 — tùy chọn

Chạy trong cửa sổ PowerShell riêng, sau khi driver NVIDIA đã hoạt động:

```powershell
nvidia-smi
if ($LASTEXITCODE -ne 0) { throw 'Driver/GPU chưa sẵn sàng; dùng CPU hoặc xử lý driver trước.' }
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-AI.ps1 -Mode Cuda
if ($LASTEXITCODE -ne 0) { throw 'CUDA chưa đạt; không train bằng interpreter này.' }
$gpu = 'E:\SOC-Lab\AI\.venv-ai04-cuda\Scripts\python.exe'
& $gpu -c 'import torch; print(torch.__version__, torch.version.cuda); assert torch.cuda.is_available(); print(torch.cuda.get_device_name(0))'
```

Gói dùng `torch==2.11.0` qua index chính thức `cu126`, phù hợp phiên bản đã được tài liệu Lab A ghi nhận. Wheel Windows/Python3.12 đã được kiểm tra tồn tại; GPU/driver thật cần kiểm tra trên máy bạn. Script không tự cài driver hoặc fallback âm thầm sang CPU. Muốn train CPU thì chủ động dùng `$cpu` và `--device cpu`.

## 3. Kiểm tra lab/model trước khi dùng

```powershell
$cpu = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$oldModel = 'E:\SOC-Lab\AI\runs\mlp-lab-20261014-212857'
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
& $cpu .\lab_doctor.py --config .\live-config.json --model $oldModel --runtime --bridge
if ($LASTEXITCODE -ne 0) { throw 'Đọc lỗi từng nguồn/model trước khi chạy Live.' }
```

Chưa có model thì bỏ `--model`; chưa cài bridge thì bỏ `--bridge`. Docker cần đang chạy; endpoint cần Suricata và các file log cấu hình. Đối chiếu asset IP sau reboot, interface sensor và rules đang nạp. Một file log rỗng hoặc process tồn tại chưa chứng minh sensor thấy traffic.

Khi chưa muốn gửi Wazuh, chạy Live local bằng model cũ để đối chiếu pipeline:

```powershell
& $cpu -u .\lab_live.py --model $oldModel --config .\live-config.json --output-dir 'E:\SOC-Lab\AI\live'
```

Ctrl+C một lần, đợi đóng phiên. Context được ghi riêng; HTTP rate mặc định tắt. Không bật watcher cũ và mới cùng outbox. Dùng cùng output root để giữ hàng đợi cũ khi đã đóng publisher trước; mỗi capture vẫn có thư mục phiên riêng.

## 4A. Có cache CICIDS cũ: mở run mới

Đây là train lại weights từ đầu trên feature cache có sẵn, không resume run đã complete. Không tạo lại PCAP chỉ để cập nhật code.

```powershell
$train = 'E:\SOC-Lab\AI\.venv-ai04-cuda\Scripts\python.exe'
$prepared = 'E:\SOC-Lab\AI\prepared-v01'
$newRun = Join-Path 'E:\SOC-Lab\AI\runs' ('mlp04-base-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $train -m soc_ai train --prepared $prepared --output $newRun --device cuda --epochs 30 --batch-size 2048 --patience 7 --checkpoint-seconds 30 --skip-baseline
if ($LASTEXITCODE -ne 0) { throw 'Training chưa hoàn tất; giữ checkpoint và xem lỗi.' }
```

Để cải thiện HTTP/SSH normal local, thu các phiên riêng theo [Quality guide](QUALITY-UPDATE-VI.md), bỏ phần cài patch lịch sử vì code đã tích hợp. `prepare_quality_data.py` tái dùng cache gốc; kiểm tra đường dẫn trong plan trước khi train. Chính sách `--local-loss-fraction 0.20` dành cho **base replay + local**, không dành cho dataset hoàn toàn local. Nó cần ít nhất 100 local rows mỗi split, 50 vector train khác nhau và validation đại diện các lớp active; đây là điều kiện kỹ thuật, không đảm bảo accuracy.

```powershell
$prepared = 'E:\SOC-Lab\AI\DUONG_DAN_PREPARED_BASE_PLUS_LOCAL_DA_KIEM_TRA'
if (-not (Test-Path -LiteralPath (Join-Path $prepared 'report.json'))) { throw 'Thay placeholder bằng cache có thật.' }
$newRun = Join-Path 'E:\SOC-Lab\AI\runs' ('mlp04-quality-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $train -m soc_ai train --prepared $prepared --output $newRun --device cuda --epochs 30 --batch-size 2048 --patience 7 --checkpoint-seconds 30 --local-loss-fraction 0.20 --skip-baseline
```

Không thay local fraction/dataset/chính sách khi resume checkpoint cũ. Policy được lưu và khôi phục; checkpoint cũ giữ objective cũ, run Quality mới dùng selection mới.

## 4B. Không có cache: xây dataset mới từ lab

Một model cần **BENIGN và ít nhất một lớp attack có bằng chứng**. Không thể train sáu lớp thật chỉ từ normal SSH/HTTP. Lớp thiếu được mask và ghi vào metadata; không gọi đó là model đủ sáu lớp. SQLi/HTTP burst chưa có lớp MLP tương ứng và không tự gắn thành Bot/DDoS.

Thu nhiều phiên riêng theo [kịch bản](SCENARIOS-VI.md): normal SSH/HTTP đa dạng, SSH password guessing có kiểm soát, các attack khác chỉ khi có bằng chứng phù hợp. Phân role cả phiên ngay từ đầu: train, validation, test phát triển. Sau đó thu **các phiên final benchmark mới**, chưa dùng cho train/threshold/chọn epoch.

### SSH có công cụ hỗ trợ gán nhãn

[Label SSH có kiểm soát](LABEL-SSH-VI.md) mô tả operator manifest và capture cần có. Công cụ đối chiếu đúng nguồn/đích/account/cổng/thời gian với Accepted hoặc Failed auth; loại flow trộn hoặc không đủ bằng chứng. Không thực thi tấn công và không lấy dự đoán làm nhãn.

```powershell
& $cpu .\label_controlled_ssh.py --capture 'E:\SOC-Lab\dataset\raw\PHIEN_DA_DONG' --operator 'E:\SOC-Lab\AI\evidence\operator.json' --output 'E:\SOC-Lab\AI\reviewed\PHIEN_MOI'
if ($LASTEXITCODE -ne 0) { throw 'Chưa đủ bằng chứng gán nhãn.' }
```

Các placeholder phải thay bằng đường thật. Lặp lại trên phiên normal/attack riêng ở từng role; đổi vai trò bằng cách chạy **phiên mới**, không đổi tên cùng capture.

### Nguồn khác hoặc cần review thủ công

`prepare_session_data.py index` đọc raw EVE và tạo draft với `label:null`. Chỉ giữ/gán nhãn các flow mà operator và nguồn độc lập chứng minh được. Không gán cả file captured background là attack.

```powershell
& $cpu .\prepare_session_data.py index --eve 'E:\SOC-Lab\AI\evidence\train-http\eve.jsonl' --output 'E:\SOC-Lab\AI\evidence\train-http\labels-draft.jsonl' --session 'train-http-01' --role train
```

Định dạng: mỗi row `soc-lab-labeled-flow/0.1` giữ flow gốc, `raw_ref` với dòng/hash, nhãn thuộc sáu lớp, `label_method` đã review và `evidence_refs` trỏ operator + auth/application/PCAP. Manifest `soc-supervised-sessions/1.0` có `synthetic:false`, các session với role/capture ID riêng, hash label file và toàn bộ evidence. Xem [manifest mẫu](../examples/supervised-sessions.example.json). Hàm builder kiểm tra raw row đúng counters/time/tuple, hash trước/sau và không dùng cùng raw capture cho nhiều split.

### Ghép các fragment và chuẩn bị arrays

Đặt manifest tổng ở thư mục chứa các fragment để đường tương đối không đi ra ngoài. Ví dụ `E:\SOC-Lab\AI\reviewed` chứa sáu thư mục labeler mới tạo, mỗi thư mục có `fragment.json`:

```powershell
$reviewRoot = 'E:\SOC-Lab\AI\reviewed'
$fragments = @(Get-ChildItem -LiteralPath $reviewRoot -Filter 'fragment.json' -Recurse)
if ($fragments.Count -lt 6) { throw 'Cần các phiên normal/attack riêng cho train, validation, test.' }
$sessions = @()
foreach ($file in $fragments) {
    $fragment = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($fragment.synthetic -ne $false) { throw 'Không đưa fixture giả lập vào dataset thật.' }
    foreach ($s in $fragment.sessions) {
        $prefix = $file.Directory.Name + '/'
        $s.records = $prefix + $s.records
        foreach ($e in $s.evidence_files) { $e.path = $prefix + $e.path }
        $sessions += $s
    }
}
$manifest = Join-Path $reviewRoot 'training-sessions.json'
if (Test-Path -LiteralPath $manifest) { throw 'Manifest đã tồn tại; dùng tên mới.' }
@{schema_version='soc-supervised-sessions/1.0'; synthetic=$false; sessions=$sessions} | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $manifest -Encoding UTF8
$prepared = 'E:\SOC-Lab\AI\prepared-local-04-NEW'
& $cpu .\prepare_session_data.py build --manifest $manifest --output $prepared
if ($LASTEXITCODE -ne 0) { throw 'Chuẩn bị dữ liệu chưa đạt; không train.' }
```

Giữ mỗi fragment trực tiếp trong một thư mục con của `reviewed` như ví dụ. Nếu cấu trúc lồng sâu khác, sửa prefix theo đường tương đối thật; không bỏ kiểm tra path/hash. Có thể trộn với cache gốc bằng `--base-prepared E:\SOC-Lab\AI\prepared-v01`; source baseline thiếu full campaign provenance thì benchmark vẫn ghi chưa xác minh đầy đủ.

Các normal imports cũ từ `import_lab_normal.py`/`collect_normal_http.py` cũng có thể tái dùng: session manifest khai báo `import_directory` tương đối và `report_sha256`, id/role/capture ID đúng; builder verify report/data/source hashes. Không tự sửa role của import cũ.

### Train weights mới hoàn toàn

```powershell
$train = 'E:\SOC-Lab\AI\.venv-ai04-cuda\Scripts\python.exe'
$newRun = Join-Path 'E:\SOC-Lab\AI\runs' ('mlp04-local-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
& $train -m soc_ai train --prepared $prepared --output $newRun --device cuda --epochs 30 --batch-size 512 --patience 7 --checkpoint-seconds 30 --skip-baseline
if ($LASTEXITCODE -ne 0) { throw 'Training chưa hoàn tất; xem log/checkpoint.' }
& $cpu -m soc_ai predict --model $newRun --verify-only --device cpu
if ($LASTEXITCODE -ne 0) { throw 'Bundle CPU chưa verify được.' }
```

CPU training: thay `$train` bằng `$cpu` và `--device cuda` bằng `--device cpu`. Không thêm `--local-loss-fraction` cho tập hoàn toàn local. Batch/epoch ở đây là điểm khởi đầu, không phải cấu hình tối ưu đã đo.

Pause: Ctrl+C một lần ở cửa sổ train, đợi `TRAINING_PAUSED`. Resume cùng interpreter/phiên bản/dataset bằng `python -m soc_ai train --resume DUONG_RUN_PAUSED`; không resume run đã complete để đổi thí nghiệm. Kiểm tra hash/cache/preprocessor sẽ chặn resume không tương thích.

### Nếu muốn dựng lại CICIDS từ PCAP gốc

`python -m soc_ai prepare` hiện nhận **cohort `cic-experimental-cohort/0.1` đã xây**, không nhận PCAP/CSV gốc. Bộ processor PCAP→EVE→đối chiếu nhãn cohort của cuộc chat trước chưa có trong source upload. Vì vậy chưa có lệnh một bước tái tạo nguyên model CICIDS sáu lớp từ các file PCAP trắng. Không thay cột CICFlowMeter CSV vào 24 feature Suricata hoặc đoán nhãn bằng IP/lịch tấn công để lấp chỗ thiếu. Đường local ở trên là đường train mới đầy đủ được cung cấp trong release này.

## 5. Final benchmark và chọn model

Thu các phiên final mới, theo [SCENARIOS](SCENARIOS-VI.md); dùng `lab_scenarios.py register` để scope/hash/evidence thành benchmark manifest. Benchmark so sánh **bundle MLP cũ và candidate thật**, không chỉ linear baseline SGD.

Nếu xây từ đầu và chưa có model cũ, trước hết train một run baseline, giữ bundle đó làm mốc rồi mới mở thí nghiệm candidate. Không tạo weights giả hoặc dùng model đã sửa sau khi xem holdout làm baseline. Khi chưa có baseline thật, có thể verify bundle và replay logic, nhưng chưa kết luận đã cải thiện so với A trước.

```powershell
$benchmark = 'E:\SOC-Lab\AI\benchmarks\holdout\benchmark-manifest.json'
$report = Join-Path 'E:\SOC-Lab\AI\benchmarks' ('comparison-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
& $cpu .\evaluate_lab.py --manifest $benchmark --baseline $oldModel --candidate $newRun --output $report
$evaluationExit = $LASTEXITCODE
if ($evaluationExit -eq 2) { throw 'Benchmark input/bundle lỗi; xem thông báo.' }
Get-Content -LiteralPath $report -Raw
```

Exit3 có report nhưng tiêu chí không đạt hoặc bằng chứng chưa đủ, không được bỏ qua như thành công. CLI train không tự chứng nhận campaign độc lập, nên số đo có thể tốt mà evidence gate vẫn `insufficient_evidence`. Xem `numerical_operating_criteria` riêng, counts/coverage và từng session/scenario, rồi review độc lập trước quyết định. Không sửa cờ provenance để làm gate xanh. Không có thao tác tự thay model.

Nếu test đã dùng nhiều lần để debug/chọn model thì nó thành regression set; cần final holdout mới. FPR thấp chỉ trên normal không chứng minh recall attack; recall cao chỉ trên scored rows không chứng minh bao phủ SYN một gói.

## 6. Live và rollback

Chỉ đổi đối số `--model` sang `$newRun` sau khi đã chấp nhận kết quả. Wazuh bridge vẫn là at-least-once và append ACK khác alert/index; làm smoke/trace theo runbook. Context shadow không được gửi Wazuh trong release này.

Rollback: đóng Live mới đúng cách, chạy model/source cũ; model và các thư mục dữ liệu vẫn giữ nguyên. Giữ log phiên lỗi để phân tích, không xóa raw để làm báo cáo sạch.
