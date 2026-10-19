# Lab A — bản hợp nhất 0.3.0-candidate.1

Đây là **bản mã nguồn ứng viên**, dựng từ `SOC-AI-v0.2.rar` và phần cập nhật còn thiếu trong `utilities.rar` ngày 19/10/2026. Bản này giữ nền Lab A, bổ sung Quality/Web và cải thiện việc kiểm tra nguồn, chuẩn hóa bằng chứng, truy vết log. Không chứa model đã train, dataset, checkpoint hoặc dữ liệu riêng của Lab B.

Đọc [báo cáo đối chiếu A/B và lộ trình](docs/PHAN-TICH-A-B-VI.md) để hiểu các quyết định. [Manifest](docs/MERGE-MANIFEST.json) ghi SHA256 đầu vào và nguồn từng phần được hợp nhất. Các README cũ mô tả từng chức năng lịch sử; hướng dẫn dưới đây là điểm bắt đầu cho gói này.

## Nội dung đã hợp nhất

| Thành phần | Quyết định |
|---|---|
| Core MLP, dashboard, checkpoint | Giữ nền source A đã gửi; 24 feature, sáu lớp và feature hash giữ nguyên. |
| Windows I/O | Giữ bản đang có trong source: snapshot đóng file, atomic replace, retry có giới hạn. Bản này còn xử lý `PermissionError` thông thường; không chép Fix/Fix2 cũ đè lên. |
| Live Observer | Giữ v0.4 + UI đã có. Không quay lại các gói v0.1–v0.3.1. |
| Local Data / Flow Check / UI | Đã có trong source; giữ lại, không chạy installer lịch sử. |
| Quality Update | Ghép công cụ normal HTTP, audit, chuẩn bị dữ liệu, policy train tùy chọn và sửa so sánh threshold float64. |
| Web Lab | Thêm `setup_web_lab.py`, `endpoint/` và tests. Chỉ là công cụ; việc giải nén gói không cài hay khởi động DVWA. |
| Cải tiến từ nghiên cứu B | Validation cấu hình/asset, Wazuh decoded EVE, bảo toàn ID, provenance byte offset, replay qua biên poll, kiểm tra chỉ đọc bằng `lab_doctor.py`. |

Không chạy thêm các installer UI/IO/Live/Quality cũ lên bản này. Ngưỡng float64 thống nhất phép so sánh tại các điểm bằng nhau; vì vậy một quyết định sát ngưỡng có thể khác code cũ dù weights không đổi. Đây không phải cách chữa báo nhầm DDoS/Bot trên HTTP bình thường.

## Dùng thử cạnh bản hiện tại trên Windows

Giữ thư mục `SOC-AI-v0.2` đang chạy. Gói mới giải nén thành thư mục **khác**, không chép đè source đang dùng. Nếu đang train thì vẫn để worker cũ dùng source cũ; không cho hai live watcher đồng thời dùng chung outbox. Dừng Live bằng Ctrl+C một lần và đợi đóng phiên trước khi thử watcher mới.

Ví dụ lưu ZIP tại `E:\SOC-Lab\AI\SOC-AI-Lab-A-Candidate-20261019.zip`. Mở **Windows PowerShell trên máy vật lý**:

```powershell
$aiRoot = 'E:\SOC-Lab\AI'
$candidate = Join-Path $aiRoot 'SOC-AI-v0.3-candidate'
if (Test-Path -LiteralPath $candidate) { throw 'Thư mục ứng viên đã tồn tại; chọn tên mới để giữ bản cũ.' }
Expand-Archive -LiteralPath (Join-Path $aiRoot 'SOC-AI-Lab-A-Candidate-20261019.zip') -DestinationPath $aiRoot -ErrorAction Stop
$inferPython = Join-Path $aiRoot '.venv-infer\Scripts\python.exe'
$trainPython = Join-Path $aiRoot '.venv\Scripts\python.exe'
$model = Join-Path $aiRoot 'runs\mlp-lab-20261014-212857'
Set-Location $candidate
```

Mặc định dùng đúng nguồn/asset trong source bạn đã gửi, bao gồm Apache. Nếu cấu hình active trên Windows đã thay đổi sau lúc xuất RAR, đối chiếu `live-config.json` và mang cấu hình active sang thư mục ứng viên trước khi kiểm tra. Asset mapping giúp nhận đúng host, không giới hạn IP attacker.

Kiểm tra **chỉ đọc**, không cài đặt hay restart Docker:

```powershell
& $inferPython .\lab_doctor.py --config .\live-config.json --model $model --runtime --bridge --output .\doctor-result.json
if ($LASTEXITCODE -ne 0) { throw 'Có kiểm tra chưa đạt; đọc doctor-result.json trước khi chạy live.' }
```

`--bridge` yêu cầu bridge đã được cài. Nếu chỉ thử quan sát local, bỏ `--bridge`; dùng lệnh live không có `--publish-wazuh` bên dưới. Doctor xác nhận file/process/bundle trong phạm vi được yêu cầu, **không xác nhận capture đủ traffic, model chính xác hoặc alert đã tới indexer**. File rỗng có thể hợp lệ nhưng chưa chứng minh nguồn hoạt động.

Chạy cùng model cũ để đối chiếu pipeline trước:

```powershell
& $inferPython -u .\lab_live.py --model $model --config .\live-config.json --output-dir (Join-Path $aiRoot 'live') --publish-wazuh
```

Nếu chưa cài bridge, bỏ `--publish-wazuh`. `Start-AI-Live.cmd` vẫn dùng đường dẫn model/output Windows đã có trong Lab A; nhận đường dẫn model ở đối số đầu. Đây chưa phải launcher portable cho mọi máy.

Quay lại bản cũ: đóng live ứng viên đúng cách rồi chạy launcher trong `SOC-AI-v0.2`. Model/data/checkpoint hiện có vẫn ở ngoài thư mục ứng viên; không cần chép hay tạo lại PCAP.

## Kiểm thử và cải thiện model

Chạy toàn bộ hai vị trí tests bằng Python training đã có các thư viện:

```powershell
& $trainPython .\run_checks.py
if ($LASTEXITCODE -ne 0) { throw 'Kiểm thử chưa đạt.' }
```

Kết quả cloud: 164 ca được nhận diện, 162 đạt, hai ca Windows bỏ qua. Xem [phạm vi kiểm chứng](docs/VALIDATION-VI.md). Các ca train dùng dữ liệu tổng hợp nhỏ để kiểm tra pause/resume/export; không train lại model thực của bạn.

Quality tools đã tích hợp nhưng **chưa thu dữ liệu hoặc train candidate thực**. Đọc [hướng dẫn Quality](docs/QUALITY-UPDATE-VI.md), bắt đầu từ phần thu normal HTTP; bỏ phần cài patch cũ. Dùng run mới khi bật `--local-loss-fraction`, không resume run cũ để đổi policy. Chưa tự chọn candidate làm model mặc định. Phải so sánh FPR normal SSH/HTTP và recall tấn công trên phiên độc lập.

Web đã hoạt động thì không cần cài lại. [Hướng dẫn Web gốc](docs/WEB-LAB-VI.md) dành cho endpoint cần dựng dịch vụ; trong bản hợp nhất, installer ở ngay thư mục project. Dịch vụ DVWA có tài khoản mặc định dành cho lab cô lập. Bộ gói này chưa dựng lại toàn bộ endpoint/Wazuh từ Compose.
