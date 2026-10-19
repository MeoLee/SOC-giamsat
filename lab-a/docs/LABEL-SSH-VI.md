# Gán nhãn SSH có kiểm soát từ capture thật

`label_controlled_ssh.py` nối **flow TCP/SSH đã hoàn tất trong EVE** với **log sshd gốc** và lời khai đã review của người vận hành. Công cụ không phát traffic, không thực thi tấn công, không train, không lấy dự đoán AI hoặc cảnh báo rule làm nhãn. Đây là đường hỗ trợ tạo dataset local mới trong [hướng dẫn cài/train](INSTALL-TRAIN-VI.md), không phải bộ tự gán nhãn mọi traffic SSH.

## 1. Thu bằng chứng theo từng phiên

Làm các bước chuẩn bị network, nguồn log và thu capture trong [SCENARIOS-VI.md](SCENARIOS-VI.md). Mỗi capture dành riêng một role `train`, `validation` hoặc `test` phát triển, một ý định và một cặp nguồn/đích/account. Thu normal và password guessing ở các phiên độc lập; không chia lại cùng capture thành ba role. Giữ các phiên **final benchmark mới** ngoài toàn bộ quá trình train/chọn threshold/chọn model.

Các đầu vào cần có:

- Thư mục capture chứa `session.json` dạng `soc-capture/1.0`, đã `closed:true`, `status:completed`; không gap, partial hoặc lỗi nguồn chưa giải quyết. Capture có ID, thời gian bắt đầu/kết thúc, danh sách nguồn và SHA256 đầy đủ.
- EVE gốc, mặc định `suricata-eve.jsonl`; auth gốc, mặc định `ubuntu-auth.log`. Giữ nguyên bytes và newline. Tool kiểm tra hash của mọi source trong capture, kể cả source không dùng gán nhãn.
- Transcript độc lập của operator: thời gian có timezone, endpoint/account, ý định, thao tác và kết quả thực quan sát được. Không ghi mật khẩu, private key, cookie hay token. Giữ bản đầy đủ ở nơi riêng; không đẩy bằng chứng nhạy cảm lên GitHub.
- `operator.json` theo mẫu bên dưới, đã được người chịu trách nhiệm đối chiếu với log. Hash chỉ chứng minh bytes không đổi, không chứng minh lời khai đúng.

Auth phải có năm, timezone và hostname ngay trong từng dòng, ví dụ minh họa:

```text
2026-10-19T14:00:02.500000+07:00 ubuntu-endpoint sshd[123]: Accepted password for labtest from 192.0.2.10 port 45000 ssh2
```

Địa chỉ `192.0.2.0/24` chỉ dành cho tài liệu. `target_host` phải khớp **hostname được ghi trong auth**, không đoán theo tên Docker, asset hay IP. Kiểu `Oct 19 14:00:02 ...` thiếu năm/timezone bị từ chối; không tự thêm năm hoặc sửa giờ vào log cũ. Cấu hình timestamp đầy đủ cho nguồn trước khi thu phiên mới. Clock lệch hoặc log chỉ chính xác tới giây có thể làm join thất bại: kiểm tra nguồn, không nới cửa sổ bằng cách sửa dữ liệu.

## 2. Khai báo và review operator manifest

Mở PowerShell trên Windows tại thư mục source mới. Sau khi capture đã đóng:

```powershell
$cpu = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$capture = 'E:\SOC-Lab\dataset\raw\THU_MUC_CAPTURE_DA_DONG'
$evidenceDir = 'E:\SOC-Lab\AI\evidence\train-normal-ssh-01'
if (Test-Path -LiteralPath $evidenceDir) { throw 'Chọn thư mục bằng chứng mới để giữ bản cũ.' }
New-Item -ItemType Directory -Path $evidenceDir -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath '.\examples\operator-ssh.example.json' -Destination (Join-Path $evidenceDir 'operator.json') -ErrorAction Stop
$session = Get-Content -LiteralPath (Join-Path $capture 'session.json') -Raw | ConvertFrom-Json
$session | Select-Object session_id, started_at_utc, ended_at_utc, closed, status
```

Thay placeholder bằng đường thật. Chép transcript thật đã thu vào `$evidenceDir\operator-log.txt`; không tạo transcript giả sau khi nhìn kết quả model. Mở `operator.json` bằng editor và điền:

| Trường | Ý nghĩa và kiểm tra |
|---|---|
| `schema_version` | Giữ `soc-controlled-ssh/1.0`. |
| `id` | ID mới, duy nhất; 1–96 ký tự chữ/số, dấu chấm, gạch dưới hoặc gạch ngang; bắt đầu bằng chữ/số. |
| `role` | `train`, `validation` hoặc `test`; role của cả phiên, đã quyết định trước khi xem kết quả AI. |
| `capture_session_id` | Đúng `session_id` của capture vật lý đã đóng. Đổi tên thư mục không tạo capture mới. |
| `source_ip`, `target_ip` | Cặp IP thật theo chiều client→server trong EVE, dạng IP chuẩn; không dùng cặp minh họa. Hai IP phải khác nhau. |
| `target_host`, `username` | Khớp nguyên giá trị hostname/account trong auth; giữ riêng từng account. |
| `start_time`, `end_time` | ISO datetime có timezone, ví dụ `+07:00` hoặc `Z`; nằm trọn trong thời gian capture, end lớn hơn start. Scope đủ bao phủ **toàn bộ start/end của flow đã đóng** cần chọn. |
| `captured_at` | Thời điểm ghi nhận bằng chứng thực, ISO datetime có timezone. |
| `intent` | `normal_ssh` hoặc `ssh_password_guessing`, theo thao tác được kiểm soát, không theo prediction. |
| `tool_output.path` | Đường tương đối từ thư mục chứa operator JSON tới transcript, ví dụ `operator-log.txt`; không đi ra ngoài thư mục bằng chứng. |
| `tool_output.sha256` | SHA256 lowercase của transcript không rỗng, sau khi hoàn tất ghi chép. |
| `reviewer` | Tên người đã kiểm tra capture, transcript, scope, auth và ý định. |
| `controlled`, `independent`, `reviewed` | Chỉ đặt cả ba thành `true` khi đã xác nhận: phiên có kiểm soát, nhãn dựa bằng chứng độc lập với AI/rule, và đã review. `independent` không tự chứng nhận các campaign/split độc lập. |
| `synthetic` | `false` chỉ cho bằng chứng **thật**; giữ `true` cho fixture/replay/ví dụ. Không hạ cờ synthetic của capture. |

Mẫu cố ý đặt `synthetic:true`, ba cờ review là `false` và hash chưa điền, nên không thể dùng ngay để tạo nhãn thật. Phần mềm không thay operator thực hiện review.

Sau khi transcript đã hoàn tất, tính hash rồi chép chuỗi này vào `tool_output.sha256`:

```powershell
$transcript = Join-Path $evidenceDir 'operator-log.txt'
if (-not (Test-Path -LiteralPath $transcript -PathType Leaf)) { throw 'Thiếu transcript thật.' }
(Get-FileHash -LiteralPath $transcript -Algorithm SHA256).Hash.ToLowerInvariant()
```

Nếu sửa transcript, phải hash và review lại; không sửa metadata/hash capture để che lỗi nguồn.

## 3. Công cụ chọn nhãn như thế nào?

| Ý định đã review | Bằng chứng tối thiểu | Nhãn cho flow được chọn |
|---|---|---|
| `normal_ssh` | Đúng một `Accepted password` hoặc `Accepted publickey` khớp flow; không có failure/outcome lẫn | `BENIGN` trong phạm vi phiên normal có kiểm soát |
| `ssh_password_guessing` | Ít nhất **8 failure password khác nhau trong một cửa sổ 60 giây**, cùng source/account/hostname và trong scope operator; từng flow được chọn chỉ có password failure | `SSH-Patator` local có kiểm soát |

Mỗi flow phải là TCP, ứng dụng `ssh`, đi đúng `source_ip`→`target_ip`, cổng đích **22**, nằm trọn trong scope và trong phạm vi model. Auth phải khớp source IP **và cổng nguồn**, hostname, account; timestamp auth nằm trong khoảng start/end của chính flow. Tool không hỗ trợ cổng SSH khác trong release này.

Tám lần bấm chạy lệnh không tương đương tám failure. Các bản sao cùng auth outcome không tăng số trial. Đủ tám failure là điều kiện hỗ trợ ý định, không bảo đảm có tám flow hợp lệ hoặc tám nhãn đầu ra. Các flow trộn fail/success, nhiều user/host, một auth khớp nhiều flow, flow không đầy đủ hoặc observations mâu thuẫn bị loại; login đúng sau burst không tự bị gắn `SSH-Patator`. Nhãn local này không chứng minh compromise và không bảo đảm tương đương phân phối CICIDS-SSH-Patator.

## 4. Tạo fragment, xem báo cáo rồi ghép dataset

Chọn thư mục output chưa tồn tại, trực tiếp dưới `reviewed` để ghép theo hướng dẫn cài/train:

```powershell
$operatorFile = Join-Path $evidenceDir 'operator.json'
$labelOutput = 'E:\SOC-Lab\AI\reviewed\train-normal-ssh-01'
& $cpu .\label_controlled_ssh.py --capture $capture --operator $operatorFile --output $labelOutput
if ($LASTEXITCODE -ne 0) { throw 'Chưa đủ bằng chứng; đọc lỗi trước khi tiếp tục.' }
Get-Content -LiteralPath (Join-Path $labelOutput 'report.json') -Raw
```

Nếu capture dùng tên output khác, truyền `--eve TEN_FILE_EVE` và `--auth TEN_FILE_AUTH` đúng metadata capture. Không truyền log Wazuh bọc ngoài thay native EVE/auth.

Output gồm:

- `labels.jsonl`: flow đã chuẩn hóa cùng nhãn, raw EVE line/byte offset/hash và các auth line/hash đối chiếu; không bỏ flow gốc.
- `fragment.json`: một session `soc-supervised-sessions/1.0`, role, capture ID, synthetic, hash label và danh sách evidence; **đây là fragment cho preparer**, không phải benchmark manifest.
- `evidence/`: bản sao đóng băng EVE, auth, operator, transcript và `capture-session.json`.
- `report.json`: số chọn/loại và hạn chế. `complete:true` nghĩa thao tác tạo fragment hoàn tất, không chứng nhận chất lượng dataset hay model.

Tool chỉ xuất khi còn ít nhất một flow không mơ hồ, không ghi đè output có sẵn và kiểm tra hash trước/sau. Đọc các số `excluded_*` trong report; loại nhiều là tín hiệu cần kiểm tra sensor/thời gian/thiết kế capture, không phải lý do đổi điều kiện để lấy thêm nhãn.

Lặp lại với các phiên vật lý riêng cho normal và attack ở cả ba role. **Một fragment không đủ train model.** Dùng phần “Ghép các fragment và chuẩn bị arrays” của [INSTALL-TRAIN-VI.md](INSTALL-TRAIN-VI.md) để tạo `training-sessions.json`, sửa prefix đường tương đối khi ghép và chạy `prepare_session_data.py build`. Dataset cần BENIGN và ít nhất một lớp attack ở các split; lớp chưa có dữ liệu được mask, không tự trở thành model sáu lớp đầy đủ. Không dùng fragment này trực tiếp với `lab_scenarios.py register` hoặc `evaluate_lab.py`; final benchmark có định dạng/bằng chứng riêng.

## 5. Tự kiểm tra phần mềm trước capture thật

```powershell
& $cpu -m unittest test_label_controlled_ssh -v
if ($LASTEXITCODE -ne 0) { throw 'Kiểm thử labeler chưa đạt.' }
```

Các test dùng dữ liệu synthetic để kiểm tra join/hash/split, không phát traffic. Fragment và prepared arrays từ fixture phải giữ synthetic và không được dùng làm bằng chứng accuracy, dataset thật hoặc final holdout. Các test đạt vẫn chưa xác nhận Windows/Docker/clock/sensor của máy lab đang hoạt động đúng.
