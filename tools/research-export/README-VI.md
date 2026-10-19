# Trích xuất cấu hình SOC để nghiên cứu

Chạy trên **máy đang có lab cần tham khảo**, trong **một cửa sổ Windows PowerShell mới hoàn toàn**. Docker Desktop phải đang chạy và tài khoản hiện tại phải dùng được Docker. Không chạy các lệnh này bên trong Ubuntu hoặc Kali.

Script dùng được với Windows PowerShell 5.1 hoặc PowerShell 7. Không cần cài Python. Nó không cài thêm package, sửa cấu hình hay khởi động/dừng/restart container.

## 1. Tải script

Lưu `Export-SOC-Research.ps1` vào thư mục Downloads trên máy kia. Đọc nội dung script nếu cần trước khi chạy.

## 2. Chạy một lần để lấy Docker và cấu hình container

Trong cửa sổ PowerShell mới trên máy kia, dán nguyên khối:

```powershell
Set-Location "$HOME\Downloads"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Export-SOC-Research.ps1"
```

`ExecutionPolicy Bypass` ở đây chỉ áp dụng cho tiến trình PowerShell được gọi, không lưu thay đổi chính sách của máy.

Mặc định script tìm container theo tên/image có Ubuntu, endpoint, Suricata, Wazuh, Kali, Filebeat, Logstash, SOC hoặc AI. Nó ghi danh sách container vào gói kết quả. Container đang dừng chỉ được lấy metadata, không tự khởi động.

Nếu tên container khác hoàn toàn và không được chọn, dùng tên thật trong `container-list.txt`, phân tách bằng dấu phẩy. Ví dụ dưới đây chỉ dùng khi các tên đó đúng trên máy kia:

```powershell
Set-Location "$HOME\Downloads"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Export-SOC-Research.ps1" -ContainerNames "ubuntu-endpoint,suricata,wazuh.manager,ai"
```

## 3. Lấy thêm Compose, Dockerfile và mã nguồn AI

Đây là cách nên dùng nếu người sở hữu máy biết thư mục project và AI. **Dùng lại cửa sổ PowerShell ở bước 2** hoặc mở mới rồi dán lại toàn bộ khối dưới đây. Không cần chạy bước 2 trước nếu làm bước này ngay.

Khi được hỏi, dán đường dẫn thư mục trên chính máy kia, không phải đường dẫn trên máy của bạn. Đường dẫn lấy từ thanh địa chỉ File Explorer. Nhấn Enter để bỏ qua phần chưa biết. Thư mục AI phải là nơi có mã `.py`, không phải thư mục môi trường ảo `.venv`.

```powershell
Set-Location "$HOME\Downloads"
$thuMucProject = (Read-Host "Thu muc chua Compose/Dockerfile (Enter de bo qua)").Trim().Trim('"')
$thuMucAI = (Read-Host "Thu muc ma nguon AI (Enter de bo qua)").Trim().Trim('"')
$thuMucModel = (Read-Host "Thu muc model co model.json/features.json (Enter de bo qua)").Trim().Trim('"')
$thamSo = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\Export-SOC-Research.ps1')
if ($thuMucProject) { $thamSo += @('-ProjectPath', $thuMucProject) }
if ($thuMucAI) { $thamSo += @('-AIPath', $thuMucAI) }
if ($thuMucModel) { $thamSo += @('-ModelPath', $thuMucModel) }
& powershell.exe @thamSo
```

Mỗi lần chạy tạo một thư mục và ZIP mới; không ghi đè lần trước. Nếu bước 3 đủ thông tin thì gửi gói bước 3, không cần gửi cả hai.

Không có mã nguồn AI trên host thì gói vẫn có command, mount, mạng và tên biến môi trường của container AI nếu nhận diện được. Phần source trong image hoặc repo riêng sẽ cần cung cấp sau; script không giả định đã lấy được nó.

## 4. Gửi file nào

Cuối màn hình có dòng `DONE:` chỉ đường dẫn ZIP, thường là:

```text
Downloads\SOC-Research-Exports\SOC-Research-YYYYMMDD-HHMMSS-xxxxxx.zip
```

Mở thư mục cùng tên trước, đọc `COLLECTION-NOTES.txt` và xem các file đã xuất. Sau khi người sở hữu lab đồng ý chia sẻ và đã xem lại dữ liệu, tải ZIP lên cuộc trò chuyện này. Không cần đẩy lên GitHub.

Lọc thông tin nhạy cảm là **best-effort**, không bảo đảm nhận ra mọi mật khẩu viết cứng trong code hay cú pháp tùy chỉnh. Script chủ động bỏ qua các file khóa, `.env`, kho thông tin đăng nhập, cookie, log thô, dataset và trọng số. Cần xem lại code/config trước khi chia sẻ; địa chỉ IP nội bộ, tên máy, username và đường dẫn cá nhân có thể còn trong gói.

## 5. Gói chứa gì

| Phần | Nội dung |
|---|---|
| Docker | Phiên bản; container names/images/status; metadata đã lọc gồm command, mounts, network, ports, capabilities, restart policy và tên biến môi trường |
| Compose | File gốc từ Compose labels nếu đọc được trên host; cấu hình và Dockerfile từ `ProjectPath` nếu chỉ định |
| Ubuntu | OS/packages, tiến trình không kèm arguments, interface/routes/listening ports; SSH, sudo, rsyslog/journald, audit và startup files theo danh sách |
| Suricata | Build info, command line của Suricata, YAML, custom rules và inventory rules; file lớn chỉ ghi metadata/hash |
| Wazuh | `ossec.conf`, local rules/decoders, shared agent config, internal options; một số cấu hình Filebeat/indexer/dashboard; service/agent status nếu có công cụ |
| AI | Code và text config trong `AIPath`; bỏ qua venv, `data`, `dataset`, `output*`, logs, live outputs, runs và checkpoints |
| Model | Một số JSON metadata và requirements trong `ModelPath`, gồm `metadata_v4.json` hoặc các bản tương tự; không lấy weights/checkpoint |
| Bằng chứng thu thập | Command, exit code, stdout/stderr; danh sách file nguồn; ghi chú thiếu/lỗi; SHA256 của các file đã lọc |

Không chạy `docker compose config` vì lệnh đó có thể đưa giá trị secret từ môi trường vào output. Không ghi raw `docker inspect` hoặc toàn bộ environment. Không đọc nội dung auth/HTTP/EVE/alerts logs.

File config trong container giới hạn 512 KiB/file, tổng 120 file / 8 MiB mỗi container. File trên host giới hạn 1 MiB/file, tổng 300 file / 20 MiB. File vượt giới hạn, symlink/junction và lỗi đọc được ghi rõ. Đọc các ghi chú trước khi kết luận thành phần nào vắng mặt.

Bản đã lọc dùng để phân tích, không phải backup để restore hoặc mã nguồn đem chạy lại. Thu được cấu hình không chứng minh hệ thống đang hoạt động đầu cuối.

Bộ lọc đã được bổ sung sau khi xem gói Lab B: các thư mục `data` và `output*`, cùng tên file kết quả phổ biến như `anomaly_scores*.json`/`attack_chains.json`, được bỏ qua. Bản đầu có thể đã lấy các JSON này khi quét cả thư mục project. Vẫn cần kiểm tra gói trước khi chia sẻ.

## 6. Nếu có lỗi

- **Docker không kết nối được:** mở Docker Desktop, đợi engine sẵn sàng, kiểm tra `docker ps -a`, rồi chạy lại script. Gói lần lỗi vẫn giữ thông tin chẩn đoán.
- **Container đang dừng:** gửi gói hiện có trước. Nó có metadata nhưng thiếu file bên trong; không cần khởi động mọi container chỉ để trích xuất.
- **`sh` không tồn tại hoặc không đọc được file:** xem `config-and-status.txt`; script giữ lỗi để phân tích, không tự sửa container.
- **Không tìm được Compose từ label:** label có thể trỏ đến đường dẫn của máy/build cũ. Dùng `ProjectPath` đúng trên host hiện tại hoặc gửi riêng Compose sau khi bỏ secret.
- **Thư mục AI quá rộng:** chọn đúng thư mục source, tránh chọn cả ổ đĩa hoặc toàn bộ kho dataset. Các phần bị giới hạn được ghi trong notes.

## 7. Mức kiểm thử của bộ công cụ

Script được kiểm tra cú pháp và chạy thử bằng PowerShell 7.4.6 trên Linux với Docker giả lập. Các phép thử kiểm tra lọc secret, chọn container, container dừng, lỗi lệnh, xuất source/model metadata, bỏ qua file nhạy cảm/symlink/file lớn, ZIP và checksum.

Chưa chạy trên Windows PowerShell 5.1 hoặc Docker lab thực của người sở hữu. Cần đọc kết quả lần chạy thực để xác nhận phần nào đã thu đủ.
