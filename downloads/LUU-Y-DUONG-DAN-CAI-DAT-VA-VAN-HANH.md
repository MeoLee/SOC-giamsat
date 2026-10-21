# SOC-AI Lab — Lưu ý về đường dẫn, cài đặt và vận hành

Tài liệu bổ sung cho `HUONG-DAN.md` và `Install-Lab.ps1`. Áp dụng cho bộ Compose đang được đóng gói; không thay thế việc kiểm thử cài đặt toàn bộ trên máy mới.

## 1. Chọn đúng cách chạy

| Cách sử dụng | Cần chuẩn bị |
|---|---|
| Lab Compose: Wazuh + endpoint + Kali + AI suy luận | Docker Desktop Linux containers, Compose V2 và toàn bộ bộ nộp |
| Training Dashboard chạy ngoài Docker | Python, dependency training, nguồn backend/HTML và dữ liệu trên máy chạy backend |

Bộ cài Compose không tự cài Python training trên Windows, tự tải dataset training hoặc tự chuyển đường dẫn dataset cũ sang máy mới.

## 2. Có phải sửa đường dẫn khi sang máy khác?

**Không cần sửa thư mục gốc của bộ Compose**, nếu giữ nguyên cấu trúc bên trong và dùng các script đã cung cấp.

Ví dụ đều hợp lệ về cấu trúc:

```text
E:\SOC-Lab\Bai-Nop\SOC-AI-Lab\
D:\DoAn\SOC-AI-Lab\
C:\Users\Teacher\Documents\SOC-AI-Lab\
```

Nên dùng một thư mục trên ổ đĩa cục bộ, không đặt trực tiếp trong ZIP. Ưu tiên đường dẫn ngắn, dễ đọc; khoảng trắng không mặc định là lỗi nếu được trích dẫn đúng. Tránh thư mục đồng bộ cloud hoặc ổ mạng trong lần cài đầu để giảm vấn đề quyền và bind mount.

Các script hiện có dùng PowerShell Windows. Không coi việc chuyển folder sang Linux/macOS là đủ để chạy nguyên các script đó; cần PowerShell/launcher tương thích và kiểm thử riêng.

## 3. Bốn loại đường dẫn cần phân biệt

| Loại | Ví dụ | Ý nghĩa |
|---|---|---|
| Đường dẫn host | `D:\DoAn\SOC-AI-Lab` | Nơi giải nén bộ nộp trên máy |
| Đường dẫn tương đối Compose | `./model/mlp04-quality` | Tính từ thư mục Compose chính trong cách gọi hiện tại |
| Đường dẫn trong container | `/opt/soc/model` | Nơi ứng dụng trong container nhìn thấy model |
| Đường dẫn Docker volume | Volume database/indexer | Do Docker quản lý, không phải thư mục model/data của project |

Ví dụ mount:

```yaml
volumes:
  - ./model/mlp04-quality:/opt/soc/model:ro
  - ./data:/data
```

- Bên trái: thư mục trên máy host, được giải từ vị trí Compose.
- Bên phải: đường dẫn Linux trong container.
- `:ro`: chỉ đọc; model không được ghi ngược từ container.
- Thay thư mục gốc trên host không yêu cầu đổi `/opt/soc/model`.

## 4. Cơ chế xác định thư mục gốc

| Thành phần | Cách xác định |
|---|---|
| `Install-Lab.ps1` | `$PSScriptRoot`: thư mục chứa bộ cài |
| Script trong `scripts/` | Lấy thư mục cha của `$PSScriptRoot` làm project root |
| Compose | Đường dẫn tương đối từ file Compose chính |
| AI trong container | `/opt/soc/ai`, `/opt/soc/model`, `/opt/soc/config`, `/data` |

Bộ cài không quét và sửa mọi chuỗi đường dẫn trong tất cả file. Nó sử dụng cấu trúc đã quy định. Các tham chiếu tuyệt đối còn sót trong cấu hình/script khác vẫn phải được kiểm tra nếu chúng thực sự được sử dụng.

Lệnh nhập tay bên ngoài các script có thể phụ thuộc thư mục terminal hiện tại. Ví dụ `docker compose -f compose.yaml ...` cần được gọi tại folder chứa file đó, hoặc truyền đường dẫn Compose đúng.

## 5. Mở và chạy trong VS Code

1. Giải nén toàn bộ bộ nộp.
2. Chọn **File → Open Folder** và mở folder chứa `compose.yaml`.
3. Mở **Terminal → New Terminal**, chọn PowerShell.
4. Kiểm tra:

```powershell
Get-Location
Test-Path .\compose.yaml
Test-Path .\Install-Lab.ps1
```

Hai dòng kiểm tra file phải là `True`.

5. Chạy bộ cài:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Lab.ps1
```

Nếu đang đứng ở thư mục khác, có thể gọi bộ cài bằng đường dẫn đầy đủ:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'D:\DoAn\SOC-AI-Lab\Install-Lab.ps1'
```

Không dán các ký hiệu `PS>`, `>>` hoặc prompt Kali vào terminal. Mở riêng `compose.yaml` không hiển thị đầy đủ cây thư mục; phải mở cả folder trong VS Code.

## 6. Giữ nguyên cấu trúc bên trong

Có thể đổi tên folder ngoài cùng trước khi cài. Không tùy ý đổi các tên sau:

```text
ai/
model/mlp04-quality/
config/ai/
config/endpoint/
config/suricata/
config/wazuh/
docker/
scripts/
dashboards/
compose.yaml
generate-certs.yaml
```

Dockerfile, Compose và script tham chiếu trực tiếp các vị trí này. Nếu đổi, phải cập nhật tất cả tham chiếu liên quan.

Không chỉ gửi một mình `compose.yaml`: file đó không chứa mã nguồn, model, rule, database hoặc dashboard đi kèm.

## 7. Đổi tên hoặc chuyển folder sau khi đã triển khai

Trước khi chuyển:

1. Dừng phiên AI bằng Ctrl+C và chờ đóng capture.
2. Từ vị trí cũ, chạy:

```powershell
docker compose -f compose.yaml stop
```

3. Chuyển/đổi tên **toàn bộ** folder, gồm file ẩn `.env`, cấu hình và dữ liệu cần giữ.
4. Mở lại folder mới trong VS Code.
5. Từ vị trí mới, chạy:

```powershell
docker compose -f compose.yaml up -d wazuh.indexer wazuh.manager wazuh.dashboard endpoint kali
```

6. Kiểm tra mount và trạng thái trước khi bật AI.

`docker start` đơn thuần có thể giữ bind mount của container cũ; không dùng nó để mặc định cập nhật đường dẫn sau khi chuyển folder. Compose có thể cần tạo lại container để dùng mount mới.

Project name hiện là `soc-ai-submission`, container có tên cố định. Đổi tên folder không tạo ra một bản lab độc lập. Muốn chạy hai bộ đồng thời phải đổi project/container name, cổng, mạng và cấu hình AI tương ứng.

## 8. Dữ liệu nào đi theo folder, dữ liệu nào không?

| Dữ liệu | Vị trí | Chép folder có mang theo không? |
|---|---|---|
| Mã nguồn, Dockerfile, rule, cấu hình mẫu | Project | Có |
| Model cuối | `model/mlp04-quality` | Có |
| Session AI đã lưu | `data/monitor-sessions` | Có nếu không loại bỏ |
| Thông số/mật khẩu triển khai | `.env` | Có nếu chép file ẩn |
| Chứng chỉ Wazuh đã sinh | `config/wazuh/config/wazuh_indexer_ssl_certs` | Có nếu được chép |
| Database DVWA dùng để khởi tạo | `config/endpoint/database/dvwa.sql` | Có |
| Database DVWA đang vận hành | Docker volume | Không tự đi theo folder |
| Alert/index Wazuh, cấu hình manager/agent | Docker volumes | Không tự đi theo folder |
| Image Docker đã build | Docker image store | Không tự đi theo folder |

Máy mới sẽ build/tải image và tạo volume mới. Chép folder không phải bản backup đầy đủ của lab đang vận hành.

`E:\DockerData` là nơi Docker Desktop của máy tác giả lưu dữ liệu. Máy khác không cần có đường dẫn này. Không sửa/chuyển trực tiếp kho dữ liệu Docker để cài bộ nộp.

## 9. IP/subnet là cấu hình riêng, không phải đường dẫn

Mặc định bộ Compose:

| Thành phần | Giá trị |
|---|---|
| Subnet lab | `172.30.20.0/24` |
| Endpoint | `172.30.20.3` |
| Kali | `172.30.20.4` |
| Wazuh manager DNS trong mạng Docker | `wazuh.manager` |
| Dashboard trên máy host | `https://localhost:8443` |

Chuyển folder không tự đổi IP. Nếu trùng subnet với VPN/mạng máy thầy, phải cập nhật đồng bộ:

1. `LAB_SUBNET`, `ENDPOINT_IP`, `KALI_IP` trong `.env`.
2. Asset IP trong `config/ai/live-config.json`.
3. `HOME_NET` trong `config/suricata/suricata.yaml`.
4. Rule, helper hoặc script có IP/CIDR cố định nếu có.

Helper có thể kiểm tra phạm vi đích riêng. Không suy ra chỉ sửa `.env` là mọi helper tự chấp nhận subnet mới. Sau khi đổi cấu hình COPY vào image, phải build lại image tương ứng.

Lệnh hướng dẫn cũ dùng `172.20.0.3` thuộc lab gốc. Với bộ mới, kiểm tra biến `$TARGET` trong Kali trước khi thử.

## 10. .env, mật khẩu và VirusTotal

- Bộ cài tạo `.env` từ `.env.example` nếu chưa có và giữ nguyên nếu đã có.
- `LAB_SSH_PASSWORD` dành cho SSH `soctest`.
- `DVWA_DB_PASSWORD` dành cho kết nối database DVWA.
- Hai giá trị này không mặc định là mật khẩu Wazuh Dashboard hoặc tài khoản web DVWA.
- API key VirusTotal nhập riêng qua prompt ẩn, không nhập vào trường mật khẩu SSH.
- Key VT được lưu trong cấu hình manager và có thể tồn tại trong backup cấu hình.
- Stop/start container giữ volume thì thường không cần nhập lại key. Volume trống/cấu hình bị thay thế có thể cần thiết lập lại.

Cấu hình VT sau khi lab đã được Initialize thành công:

```powershell
docker compose -f compose.yaml --profile monitor run --rm --no-deps ai python setup_virustotal.py --manager soc-submit-manager
```

Không đưa key vào command line, ảnh hoặc tài liệu công khai. Khi bàn giao một bộ còn giữ mật khẩu/key của lab cũ, người nhận cần biết đó là cấu hình đã có; không coi đây là bộ credential mới tự sinh hoàn toàn.

Chứng chỉ TLS mới phải khớp giữa các dịch vụ. Không xóa hoặc sinh lại CA tùy tiện khi indexer/manager đã có dữ liệu và cấu hình tin cậy cũ.

## 11. Training Dashboard chạy ngoài Compose

Đường dẫn dưới đây phải thay theo máy chạy backend:

- Python interpreter/môi trường ảo.
- Thư mục mã nguồn training.
- `--root` của Training Dashboard.
- Dataset cohort, prepared và run.

Ví dụ:

```powershell
Set-Location 'D:\DoAn\Training-Source'
$py = 'D:\Python-Envs\soc-training\Scripts\python.exe'
& $py -m soc_ai dashboard --root 'D:\SOC-Research' --port 8765
```

Mở `http://127.0.0.1:8765`. Không double-click HTML để thay cho chạy backend.

Đường dẫn nhập trên form được backend đọc trên máy của nó. Nếu truy cập từ trình duyệt ở máy khác, không nhập đường dẫn chỉ tồn tại trên máy trình duyệt.

Run cũ có thể lưu `hyperparameters.prepared_path` tuyệt đối của máy tác giả. Việc chọn run cũ có thể nạp lại đường dẫn đó lên form. Không sửa trọng số/hash để che việc thiếu dữ liệu. Muốn train/resume trên máy mới, phải có đúng dữ liệu và xử lý đường dẫn/cấu hình theo cơ chế của backend/checkpoint; không mặc định đổi ô form là resume đã chuyển dữ liệu thành công.

## 12. Vận hành hằng ngày

Tại thư mục bộ nộp:

```powershell
# Bật hạ tầng.
docker compose -f compose.yaml up -d wazuh.indexer wazuh.manager wazuh.dashboard endpoint kali

# Xem trạng thái.
docker compose -f compose.yaml ps -a

# Bật AI sau khi dịch vụ sẵn sàng.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-AI.ps1
```

Đợi READY rồi mới thực hiện kịch bản. Không chạy nhiều monitor cùng nguồn mà chưa có thiết kế chống trùng.

AI chạy qua `compose run --rm`; phiên có thể mang tên container tự sinh. Theo dõi ngay terminal Start-AI, không mặc định container luôn tên `soc-submit-ai`.

Dashboard: `https://localhost:8443`. Import `dashboards/Attack-Chain.ndjson` một lần hoặc khi cập nhật. Chọn đúng thời gian; native VT/FIM có thể không có session ID của AI.

Khi kết thúc: Ctrl+C ở terminal AI, đợi capture đóng, sau đó:

```powershell
docker compose -f compose.yaml stop
```

Không dùng `down -v` nếu còn cần dữ liệu Wazuh, database, agent key hoặc cấu hình integration.

## 13. Thay file nào thì cần làm gì?

| Thay đổi | Thao tác tiếp theo |
|---|---|
| Mã AI/HTML nằm trong image AI | Build lại image AI; tạo phiên/container mới |
| HTML của training chạy trực tiếp trên host | Thay đúng file nguồn rồi Ctrl+F5; khởi động lại backend nếu cần |
| Model được mount read-only | Thay toàn bộ bundle nhất quán, dừng và bật phiên AI mới |
| `config/ai/live-config.json` được bind mount | Dừng/bật lại phiên AI để nạp cấu hình mới |
| Suricata/config endpoint được COPY vào image | Build lại endpoint và tạo lại container; xem ảnh hưởng volume trước |
| `.env` hoặc cấu hình Compose | Chạy lại `docker compose up` để áp dụng; `docker restart` không mặc định nạp env mới |
| Rule Wazuh | Dùng bước cài rule của project và cơ chế kiểm tra/restart tương ứng |

**Lưu ý volume che nội dung image:** `/var/ossec/etc` và `/etc/ssh` của endpoint đang dùng named volume. Build lại image không tự thay các file cũ đã có trong volume. Database volume đã khởi tạo cũng không tự import lại SQL mới. Không xóa volume để áp dụng thay đổi nếu chưa có phương án backup/migration.

Không trộn trọng số, model.json, preprocessor và features của các run khác nhau.

## 14. Docker Desktop và quyền truy cập

- Docker phải chạy Linux containers.
- Host folder phải được Docker Desktop truy cập; kiểm tra sharing/quyền nếu bind mount thất bại.
- Script PowerShell dùng ExecutionPolicy Bypass cho tiến trình gọi, không yêu cầu đổi policy toàn máy.
- Script cài không tự cài Docker Desktop hoặc driver GPU.
- AI dùng Docker socket để gọi Docker CLI. Quyền này tương đương khả năng điều khiển Docker daemon; chỉ dùng trong lab tin cậy.
- Endpoint/Kali hiện không yêu cầu `privileged: true`. Không bật privileged chỉ để dập cảnh báo.

Một dòng stderr màu đỏ không luôn là lỗi dừng dịch vụ. Đối chiếu exit code, trạng thái và log thực tế.

## 15. Cài đặt hoàn tất khác với nghiệm thu phát hiện

Bộ cài build/start/initialize không thay thế kiểm thử chuỗi hành vi.

Trước khi bàn giao cần xác nhận:

- AI image build được.
- Wazuh indexer/manager/dashboard khởi động và kết nối đúng.
- Endpoint phục vụ web/database/SSH; Suricata và log hoạt động.
- Agent kết nối; custom rule và bridge đã cài.
- AI nạp đúng model, thu đúng nguồn và READY.
- Threat Hunting có event; Attack Chain có các bước với bằng chứng.
- VT hoạt động nếu cấu hình riêng.
- Stop/start và chuyển folder không làm dùng nhầm mount/cấu hình.

Nếu có lỗi, lưu command, log, trạng thái và cấu hình liên quan; che key/password. Không sửa raw evidence hoặc metadata chỉ để làm kiểm tra vượt qua.

## 16. Checklist trước khi cài trên máy thầy

- [ ] Giải nén đầy đủ, mở đúng folder trong VS Code.
- [ ] Docker Desktop Linux containers và Compose V2 hoạt động.
- [ ] Còn đủ tài nguyên và Internet cho lần build đầu.
- [ ] Không trùng cổng, subnet hoặc tên container với bản lab khác.
- [ ] `.env` đúng mục đích; biết phân biệt mật khẩu SSH, DB và Wazuh.
- [ ] Model bundle đầy đủ, không có đường dẫn host cá nhân bắt buộc trong launcher.
- [ ] Dataset/prepared riêng được cung cấp nếu cần training.
- [ ] Biết dữ liệu nào nằm trong folder, dữ liệu nào nằm ở volume.
- [ ] Biết cách dừng AI an toàn, không dùng `down -v` ngoài kế hoạch.
- [ ] Ghi rõ trạng thái đã/chưa kiểm thử end-to-end của bộ bàn giao.
