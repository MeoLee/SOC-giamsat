# SOC Web Lab v0.1 — Apache + DVWA trên Ubuntu hiện tại

Đây là bước dựng mục tiêu web trước khi cập nhật detection web. Đặt trong ubuntu-endpoint để Suricata và agent hiện tại có thể quan sát request Kali gửi thẳng tới máy đó. Cài theo bộ package Linux chính thức của DVWA; không tạo thêm web target/container, không đổi IP và không sửa trọng số AI.

## Chạy

Giữ Docker và các container lab chạy. Nếu watcher đang chạy, Ctrl+C và đợi LIVE_DONE trước khi cài; sau cài có thể bật watcher lại bằng launcher hiện có.

Giải nén ZIP ra E:\SOC-Lab\tools\SOC-Web-Lab-v0.1. Mở Windows PowerShell mới trên máy vật lý, dùng Python 3.12 từ môi trường inference (bộ cài chỉ dùng thư viện chuẩn).

python setup_web_lab.py

Lệnh này chạy apt update/install trong Ubuntu, clone DVWA chính thức, ghi revision để tái dựng, cài cấu hình Apache riêng và kiểm tra syntax, khởi động MariaDB/Apache, tạo database nếu mới và trống, khởi tạo bảng DVWA, thêm localfile access/error vào Wazuh agent và restart agent nếu cấu hình đổi. Cuối cùng thêm block web autostart riêng vào /root/.bashrc với điều kiện PID1, giữ các block SSH/Suricata hiện có. Không tạo backup dài hạn. Không reset database có sẵn dữ liệu.

Cần có WEB_LAB_READY. Nếu lỗi, dừng ở lỗi đó và giữ toàn bộ stdout/stderr; không chạy các kịch bản tải. Kiểm thử local trong ZIP chỉ kiểm tra logic chỉnh cấu hình, không thay cho cài thử trên Docker của bạn. Không dùng systemctl vì container hiện chạy PID1 Bash. Autostart hiện phụ thuộc Bash đọc .bashrc; khi chuyển thành Compose với entrypoint riêng phải gọi start-soc-web.sh trong entrypoint.

## Xác nhận từ Kali

Mở Windows PowerShell thứ hai: docker exec -it kali-attacker bash
Sau đó Bash Kali:

curl -fsS http://172.20.0.3/soc-lab-health
curl -sS -o /dev/null -w 'DVWA HTTP=%{http_code}\n' http://172.20.0.3/dvwa/login.php

Kết quả SOC_WEB_OK và HTTP=200. DVWA dùng login mặc định admin / password, security mặc định low. Chưa mở cổng ra Windows/LAN/Internet; browser Windows không tự truy cập được IP bridge như Kali. Nếu cần giao diện browser Windows, bước sau có thể thêm đường truy cập localhost riêng mà không đổi sensor/target.

## File tạo bên trong endpoint

- /opt/soc-lab/DVWA: source upstream và config riêng.
- /opt/soc-lab/web-install.json: trạng thái cài và git revision.
- /etc/apache2/conf-available/soc-lab-web.conf: alias và GlobalLog, giới hạn lab CIDR.
- /usr/local/sbin/start-soc-web.sh: bật MariaDB loopback và Apache, không dùng systemd.
- /var/log/apache2/soc-lab-access.log: combined cho Wazuh.
- /var/log/apache2/soc-lab-requests.tsv: start/end microsecond epoch, client IP/port, server IP/port, method, URI/query, HTTP status, response bytes, duration microseconds, user agent. Apache escaping áp dụng; đây không phải JSON.
- /var/log/apache2/error.log: error log mặc định.

Alias DVWA/health chỉ cho loopback và 172.20.0.0/24; có thể chọn subnet khác bằng --lab-cidr. Đây là ACL của dịch vụ vulnerable, không phải bộ lọc IP attacker của AI. MariaDB khi script tự khởi động chỉ bind 127.0.0.1. Không đưa vulnerable web ra Internet. Không thay HOME_NET hoặc tắt các biện pháp bảo vệ host.

## Tái sử dụng khi nộp bài

Source DVWA lấy từ upstream lúc cài và commit được ghi nhận. Gói v0.1 chưa là Compose đầy đủ; khi đóng gói nộp bài cần pin revision này, đưa package/config/startup vào Dockerfile/entrypoint và mount log/data phù hợp. Sao chép file compose không tự mang theo package đã cài trong writable layer của container hiện tại.

Xem SCENARIOS.md cho thứ tự kịch bản và thiết kế detection/AI. Gói chưa thêm khả năng SQLi vào MLP hay web attack chain vào live observer.
