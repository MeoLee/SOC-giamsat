# 0.4.10 — Severity theo bằng chứng, không chỉ theo tên công cụ

## Đối chiếu thang Wazuh

Ảnh dashboard của bạn phân nhóm `rule.level`: **Low 0–6, Medium 7–11,
High 12–14, Critical ≥15**. Rule level 0 bị bỏ qua; với cấu hình alert threshold
mặc định, không phải mọi level thấp đều được ghi thành alert/index.

Tài liệu Wazuh mô tả level 10 là nhiều lỗi do người dùng (ví dụ sai mật khẩu),
11 là cảnh báo integrity, 12 là sự kiện quan trọng có thể nhằm vào ứng dụng,
13 là mẫu tấn công phổ biến, 14 thường là sự kiện bảo mật quan trọng qua
correlation; 15 là severe attack cần xử lý ngay. Mô tả level 15 của tài liệu
rất nghiêm ngặt về false positive; trong thực tế vẫn cần kiểm chứng dữ liệu,
ngữ cảnh tài sản và hành vi được phép.

Severity là ưu tiên xử lý của alert, không phải chứng nhận khai thác thành
công. `risk_score` 0–100 của Lab A, xác suất softmax MLP và tiến độ chain là
các đại lượng khác. Risk 95 không tự chuyển thành level 15.

## Chính sách triển khai

| Bằng chứng | Wazuh level | Lý do |
|---|---:|---|
| HTTP/auth bình thường | 3 — Low | Observation |
| MLP dự đoán bất thường, chưa xác minh | 5 — Low | Không dùng dự đoán riêng lẻ làm kết luận xâm nhập |
| Quét nhiều cổng đã đạt ngưỡng | 8 — Medium | Recon đã quan sát; chưa có thâm nhập |
| Nhiều lần sai mật khẩu, chưa success | 10 — Medium | Phù hợp mô tả level 10; kiểm tra reset/lockout riêng |
| Login thành công sau chuỗi thất bại | 13 — High | Correlation đáng điều tra; chưa chứng minh account bị đánh cắp |
| SQLi indicator trong HTTP server evidence | 12 — High | Có payload/mẫu khai thác nhắm ứng dụng; vẫn là attempt |
| Suricata SQLi SID 9900101/9900102 | 12 — High | Chỉ nâng các SID đã biết; không nâng mọi alert mạng |
| Generic sensor alert | 8 — Medium | Chưa đủ bối cảnh để áp dụng High đồng loạt |
| Chain có risk_level=high theo policy hiện tại | 12 — High | Nâng ưu tiên correlation, chưa khẳng định compromise |
| File có hash dương tính từ VirusTotal | 12 — High | Giữ native 87105; chưa chứng minh file đã chạy |
| Chỉ tạo PHP/file mới hoặc file bị sửa | Giữ mức hiện tại | Extension/FIM không đủ kết luận malware hoặc execution |
| Thâm nhập/tác động nghiêm trọng có bằng chứng đáng tin cậy | 15 — Critical khi detector đủ chứng cứ | Cần xác nhận hành vi/quyền/tác động và loại trừ hoạt động được phép |

Thay đổi XML: `119204: 12→10`, `119206: 8→12`, `119214: 10→12`, thêm
`119215 level 12` là rule con của 119209, chỉ nhận signature_id 9900101 hoặc
9900102. Giữ 119205 level 13 và native 87105 level 12. Không sửa file ruleset
vendor; tất cả thay đổi Lab A nằm trong `/var/ossec/etc/rules/`.

SQLi native Apache/Suricata vẫn có thể phát alert ở level khác. Hai alert
mang bằng chứng/ý nghĩa khác nhau không cần cùng level. Widget tính alert,
không đếm số cuộc tấn công duy nhất. Nâng rule chỉ áp dụng **alert mới**, không
sửa severity của log đã index; không xóa index để làm đẹp các bộ đếm.

## Khi nào dùng Critical?

Không nâng Critical chỉ vì "chuẩn bị leo thang", một shell command, một IP
đáng ngờ, một file hash dương tính hoặc nhiều node trong graph. Ví dụ phù hợp
để xây detector Critical sau này:

- Tiến trình khai thác liên kết được với phiên xâm nhập, sau đó thực sự chuyển
  từ user không đặc quyền sang effective UID 0 trái phép, có process/audit và
  thời điểm/parent/session để đối chiếu.
- File bị nhận diện độc hại **đã được thực thi**, có process tree và bằng chứng
  persistence/C2 hoặc tác động xác minh được trên tài sản quan trọng.
- Mã hóa/phá hủy dữ liệu đang diễn ra, truy cập đặc quyền trái phép hoặc tác
  động nghiêm trọng được xác minh; không bắt buộc phải có leo thang trước đó.

Một lệnh `sudo` hợp lệ của quản trị viên hoặc probe shell cố định trong lab
không phải Critical. "Tấn công sâu" cần được diễn đạt bằng chứng cụ thể:
execution, account/privilege, persistence, credential access, impact.

Hiện Lab A chưa có general process/audit telemetry để tự xác minh các điều
kiện này; bản 0.4.10 **không thêm rule Critical chỉ chờ field tự khai báo**.
Native Wazuh vẫn có thể phát Critical nếu rule gốc của nó match bằng chứng
khác. Việc ô Critical còn 0 trong bài SQLi attempt/EICAR là kết quả phù hợp.

## VirusTotal và EICAR

Native 87105 level 12 khi `virustotal.malicious=1`; integration 4.14.7 đặt cờ
này khi report có ít nhất một engine dương tính. Một engine có thể false
positive; xem tỷ lệ, ngày scan, file hash, ngữ cảnh và execution. `found=0`
nghĩa là chưa có record; `positives=0` cũng chưa chứng minh file an toàn.

EICAR là test vector antivirus vô hại đã được nhận diện rộng rãi. Nó kiểm
tra đường FIM → hash lookup → Wazuh alert → dashboard, không phải bằng chứng
máy đã nhiễm malware. Không tải malware sống hoặc tạo reverse shell cho bài
kiểm thử này. Không tự nâng EICAR lên Critical.

Native 87105 có mapping ATT&CK T1203 của vendor. Hash report đơn lẻ không xác
minh T1203 đã xảy ra; không dùng mapping đó làm chứng cứ khai thác thành công.

## Nguồn đã đối chiếu

- [Wazuh — Rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html).
- [Wazuh — Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).
- [Wazuh — VirusTotal integration](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html).
- [Wazuh 4.14.7 — Native VirusTotal rules, gồm 87105 level 12](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0490-virustotal_rules.xml).
- [Wazuh 4.14.7 — Native integration source](https://github.com/wazuh/wazuh/blob/v4.14.7/integrations/virustotal.py).
- [Wazuh — Integrator configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html).
- [VirusTotal — Public/Premium API](https://developers.virustotal.com/reference/public-vs-premium-api).
- [EICAR — Anti Malware Testfile](https://www.eicar.org/download-anti-malware-testfile/).

Native code 4.14.7 dùng GET tới API v2 `/vtapi/v2/file/report`, gửi MD5 từ
FIM; không có upload nội dung. Tài liệu tổng quan có đoạn mô tả POST; bản
triển khai này đối chiếu đúng source của version bạn đang dùng. Không thay
bằng API v3 hoặc giả định key/quota hợp lệ khi chưa test live.

[Chỉ một kịch bản tiếp theo: VT-01 — control và EICAR](VIRUSTOTAL-01-VI.md).
[Phạm vi kiểm chứng](validation-0410.json).
