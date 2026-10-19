# SOC AI Live v0.4 — sửa phạm vi giám sát và nối Wazuh

Bản này cập nhật bộ chạy live, không thay soc_ai/, normalizer, checkpoint, model weights hoặc dữ liệu train. Không cần cài thêm thư viện. Dùng Python CPU tại E:\SOC-Lab\AI\.venv-infer\Scripts\python.exe.

## Cài và chạy

Tất cả lệnh dưới đây chạy ở Windows PowerShell trên máy vật lý, không chạy trong Bash Kali. Bật Docker Desktop và các container đang dùng. Nếu watcher cũ đang chạy, Ctrl+C tại cửa sổ đó và đợi kết thúc trước khi chép bản mới.

1. Giải nén ZIP vào thư mục tạm. Chỉ chép các file *.py, *.xml, *.rules, *.md, *.cmd vào project hiện tại. Giữ nguyên live-config.json và correlation-config.json của bạn. ZIP không chứa soc_ai/ hoặc model.
2. Chạy 72 kiểm thử theo hướng dẫn chat. Đây là kiểm thử logic với Docker/predictor giả lập; chưa chứng minh hệ thống Docker của bạn đã nhận cảnh báo.
3. Chạy setup_wazuh.py một lần. Công cụ thêm localfile JSON vào ossec.conf của manager và tạo file soc_ai_bridge_rules.xml riêng. Các file rule cũ được giữ nguyên. Kiểm tra trùng ID, analysisd -t, logcollector -t và sáu logtest trước khi restart Wazuh. Nếu kiểm tra hoặc restart thất bại, khôi phục cấu hình vừa sửa từ bộ nhớ. Không tạo bản backup lâu dài. Sau restart, agent có thể mất kết nối ngắn rồi nối lại.
4. Chạy wazuh_bridge.py --smoke-test --verify-alert để xác nhận rule 119201 thực sự xuất hiện trong alerts.json. Nếu chưa đạt thì chưa coi đường nối Wazuh đã hoàn tất.
5. Chạy lab_live.py --model MODEL_DIR --config live-config.json --output-dir E:\SOC-Lab\AI\live --publish-wazuh. Đợi READY rồi thực hiện hoạt động lab trong cửa sổ khác. Không cần khai báo scenario.

Các lần sau có thể bấm đúp Start-AI-Live.cmd; cần Docker và các dịch vụ sensor/agent chạy sẵn. Không cần VS Code hay dashboard training. CMD mặc định dùng model mlp-lab-20261014-212857; có thể truyền model directory làm tham số đầu tiên.

Ctrl+C ở cửa sổ AI để kết thúc. Đợi LIVE_DONE và trả về dấu nhắc lệnh trước khi đóng cửa sổ hoặc tắt máy. Completed flow thường chỉ xuất hiện sau timeout sensor; grace 10 giây không bảo đảm mọi kết nối đang mở đã được ghi thành flow.

## Phạm vi rõ ràng

- Mặc định không lọc IP. Mọi flow mới mà các nguồn EVE cấu hình ghi ra đều qua normalizer và predictor. --all-flows còn hoạt động để tương thích; --endpoints A B chỉ dùng nếu bạn chủ động yêu cầu giới hạn.
- Tài sản assets trong live-config.json chỉ ánh xạ IP sang host để ghép bằng chứng; không chọn attacker, không lọc flow, không whitelist nguồn.
- Wazuh alerts từ các agent khác cũng được xét. Host trong auth log phải khớp agent.name; trường hợp không khớp được ghi vào correlation-errors.jsonl, không ghép tùy tiện. Agent IP quản trị không được mặc định thay cho IP dịch vụ.
- Chỉ thu những nguồn đã cấu hình. Thêm nguồn bằng sources trong live-config.json, kind=auth/eve/wazuh/web/raw, tên container, đường dẫn log tuyệt đối và output basename duy nhất. Mỗi nguồn eve hiện phải là container có Suricata đang chạy. Thêm asset tương ứng nếu cần ghép network IP với hostname.
- Cấu hình ví dụ hiện có Suricata/auth của Ubuntu và alerts của manager. Không tự triển khai sensor cho container mới, không tự nhìn thấy traffic Kali tới container khác, không tự bật auditd/process telemetry. Traffic không đi qua điểm bắt gói thì cần bố trí sensor khác.
- Không có dữ liệu giải mã SSH/TLS: metadata không phải nội dung lệnh bên trong. HTTP/DNS/TLS metadata chỉ được ghi nếu EVE nguồn đã bật các loại sự kiện đó. Trường hợp cần nội dung lệnh phải bổ sung log ứng dụng/tiến trình phù hợp.
- Chỉ đọc dữ liệu mới từ khi watcher khởi động. Không tự nạp toàn bộ log cũ hoặc replay khoảng thời gian watcher tắt. Các file raw vẫn lưu được dùng riêng cho replay/huấn luyện sau khi xác minh nhãn.

## Giao diện CLI

- SCOPE: ALL OBSERVED FLOWS — không lọc IP.
- SOURCE — từng nguồn log và container.
- [SENSOR] — cảnh báo Suricata quan sát được, nguồn, đích, cổng, chữ ký.
- [HTTP] — request HTTP mới, nguồn, đích, method, status, đường dẫn và dấu hiệu SQL nếu có.
- [AUTH] — đăng nhập thành công/thất bại, nguồn, tài khoản, host đích, số sự kiện trong lượt đọc.
- [AI] — tóm tắt mỗi khoảng 10 giây theo sensor, nguồn, đích, protocol/app, nhãn và decision; có số flow, khoảng cổng đích và score_max.
- [CORRELATION] — case mới hoặc chuyển giai đoạn, kèm nguồn/đích và chuỗi bằng chứng.
- Mặc định console giữ yên lúc không có sự kiện, không lặp LIVE/WAZUH counters. Lỗi gửi và hồi phục chỉ thông báo khi trạng thái thay đổi. Có thể bật bộ đếm bằng --heartbeat-seconds 60.
- WAZUH ERROR/PENDING/RECOVERED — thay đổi trạng thái hàng đợi; append thành công chưa đồng nghĩa indexer/dashboard đã nhận.

Mọi dự đoán chi tiết vẫn nằm trong ai-predictions.jsonl, đầu vào tương ứng trong ai-input-flows.jsonl. Tóm tắt console không thay thế bản ghi từng flow.

## Đầu ra và Wazuh

Thư mục phiên mới: E:\SOC-Lab\AI\live\raw\<UTC>-live-observe-<id>.

- Log gốc: ubuntu-auth.log, suricata-eve.jsonl, wazuh-alerts.jsonl, apache-requests.tsv, apache-access.log (hoặc tên nguồn bạn đặt).
- web-events.jsonl: request HTTP chuẩn hóa, gồm thời gian UTC, IP/cổng, method, URI gốc và query giải mã có giới hạn, status, response bytes, duration_us. Log không chứa HTTP request body.
- ai-input-flows.jsonl, ai-predictions.jsonl, ai-errors.jsonl.
- live-activities.jsonl: metadata quan sát, auth, dự đoán tổng hợp và chuyển trạng thái correlation.
- correlation-events.jsonl, correlation-cases.json, correlation-errors.jsonl: bằng chứng và case.
- ai-session.json: phạm vi, nguồn, model hash, số bản ghi, lỗi gửi Wazuh và số pending.
- session.json/checkpoint.json: trạng thái thu log và hash của file raw.

Hàng đợi chung: E:\SOC-Lab\AI\live\wazuh-outbox.sqlite. Các sự kiện chưa gửi được giữ qua lần chạy mới. Chỉ cho một publisher dùng cùng outbox. Gửi tối đa bốn sự kiện/lượt poll, timeout mỗi lần 5 giây; khi lỗi thử lại sau 15 giây. Hàng đợi giới hạn 10000 tóm tắt; chạm giới hạn thì dừng với lỗi và giữ raw/activities. Không tự xóa log hoặc outbox.

Manager nhận JSONL tại /var/ossec/logs/soc-ai/events.jsonl, sau đó logcollector -> decoder JSON -> custom rules -> alerts.json -> indexer/dashboard theo cấu hình Wazuh hiện có. Log do manager thu thường mang agent.id=000; host được giám sát nằm trong data.target_host/data.target_ip. Không gán giả agent 001.

Rule 119201: kiểm tra kết nối, level 3.
Rule 119202: dự đoán possible_attack tổng hợp, level 5, ghi rõ unverified.
Rule 119203: recon có bằng chứng, level 8.
Rule 119204: nhiều lần sai mật khẩu theo cửa sổ/tài khoản/nguồn/host, level 12.
Rule 119206: SQLi có dấu hiệu từ HTTP/Suricata, level 8; không kết luận khai thác thành công.
Rule 119205: đăng nhập thành công sau chuỗi thất bại, level 13; không kết luận đã bị chiếm quyền.
Lọc Wazuh dashboard bằng rule.groups:soc_ai.

Correlation chỉ gửi khi case mới/chuyển trạng thái hoặc thêm giai đoạn. Số bằng chứng tăng trong cùng giai đoạn vẫn cập nhật ở correlation-cases.json, không phát một cảnh báo mới mỗi lần. Event IDs ổn định, outbox chống enqueue lặp và manager thử chống append lại; truyền nhận vẫn có ngữ nghĩa at-least-once, có thể lặp khi timeout không rõ kết quả. Không tuyên bố exactly-once. Sự kiện AI được loại khỏi đầu vào correlation để tránh vòng lặp.

Muốn đẩy lại hàng đợi khi watcher đã tắt:
python wazuh_bridge.py --outbox E:\SOC-Lab\AI\live\wazuh-outbox.sqlite
Không chạy lệnh này đồng thời watcher đang dùng cùng outbox.

## Giới hạn mô hình còn nguyên

Model có sáu lớp đã train. Những hành vi khác chưa được chứng minh nhận diện, và out_of_training_scope hiện chỉ kiểm tra điều kiện kỹ thuật chứ không phát hiện mọi dữ liệu lạ. Score chưa hiệu chuẩn. Mô hình hiện báo nhầm 8/8 phiên SSH bình thường trong test local; bản runtime này không tuyên bố đã khắc phục lỗi học đó. MLP dự đoán không tự trở thành bằng chứng xác thực, nhãn train hay kết luận compromise.

Correlation hỗ trợ recon -> password failures -> login success và recon -> possible_web_sqli; chưa có logic privilege escalation, thực thi lệnh hay exfiltration. Không tự train, đổi model, chặn IP hoặc xóa log. Giới hạn correlation 50000 sự kiện liên quan/phiên vẫn áp dụng; raw được giữ khi chạm giới hạn.

## Nguồn thiết kế

https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html


## Cập nhật web v0.4

Đóng watcher trước khi chép file. Mọi lệnh Python bên dưới dùng môi trường inference CPU, chạy ở Windows PowerShell trong project SOC-AI-v0.2.

1. Chạy `python -m unittest test_lab_live test_lab_correlation test_live_deployment test_lab_web -v` (72 tests). Thay python bằng đường dẫn `.venv-infer\Scripts\python.exe` của bạn.
2. Chạy `python setup_suricata_web.py`. Công cụ tìm chính xác tiến trình Suricata đang chạy và file -S đang dùng, giữ nguyên rule cũ, kiểm tra cấu hình và PCAP HTTP GET/POST SQLi dương tính cùng request lành tính. Chỉ khi tất cả đạt mới thay file và yêu cầu SIGUSR2 reload. Nếu lỗi, dừng và xem log; không tự bỏ qua kiểm tra. Chúng tôi chỉ chạy unit test ở môi trường tạo gói; việc biên dịch và chạy Suricata thực diễn ra tại bước này trên container của bạn. Yêu cầu reload chưa chứng minh rule live đã hoạt động; request kiểm tra kế tiếp mới xác nhận.
3. Chạy `python setup_wazuh.py` để thêm rule 119206; công cụ kiểm tra sáu logtest và restart manager. Đợi agent kết nối lại.
4. Chạy `python configure_web_live.py --config live-config.json`. Chỉ thêm hai nguồn Apache vào cấu hình đang có, không thay asset hoặc IP. Hai file log phải tồn tại từ Web Lab v0.1.
5. Mở Start-AI-Live.cmd, đợi READY, rồi tạo request trong cửa sổ Kali khác. Dòng HTTP/case xuất hiện khi có bằng chứng mới. Cảnh báo Wazuh mới lọc bằng `rule.id:119206`.

SIDs 9900101 (URI UNION SELECT) và 9900102 (HTTP body UNION SELECT sau url_decode) chỉ là hai chữ ký cục bộ. Không phải bộ ET Open đầy đủ, không bao phủ mọi SQLi, không đọc được nội dung HTTPS. Suricata vẫn chịu giới hạn body/stream trong cấu hình hiện tại. Python HTTP normalizer còn nhận dạng một dạng quoted tautology; đây là heuristic, có thể báo nhầm.

MLP vẫn có sáu lớp cũ, chưa có SQLi. Không đổi Bot thành SQLi hoặc tự gán nhãn train. BENIGN là lớp có xác suất cao nhất nhưng decision possible_attack có thể cùng xuất hiện: ngưỡng binary áp dụng lên tổng xác suất non-BENIGN. Ngưỡng rất thấp và 8/8 SSH normal local vẫn báo nhầm; bản này không tuyên bố sửa được chất lượng model.

### Replay phiên SQLi đã lưu

Dùng phiên đã đóng hoàn toàn (đợi LIVE_DONE). Phiên v0.3 chỉ có ba nguồn; KHÔNG truyền live-config.json mới có năm nguồn vào replay phiên cũ:

```
python lab_correlation.py --session OLD_SESSION --output NEW_REVIEW_DIRECTORY
```

Bộ replay đọc payload SQL từ full_log Apache trong wazuh-alerts.jsonl. Không cần chạy lại MLP hoặc sqlmap. Nếu không còn bản ghi raw Apache trong Wazuh thì không thể tái tạo những request đã thiếu; xem correlation-errors.jsonl. Replay chỉ xuất báo cáo local, không tự đẩy lại Wazuh.

Phiên mới có năm nguồn thì replay với `--config live-config.json` tương ứng nguồn lúc thu.

### Giới hạn bằng chứng

- HTTP 500 là lỗi ứng dụng; HTTP 200 là phản hồi thành công về giao thức, không chứng minh SQLi thành công. Chỉ dấu UNION trong URI cũng chưa chứng minh thực thi SQL. Kết quả sqlmap là bằng chứng thử nghiệm bổ sung độc lập.
- HTTP keep-alive cho phép nhiều request trên một TCP flow; không so sánh số flow MLP với số request như cùng đơn vị.
- Apache, Wazuh và Suricata có thể là các góc nhìn khác nhau của một request. Case lưu evidence views, không tuyên bố tổng evidence_count là số request duy nhất.
- Các case SQLi được nhóm theo nguồn/host và bucket UTC cố định 5 phút. Một đợt qua ranh giới bucket có thể tách thành hai case. Recon trước đó chỉ ghép cùng nguồn/host trong cửa sổ cấu hình.
- normalizer chỉ giải mã query percent/plus tối đa hai lượt; giữ URI gốc. Không HTML-unescape log thật. POST body không có trong Apache journal, chỉ có chữ ký Suricata khi bắt được HTTP plaintext.
- Chưa triển khai HTTP DoS detector, privilege escalation hay exfiltration trong bản này.
