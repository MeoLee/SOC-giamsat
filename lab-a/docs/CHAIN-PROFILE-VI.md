# Lab A 0.4.7 — bấm Chain ID để mở hồ sơ ngay trong Wazuh

Bản này nâng cách đọc chain trên Wazuh Dashboard. **Không cần train lại, cài
probe lại hoặc restart Wazuh.** Hồ sơ đọc các event correlation 0.4.6 đã có;
không sửa model, threshold, log gốc, ngưỡng correlation hoặc cách tính risk.

## Cài nhanh: chỉ import một file

[Tải file Dashboard 0.4.7](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/soc-ai-chain-profile-v0.4.7.ndjson).

1. Trong Wazuh, vào **Dashboards Management → Saved objects → Import**.
2. Chọn `soc-ai-chain-profile-v0.4.7.ndjson`, bật **Automatically overwrite
   conflicts**. Đây là **file đầy đủ 9 objects**, không phải repair 2 objects.
   Không chọn tạo bản sao với ID mới.
3. Import xong, mở **SOC Lab A - Điều tra Chain** và tải lại trang bằng
   Ctrl+F5. Các tiêu đề và hướng dẫn chính chuyển sang tiếng Việt.
4. Bấm một **Chain ID** để mở **SOC Lab A - Hồ sơ Chain**, có bộ lọc đúng
   Chain ID. Muốn giữ cả hai trang, dùng Ctrl+bấm Chain ID để mở tab mới.

Nếu muốn giữ source trên Windows đồng bộ, giải nén bản vá
`SOC-AI-Lab-A-v0.4.7-Chain-Profile-VI-20261020.zip` trực tiếp vào
`E:\SOC-Lab\AI\SOC-AI-v0.4-research`, ghi đè file source tương ứng. File import
cũng có ở `dashboards\soc-ai-chain-investigation.ndjson` trong project; nó có
**cùng nội dung 9 objects** với file tải trực tiếp. **Chỉ import một trong hai**.
Bản vá áp dụng cho source 0.4.6 đã có Doctor fix, không chứa `live-config.json`,
weights, dataset, venv hoặc thông tin đăng nhập. Gói full 0.4.7 dành cho lưu trữ
source/cài mới; không giải nén full đè lên config runtime đã tùy chỉnh.

Các ID của dashboard điều tra được giữ ổn định để import lại cập nhật cùng
bộ object. Dashboard 0.4.5 **Attack Chain & Scoring** được giữ nguyên. Nếu trước
đây có bản sao dashboard với ID khác, bản sao đó không tự đổi: mở dashboard
có ID `soc-ai-chain-investigation-dashboard-v1` trong URL. Không xóa index/log
hoặc visualization dùng chung để dọn dashboard trùng tên.

## Nội dung khi bấm Chain ID

Hồ sơ gồm các thẻ dọc, chữ tự xuống dòng thay vì bị cắt trong ô bảng:

- **Hồ sơ:** Session ID, IP nguồn/đích, host, account, trạng thái, số stage,
  số evidence event duy nhất, thời điểm đầu/cuối và thời lượng.
- **Điểm và phạm vi kết luận:** điểm nền, bonus recon, cap 95, policy và ý
  nghĩa của điểm. Không coi điểm là xác suất tấn công hay công thức MITRE.
- **Lý do ghép chuỗi:** diễn giải gốc của engine và điều kiện cần đối chiếu.
- **Mỗi bước đã quan sát:** tên tiếng Việt, technique ứng viên, thời gian,
  số evidence, điều kiện/ngưỡng, command hoặc URL/bytes/SHA256 nếu event có.
  Kèm diễn giải và bằng chứng cần kiểm tra cho riêng bước đó.
- **Bước tiếp theo có thể xảy ra — CHƯA QUAN SÁT:** gợi ý điều tra theo stage
  cuối, hành vi cần theo dõi và log cần bổ sung để xác nhận.
- **Độ bao phủ/dữ liệu thiếu:** không suy command từ SSH success, không suy
  C2 từ HTTP GET, không suy vắng mặt hành vi từ việc thiếu stage.
- **Truy vết:** đường dẫn hồ sơ local, mẫu evidence IDs và cách đối chiếu raw.
  Bảng bản ghi phía dưới vẫn cho mở toàn bộ field ở Table/JSON.

Cuộn chuột **trong khung hồ sơ** hoặc bấm **▲ / ▼** để đọc phần bên dưới.
Tên field/thuộc tính, giá trị trạng thái kỹ thuật và ATT&CK IDs giữ tiếng Anh.
Các đoạn log/diễn giải engine gốc cũng được giữ nguyên để đối chiếu; phần giải
thích và hướng dẫn đọc là tiếng Việt.

Trang hồ sơ mặc định tìm trong **Last 30 days** và pause auto refresh để đọc
ổn định. Bấm **Refresh** để lấy revision mới, hoặc tự bật lại auto refresh khi
muốn quan sát diễn biến. Trang tổng quan vẫn mặc định refresh 1 giây. Đổi khoảng
thời gian nếu chain cũ hơn 30 ngày. Timestamp chọn thời gian là `timestamp`
Wazuh; thời gian từng bước hiển thị UTC nguồn để đối chiếu chính xác.

Chỉ hiển thị hồ sơ khi bộ lọc trả đúng **một Chain ID trong một Session ID**.
Nếu mở tab hồ sơ trực tiếp và có nhiều chain, hoặc cùng Chain ID có trong hai
phiên capture, trang yêu cầu lọc thêm thay vì tự chọn/ghép nhầm case:

```text
data.chain_id: "CHAIN-..." and data.session_id: "SESSION-..."
```

Mỗi session chọn revision theo `data.event_time` nguồn, rồi `timestamp`
Wazuh. Giữ sửa unmapped sort để đọc được index cũ chưa có `data.event_time`.
Không cộng, lấy trung bình hay đếm các revision như những cuộc tấn công riêng.

## Bước tiếp theo là gợi ý điều tra, không phải dự báo AI

| Stage cuối đã quan sát | Giả thuyết cần theo dõi | Bằng chứng cần thêm |
|---|---|---|
| Quét cổng | Thử thông tin đăng nhập hoặc dò lỗi dịch vụ | SSH/PAM failures, request và log ứng dụng |
| Chuỗi sai mật khẩu | Thử tiếp hoặc đăng nhập thành công | Auth success cùng nguồn/host/account, thời gian và phiên |
| Success sau chuỗi sai | Thực thi lệnh/khám phá host | Process telemetry hoặc probe cùng phiên SSH |
| Shell probe | Tải file/khám phá tiếp | File/process/network và liên kết phiên |
| File probe | Có thể thực thi file, persistence hoặc liên lạc ngoài bài tập | Process tree, file/audit/network; hiện chưa có bằng chứng |
| Dấu hiệu SQLi | Tác động lên ứng dụng/database | Application/DB audit, truy vấn và kết quả liên quan |

Đây là runbook được biên soạn dựa trên bằng chứng/ATT&CK, không phải output
dự báo từ MLP. Các giả thuyết **không được thêm vào observed graph, stage
count, risk score hoặc training labels**. ATT&CK không quy định một thứ tự kỹ
thuật bắt buộc. Có thể không có bước tiếp theo hoặc hành vi có thể hợp lệ.

## Đọc đúng kết quả thực tế bạn đã gửi

Ca `20261020T152630Z-live-observe-46492d` có 7 password failures, 0 success,
0 endpoint events. Runner dừng với `kex_exchange_identification: ... Connection
reset by peer` trước lần sai thứ tám. Thiếu rule 119204/119205; chưa xác minh
chuỗi năm bước. Ngưỡng hiện tại là 8 failures trong 60 giây, nên chỉ có chain
recon 1 stage/40 là kết quả phù hợp. Bản nâng giao diện không tự sinh thêm các
bước chưa chạy. Các failure rời vẫn có ở raw auth/119208 để điều tra.

Chưa đủ bằng chứng để khẳng định nguyên nhân reset. Có thể thu thông tin
**chỉ đọc**, không đổi chính sách SSH/PAM:

```powershell
docker exec ubuntu-endpoint sshd -T | Select-String 'persource|maxstartups|maxauthtries|logingracetime'
docker exec ubuntu-endpoint tail -n 120 /var/log/auth.log
```

Đối chiếu cả bước cuối và timestamp trong `operator.json`. Không tính reset
thành password rejection hoặc hạ ngưỡng để ép ca này thành năm stage.

## Kiểm thử giao diện ngay bằng dữ liệu đã có

Không cần chạy tấn công mới để thử thao tác mở hồ sơ:

1. Trên dashboard Điều tra Chain, chọn Last 30 days hoặc khoảng ngày chứa ca cũ.
2. Lọc `data.session_id: "20261020T152630Z-live-observe-46492d"`.
3. Bấm `CHAIN-673F6F14663EC3D5` trong bảng đầu.
4. Kiểm tra thẻ bước 1: T1046/40, bằng chứng số cổng/ngưỡng/thời gian. Thẻ
   vàng gợi ý theo dõi password guessing/khai thác, ghi rõ **chưa quan sát**.
5. Mở bảng bản ghi dưới hồ sơ để đối chiếu raw fields. Stage count vẫn 1.

Nếu muốn tạo ca mới, dùng `port-scan` với phiên Live mới như quy trình hiện
có. Ca năm bước vẫn dùng `chain-extended` sau khi đã xử lý/đối chiếu SSH reset;
không coi việc dashboard hiển thị đẹp là đã kiểm thử thành công năm bước.

## Giới hạn dữ liệu và thiết kế

Giao diện dùng Vega tích hợp sẵn trong OpenSearch Dashboards, không cài plugin,
web service hay trang HTML bên ngoài Wazuh. Query chỉ đọc `wazuh-alerts-*`,
áp dụng context/time filter. Tối đa 100 Chain IDs và 10 sessions mỗi ID cho
trang không lọc; trang hồ sơ cần lọc đúng một case/phiên. Tên host, path, log
và nội dung khác đều được vẽ như text, không thực thi HTML.

Bản này không tăng kích thước message hoặc thay publisher. Các bản tóm tắt
hiện có giới hạn bằng chứng: node graph của ca >3 bước bỏ evidence IDs để giữ
message dưới 6000 byte. **Đầy đủ source_refs/evidence IDs nằm trong file case
local**, không có cách hiển thị thông tin chưa từng được gửi lên indexer. Hồ
sơ ghi rõ phạm vi đó và giữ đường dẫn `data.evidence_file` để đối chiếu. Probe
lab chỉ ghi hai hành động cố định, không phải audit mọi lệnh/file trên host.

## Nguồn tham khảo

- [MITRE CTID Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow):
  mô tả chuỗi/quan hệ hành động. Graph nội bộ của Lab A chưa phải exporter
  STIX/Attack Flow; thứ tự thời gian không tự chứng minh quan hệ nhân quả.
- MITRE ATT&CK: [T1046](https://attack.mitre.org/techniques/T1046/),
  [T1110.001](https://attack.mitre.org/techniques/T1110/001/),
  [T1078](https://attack.mitre.org/techniques/T1078/),
  [T1059.004](https://attack.mitre.org/techniques/T1059/004/),
  [T1105](https://attack.mitre.org/techniques/T1105/).
  Dùng để đối chiếu hành vi/bằng chứng; không dùng làm công thức điểm.
- [Wazuh ATT&CK integration](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html):
  custom `data.techniques` của dashboard không tự thành native `rule.mitre`.
- [OpenSearch Vega](https://docs.opensearch.org/docs/2.19/dashboards/visualize/vega/)
  và [Vega expression language](https://vega.github.io/vega/docs/expressions/):
  query context và dựng hồ sơ trong Dashboard. API thực tế được kiểm chứng
  trên OpenSearch Dashboards 2.19.3, không chỉ dựa vào mẫu cấu hình.

Phạm vi tham khảo ATT&CK/Attack Flow và bundle STIX đã đối chiếu được ghi đầy
đủ trong [tài liệu 0.4.6](CHAIN-INVESTIGATION-VI.md#nguồn-tham-khảo-và-phần-áp-dụng).

## Kiểm chứng bản phát hành

Đã import/reimport đủ 9 objects trên OpenSearch Dashboards 2.19.3 trong
container test cô lập, giữ nguyên dashboard 0.4.5. Dùng thao tác bấm Chain ID
thật để mở hồ sơ: kiểm tra ca 1 và 5 bước, đầy đủ command/URL/SHA256, tách giả
thuyết khỏi stage, tự xuống dòng ở chiều rộng 1000 px, cuộn chuột và nút ▲/▼.
Kiểm tra bộ lọc rỗng/nhiều case/cùng ID khác session, HTML chỉ hiển thị như text,
và revision cũ đến muộn không thay thế bằng chứng nguồn mới hơn.

30 query thực tế từ trình duyệt được gửi lại đến indexer: cả 6 shard test
(3 shard index cũ thiếu event_time, 3 shard index hiện tại) đều không lỗi.
Không có JavaScript page error trong lượt kiểm tra cuối. Bộ đầy đủ có 387 kiểm
tra: 385 đạt, 2 kiểm tra Windows-only được bỏ qua trên Linux. Sau chỉnh giao
diện cuối, 13 kiểm tra dashboard/profile được chạy lại và đạt.

[Kết quả kiểm chứng](CHAIN-PROFILE-VALIDATION-20261020.json) dùng **dữ liệu mẫu
cô lập**, không phải xác minh chuỗi năm bước trên máy Windows của bạn. Ca thực
đã gửi vẫn chưa hoàn tất do SSH reset. Cài/import thành công cũng không tự
chứng minh model có chất lượng phát hiện tốt hoặc các sensor thu đủ dữ liệu.
