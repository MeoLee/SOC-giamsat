# Bộ phát hiện ngữ cảnh ở chế độ shadow

`lab_context.py` bổ sung hai chỉ báo có bằng chứng giải thích được bên cạnh MLP
24 đặc trưng. Nó không đổi model, gán nhãn dataset, xác nhận tấn công hay gửi sang
Wazuh. Cả replay và live phải dùng cùng `ContextDetector`; không có công thức
offline và online riêng.

## Phạm vi và ngưỡng thử nghiệm

- **Nhiều cổng đích:** mặc định bật, từ 20 **cổng đích TCP khác nhau** trong một
  cửa sổ 60 giây, với cùng nguồn IP, đích IP và nguồn log. Ba mươi kết nối SSH
  tới một cổng vẫn là một cổng. Đọc completed EVE `event_type=flow`; không đếm
  packet/SYN, không suy ra lỗi đăng nhập từ lượng SSH. UDP chưa được hỗ trợ.
- **Lượng HTTP:** mặc định **tắt**, cần bật rõ ràng sau khi đo normal tại lab.
  Ngưỡng minh họa là 120 request trong cửa sổ 60 giây. Đếm từng
  `soc-http-event/0.1` từ Apache; không dùng số flow thay số request. Tách dịch
  vụ theo cổng đích nếu có. HTTP 4xx/5xx là thống kê phản hồi, không chứng minh
  DoS, outage hay khai thác thành công.

Các ngưỡng trên chưa được chứng minh tối ưu hoặc hiệu chỉnh tại Lab A. HTTP
ngưỡng thấp có thể báo khi benchmark hoặc truy cập hợp lệ. Port sweep có thể
đến từ quản trị hợp lệ. Tên chỉ báo là `context.distinct_port_sweep` và
`context.http_request_rate`; luôn `mode=shadow`, `attack_proven=false`,
`confirmed_compromise=false`, `training_label=null`.

## Hợp đồng dùng chung

```python
from lab_context import ContextDetector

detector = ContextDetector({
    "port_threshold": 20,
    "http_enabled": False,
})
updates = detector.observe_flow(eve_flow, "suricata-eve.jsonl", "ubuntu-endpoint")
# http_event là kết quả lab_web.apache_tsv hoặc apache_combined.
http_event["source_file"] = "apache.tsv"
http_event["source_container"] = "ubuntu-endpoint"
updates += detector.observe_http(http_event)
state = detector.snapshot()
```

`observe_*` trả danh sách chỉ báo mới hoặc cập nhật; `signal_id` ổn định cho cùng
nhóm/cửa sổ, `revision` bằng số bản ghi đã nhận trong nhóm. Consumer lưu trạng
thái phải cập nhật theo ID; không coi mỗi revision là một incident mới.
`snapshot()` là JSON, gồm cấu hình, lịch sử chỉ báo giới hạn và chất lượng.
Sửa đối tượng trả về không làm đổi trạng thái detector.

Danh tính nhóm chứa nguồn IP và đích IP (hoặc `target_host` khi Apache không
biết IP), container/sensor và file log. Không có whitelist IP kẻ tấn công. IPv6
được chuẩn hóa; IPv6 có scope/interface chưa hỗ trợ. Hai sensor hoặc hai file
không được cộng mù vào cùng số đếm. Vì vậy trực tiếp Apache và bản sao Wazuh
có thể tạo hai chỉ báo riêng; ưu tiên nguồn Apache trực tiếp cho số request
đầy đủ. Không suy ra rằng hai nguồn đó là hai request khác nhau. Thiếu metadata
nguồn HTTP sẽ dùng host/provider thay thế và tăng bộ đếm cảnh báo chất lượng.

## Thời gian, poll và sự kiện đến muộn

- Event time của flow là `flow.end`, không phải thời điểm đọc file hay thời điểm
  Suricata phát log. Counters chỉ được quan sát khi completed flow được phát;
  chỉ báo vì vậy có thể xuất hiện muộn. Không tuyên bố phát hiện trước khi flow
  hoàn tất. HTTP dùng `event_time` của request. Timestamp phải có múi giờ.
- Cửa sổ **tumbling UTC**, `[start,end)`, mặc định 60 giây; cửa sổ không reset
  giữa các poll UI/collector. Một sweep chia qua ranh giới phút có thể không
  vượt ngưỡng ở từng nửa; đây là giới hạn đã biết, không phải sliding window.
- Mỗi nguồn `(loại,container,file)` có watermark riêng bằng event time lớn
  nhất đã thấy. Chấp nhận sự kiện có `event_time >= watermark - 10 giây`
  (cấu hình được), cập nhật lại cùng `signal_id`; cũ hơn thì loại rõ ràng qua
  `late_records_rejected`. Replay nên đọc đúng thứ tự thu thập, không sort theo
  nhãn/scenario. Nếu sort khác quá mức lateness, tập nhận có thể khác live.
- Log sensor sai đồng hồ hoặc timestamp tương lai có thể đẩy watermark và làm
  các sự kiện tiếp theo bị loại muộn. Dùng `quality.watermarks` để điều tra;
  không có dịch vụ đồng bộ đồng hồ hoặc reset watermark tự động.
- ID, evidence sample và kết quả cùng tập sự kiện được chấp nhận ổn định dù
  chia poll khác nhau hoặc đảo thứ tự trong mức lateness.

## Bộ nhớ, dedup và bằng chứng

Mặc định giữ tối đa 1.000 nhóm/cửa sổ, 20.000 event trong các nhóm đang giữ,
1.000 chỉ báo lịch sử, 16 ID bằng chứng mỗi chỉ báo. Số stream watermark cũng
bị giới hạn bởi `max_groups`. Key chuỗi được giới hạn độ dài. Dữ liệu request,
payload và URL không được giữ trong detector. Các giới hạn cấu hình có trần
cứng; không có cấu hình vô hạn.

Dedup flow dùng tuple đã chuẩn hóa, counters, thời gian và sensor/file; không
dựa vào flow ID có thể thay đổi ở wrapper. HTTP dùng `record_id` cùng nguồn,
phù hợp normalizer Apache hiện tại. Hai request có toàn bộ raw log giống nhau
sẽ có cùng record ID trong normalizer, nên độ phân giải/tính đầy đủ LogFormat
ảnh hưởng khả năng phân biệt. Đây không phải dedup dataset train.

Khi một nguồn tiến qua hết cửa sổ cộng lateness, event/dedup state của cửa sổ
đó được giải phóng; chỉ báo lịch sử còn lại có `window_status=closed`. Nguồn
ngừng phát có thể chiếm chỗ cho tới khi tiếp tục hoặc detector khởi động lại.
Nếu hết chỗ thì **drop bản ghi mới và báo rõ**, không âm thầm xóa nhóm đang
đếm. Giới hạn lịch sử xóa chỉ báo cũ nhất với bộ đếm riêng. `quality.incomplete`
cho biết đã có bản ghi lỗi, quá muộn hoặc bị loại do capacity; kết quả khi đó
có thể thiếu bằng chứng. `signal_history_truncated` khác với mất event đầu
vào. Dedup/bộ đếm chỉ tồn tại trong RAM của phiên; chưa có resume qua restart.

`evidence_ids` là ID canonical trong detector, `source_file`/`source_container`
chỉ nguồn log. Flow ID context có thể tái tạo bằng replay cùng sự kiện; chưa
là byte offset hay URL mở thẳng dòng log. Phải giữ raw capture/session để kiểm
chứng. Chỉ báo không chứa ground truth và không được dùng làm nhãn train.

## Kiểm chứng và hiệu chỉnh

```powershell
python -m unittest test_lab_context -v
```

Ca kiểm chứng bao gồm nhiều cổng so với lặp một dịch vụ, normal HTTP so với
burst khi bật rõ ngưỡng, tách nguồn/đích/sensor/dịch vụ, dedup, hai poll, late
trong/ngoài ngưỡng, ranh giới cửa sổ, IPv6/múi giờ, timestamp thiếu timezone,
hết bộ nhớ, giải phóng cửa sổ, lịch sử và evidence bị giới hạn. Đây là kiểm
chứng logic bằng dữ liệu tổng hợp, không chứng minh hiệu quả trên traffic thật.

Trước khi đánh giá thực tế, giữ riêng normal SSH/HTTP, cập nhật package, health
check, benchmark hợp lệ và scan quản trị; đo số chỉ báo/giờ và điều tra từng
báo nhầm. Chọn ngưỡng trên tập hiệu chỉnh riêng, đóng băng cấu hình rồi đánh
giá trên ngày/campaign chưa dùng. Giữ chỉ báo này độc lập với nhãn MLP và chỉ
bổ sung Isolation Forest sau khi có parity feature offline/live và holdout.
