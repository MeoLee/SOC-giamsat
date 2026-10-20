# Sửa lỗi shard của Chain Investigation 0.4.6

## Nguyên nhân đã xác nhận

Dashboard báo `24 of 57 shards failed`; Show details ghi:

```text
query_shard_exception
No mapping found for [data.event_time] in order to sort on
```

Các index ngày cũ chưa có mapping `data.event_time`. Bản dashboard ban đầu yêu
cầu Top Hits sort theo trường mới trên toàn bộ `wazuh-alerts-*`, nhưng thiếu
`unmapped_type`. OpenSearch dựng sort trên từng shard kể cả khi query/time filter
không chọn tài liệu ở shard đó. Đây là thiếu sót tương thích của Saved objects,
không phải bằng chứng dữ liệu đã hỏng hoặc ổ đĩa/index cần tạo lại.

Sửa cả 18 Top Hit metric của hai bảng summary/context bằng Advanced JSON:

```json
{
  "sort": [
    {"data.event_time": {"order": "desc", "unmapped_type": "keyword", "missing": "_last"}},
    {"timestamp": {"order": "desc", "unmapped_type": "date", "missing": "_last"}}
  ]
}
```

Giữ việc chọn bằng chứng nguồn mới nhất với microsecond; dùng timestamp làm
sort phụ. Không thay mapping hay bật fielddata. Saved-search panels đã được
OpenSearch Dashboards thêm unmapped options tự động nên giữ nguyên cấu hình.
Dashboard 0.4.5 và các ID Saved objects 0.4.6 cũng giữ nguyên.

## Cập nhật trên Windows

1. Tạm pause auto refresh của trang đang lỗi để không tiếp tục hiện thông báo.
2. Tải `SOC-AI-Lab-A-v0.4.6-Chain-Investigation-Shard-Fix-20261020.zip`, giải nén
   nội dung vào `E:\SOC-Lab\AI\SOC-AI-v0.4-research` và ghi đè. Đây là bản vá
   tích lũy: dùng được cho source 0.4.5 hoặc 0.4.6. Không chứa live-config,
   weights, venv hoặc thay đổi code probe so với 0.4.6.
3. Wazuh → **Dashboards Management → Saved objects → Import**, chọn:

```text
E:\SOC-Lab\AI\SOC-AI-v0.4-research\dashboards\soc-ai-chain-investigation-shard-fix.ndjson
```

4. **Bật overwrite khi có object trùng ID**; import đè đúng **2 visualization**
   bị lỗi. File repair dùng index pattern đã có; không ghi đè bố cục dashboard,
   policy hoặc hai bảng lịch sử. Nếu bỏ qua conflicts thì lỗi vẫn lặp.
5. Mở lại **SOC Lab A - Chain Investigation**, bấm **Ctrl+F5** rồi Refresh.
   Có thể chọn Last 24 hours để xem lại chain cũ, sau đó trở về Last 15 minutes
   khi chạy Live. Bật lại auto refresh sau khi không còn thông báo shard lỗi.

Không cần chạy lại setup_chain_telemetry.py, restart Wazuh, reindex hoặc train.
Nếu chưa từng import Chain Investigation, dùng file đầy đủ
`soc-ai-chain-investigation.ndjson` (7 object) trong cùng thư mục thay cho repair.
Nếu hết lỗi nhưng bảng No results found, kiểm tra thời gian/filter và mở phiên
Live mới theo [hướng dẫn năm bước](CHAIN-INVESTIGATION-VI.md).

Kiểm tra file source sau giải nén nếu cần:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py -m unittest -v test_chain_dashboard
if ($LASTEXITCODE -ne 0) { throw 'Kiểm tra dashboard chưa đạt.' }
```

## Kiểm chứng

Đã tái hiện đúng lỗi với hai index test: ba shard thiếu field ở index cũ và ba
shard có field keyword ở index mới. Truy vấn cũ báo 3/6 shard thất bại dù filter
không chọn tài liệu cũ. Sau sửa, các truy vấn lấy trực tiếp từ trình duyệt cho
cả hai bảng và hai saved search đều có 6/6 shard thành công, failed=0.

Trình duyệt mở được hai bảng, techniques đủ năm bước, không có page error hay
toast shard lỗi. Fixture cố ý cho nhiều revision cùng millisecond của Wazuh
timestamp để giữ kiểm tra chọn đúng bước cuối. Mười test dashboard đạt, gồm
kiểm tra cả 18 metric mang unmapped options. Đây là kiểm tra trên index test
cô lập, không tự xác minh việc import trên Wazuh của người dùng.
