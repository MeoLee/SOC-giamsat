# Đo chất lượng hai model trên cùng phiên Lab thật

`evaluate_lab.py` so sánh model cũ và model ứng viên trên cùng một tập flow có bằng chứng độc lập. Công cụ giữ nguyên trọng số, preprocessor và ngưỡng trong từng bundle; kết quả là báo cáo mới, không tự thay model đang chạy.

Các fixture tự sinh và kiểm thử phần mềm chỉ chứng minh chương trình hoạt động. Chúng không chứng minh model phát hiện tốt tấn công trên Lab A. Hiện chưa có kết quả benchmark độc lập trên máy Windows của bạn để kết luận ứng viên tốt hơn model cũ.

## Chuẩn bị dữ liệu và bằng chứng

1. Giữ một bản model hiện tại làm baseline. Huấn luyện ứng viên vào thư mục khác. Không đưa các phiên test cuối vào train, early stopping, chọn checkpoint, chọn threshold hoặc điều chỉnh kịch bản sau khi xem kết quả.
2. Thu các phiên normal SSH, normal HTTP và các phiên kiểm thử tấn công được kiểm soát theo tài liệu kịch bản. Chờ Suricata ghi completed flow. Mỗi phiên có ID vật lý riêng, thời gian có múi giờ, log thô/PCAP hoặc nhật ký chạy lệnh làm bằng chứng. Không dùng cảnh báo AI hay số rule Wazuh làm nhãn đúng/sai.
3. Mỗi entry trong manifest chỉ chứa flow đã được bằng chứng xác nhận cùng một kết quả `expected_attack`. Tách theo luồng và khoảng thời gian có bằng chứng nếu capture trộn normal/attack; các đoạn của một capture vẫn chỉ là một phiên vật lý. Công cụ từ chối tính các đoạn cùng capture thành nhiều phiên độc lập.
4. Tạo manifest theo [mẫu](../examples/benchmark-manifest.example.json). Mẫu chứa đường dẫn và hash cần thay bằng dữ liệu thực; chưa phải dữ liệu có thể chạy. Đặt file flow dưới thư mục manifest, dùng đường dẫn tương đối với dấu `/`. Công cụ từ chối đường dẫn tuyệt đối, `../`, đường dẫn Windows có drive và symlink dẫn ra ngoài thư mục.
5. Chốt manifest và SHA-256 trước khi đọc kết quả test. Giữ lại báo cáo của cả những lần kết quả kém. Sau khi dùng một tập test để chọn hoặc sửa model, cần tập test cuối mới để đánh giá ứng viên tiếp theo.

Ví dụ cấu trúc:

```json
{
  "schema_version": "soc-lab-benchmark/1.0",
  "synthetic": false,
  "sessions": [
    {
      "id": "test-normal-ssh-01",
      "role": "test",
      "scenario": "normal-ssh",
      "flows": "captures/test-normal-ssh-01/flows.jsonl",
      "sha256": "THAY_BANG_SHA256_64_KY_TU_HEX_THUONG",
      "expected_attack": false,
      "expected_class": "BENIGN",
      "evidence": {
        "independent": true,
        "source": "Phiên SSH được kiểm soát; auth.log Accepted và nhật ký thao tác đã lưu",
        "collected_at": "2026-10-19T09:00:00+07:00"
      },
      "provenance": {
        "capture_session_id": "ID_VAT_LY_CUA_PHIEN_THU",
        "host_id": "ubuntu-endpoint",
        "evidence_refs": ["captures/test-normal-ssh-01/auth.log"]
      }
    }
  ]
}
```

`synthetic` ở gốc là boolean bắt buộc. Fixture phải ghi `true`; từng session có thể bổ sung `synthetic: true` nhưng không được biến manifest synthetic thành dữ liệu thật. File có record tự đánh dấu synthetic cũng không được xác nhận chất lượng thật.

`role` chỉ nhận `validation` hoặc `test`. Validation được thống kê riêng, không tham gia gate cuối và không tự hiệu chỉnh threshold. `evidence.independent` là boolean bắt buộc: chỉ chọn `true` khi người làm lab thực sự có bằng chứng độc lập. Đây là khai báo của người vận hành; công cụ không thể tự xác minh ý định của người đăng nhập từ bộ đếm mạng. `evidence_refs` là danh mục để người review truy lại bằng chứng; công cụ chỉ kiểm hash của file flow, chưa kiểm hash/nội dung các ref này.

`expected_class` không bắt buộc, chỉ nhận một trong `BENIGN`, `FTP-Patator`, `SSH-Patator`, `Bot`, `PortScan`, `DDoS`. Không gán SQLi vào Bot để khớp sáu lớp. Với SQLi, chỉ đánh giá binary flow nếu có căn cứ phù hợp và để trống `expected_class`; khả năng phát hiện payload cần kiểm thử rule/correlation riêng. Kết quả ngoài phạm vi training vẫn là unknown.

Lấy SHA-256 bằng PowerShell:

```powershell
(Get-FileHash 'E:\SOC-Lab\benchmark\captures\test-normal-ssh-01\flows.jsonl' -Algorithm SHA256).Hash.ToLowerInvariant()
```

## Chạy so sánh

Trong thư mục source Lab A mới, dùng Python môi trường inference đã cài PyTorch CPU:

```powershell
$InferPython = 'E:\SOC-Lab\AI\.venv-infer\Scripts\python.exe'
& $InferPython .\evaluate_lab.py `
  --manifest 'E:\SOC-Lab\benchmark\benchmark.json' `
  --baseline 'E:\SOC-Lab\AI\models\baseline' `
  --candidate 'E:\SOC-Lab\AI\models\candidate' `
  --output 'E:\SOC-Lab\benchmark\reports\compare-01.json'
```

Thay hai thư mục model bằng đường dẫn thực tế. Mỗi bundle phải đầy đủ và qua golden verification. Cả hai model nhận cùng những observation hợp lệ, cùng thứ tự và nhãn từ manifest. Ngưỡng có thể khác nhau giữa hai bundle vì đã được chọn trên validation của từng lần train; công cụ không chọn lại ngưỡng theo test.

Mã thoát:

| Mã | Ý nghĩa |
|---|---|
| `0` | Đã ghi báo cáo, gate trên tập được khai báo đạt |
| `3` | Đã ghi báo cáo, gate thất bại hoặc chưa đủ bằng chứng |
| `2` | Đầu vào/bundle không hợp lệ hoặc lỗi thực thi; chưa có báo cáo hoàn chỉnh |

File báo cáo dùng chế độ create-only: không ghi đè báo cáo cũ. Thiếu file flow, sai hash, trùng session, trùng capture vật lý hoặc alias `related_session_ids`, cùng completed connection xuất hiện trong nhiều phiên, hoặc bundle không qua golden sẽ bị từ chối. Cùng một connection bị lặp trong một phiên chỉ tính một lần; hai snapshot mâu thuẫn của connection đó bị từ chối. `flow_id`/`record_id` đổi tên không làm mất kiểm tra trùng connection theo endpoint, protocol và thời gian. Hash file flow, nguồn thô hoặc evidence trùng với nguồn đã khai báo trong training provenance cũng bị từ chối; việc đổi tên capture không che được bản sao có hash đã biết.

## Đọc báo cáo đúng cách

Hai quyết định phải đọc riêng:

| Mục báo cáo | Trả lời |
|---|---|
| `binary_attack` | Với threshold đã chốt, model có phát `possible_attack` không? |
| `argmax_multiclass` | Lớp có softmax lớn nhất là lớp nào? |
| `coverage` và `unknown` | Bao nhiêu flow đủ điều kiện được chấm điểm; bao nhiêu chưa có quyết định? |
| `sessions` | Normal SSH/HTTP hoặc từng kịch bản có bị trung bình toàn bộ che khuất không? |
| `paired_comparison_test` | Chênh lệch candidate − baseline theo trung bình các phiên tương ứng |
| `training_isolation` | Có đủ metadata kiểm tra tách khỏi các phiên đã được model dùng lúc train hay không? |

Argmax BENIGN có thể đi cùng `possible_attack` nếu threshold thấp. Báo cáo không ép hai khái niệm thành một. Softmax vẫn chưa được calibration thành xác suất tấn công thực tế.

JSON hỏng, thiếu trường bắt buộc, sai định dạng và flow ngoài phạm vi model được đếm riêng. Chúng không trở thành BENIGN hay true negative. Non-flow hợp lệ trong EVE được thống kê `ignored_non_flow_records`, không đưa vào mẫu số coverage của flow. Coverage tính `scored / unique flow candidates`; malformed hoặc thiếu trường vẫn làm giảm coverage. Đếm lặp đã loại không tăng số mẫu.

`recall_scored = TP / (TP + FN)` chỉ tính những flow đã chấm điểm. `effective_recall_including_unknown = TP / (TP + FN + attack_unknown)` tính những flow attack chưa có quyết định là chưa phát hiện, đồng thời giữ chúng trong nhóm unknown thay vì đổi nhãn thành BENIGN/FN. Gate dùng effective recall để không che khuất việc model từ chối phần lớn flow tấn công.

FPR chỉ tính trên benign đã chấm điểm; đọc cùng coverage và FPR từng phiên. Nếu một phiên không có mẫu đủ điều kiện, các tỉ lệ tương ứng là `null`, không phải 0% lỗi.

Báo cáo có khoảng tin cậy Wilson 95% và số mẫu. Wilson giả định các quan sát độc lập; nhiều flow trong một đợt SSH/scan thường tương quan, nên khoảng này có thể quá lạc quan. Vì vậy báo cáo còn có thống kê từng phiên và paired bootstrap theo phiên, 2.000 lần lấy mẫu với seed cố định. Ít phiên, các phiên phụ thuộc nhau hoặc mọi phiên cho cùng một kết quả đều có thể tạo khoảng bootstrap hẹp giả tạo. Không dùng con số CI này để bỏ qua thiết kế thí nghiệm.

## Gate mặc định và giới hạn

Gate chỉ xét các session `test`; policy được lưu nguyên trong báo cáo:

| Điều kiện mặc định | Giá trị |
|---|---|
| Phiên benign / attack độc lập tối thiểu | 5 / 5 |
| Kịch bản benign / attack khác nhau tối thiểu | 2 / 2 |
| Flow benign / attack được chấm điểm tối thiểu | 500 / 500 |
| Flow được chấm điểm trong mỗi phiên test tối thiểu | 100 |
| FPR benign, cận trên Wilson 95% | ≤ 1% |
| Effective attack recall, cận dưới Wilson 95% | ≥ 90% |
| Coverage toàn bộ và từng phiên test | ≥ 95% |
| FPR điểm của mỗi phiên benign | ≤ 5% |
| Effective recall điểm của mỗi phiên attack | ≥ 80% |
| FPR candidate tăng so với baseline | ≤ 0 điểm phần trăm |
| Effective recall candidate giảm so với baseline | ≤ 2 điểm phần trăm |

Đây là mục tiêu vận hành ban đầu có thể chỉnh bằng object `gate` trong manifest, không phải chất lượng đã đạt. Chính sách nên chốt trước khi mở test. Ví dụ có thể tăng số phiên hoặc nâng mức coverage; không hạ tiêu chí sau khi xem kết quả chỉ để biến báo cáo thành xanh. Các tên trường có thể chỉnh xem trong `DEFAULT_GATE` của [evaluate_lab.py](../evaluate_lab.py); tên gõ sai bị từ chối.

Gate giữ trạng thái `insufficient_evidence` nếu dữ liệu synthetic, thiếu phiên/số mẫu, thiếu bằng chứng độc lập hoặc chưa kiểm tra đầy đủ sự tách khỏi dữ liệu từng model đã dùng. Số lượng lớn flow từ một phiên không thay thế được nhiều phiên độc lập. `numerical_operating_criteria` báo riêng các kiểm tra FPR/recall/coverage và hồi quy, còn `evidence_requirements` báo các điều kiện chưa đủ. Vì vậy có thể thấy các con số đạt mục tiêu nhưng gate vẫn chưa xác nhận chất lượng; cũng có thể đồng thời vừa có lỗi FPR vừa chưa đủ dữ liệu.

Metadata model mới lưu `training_provenance`; benchmark đối chiếu session ID vật lý và logic với toàn bộ các role train, validation và internal-test đã biết, kể cả các ID/hash nằm trong `local_inputs` và nguồn gốc lồng nhau. Nó còn kiểm tra ID trong record có wrapper. Model cũ thiếu provenance vẫn so sánh được, nhưng sẽ hiển thị giới hạn này và không tự xác nhận chất lượng.

`verified_declared_identity_isolation` chỉ nói rằng đã kiểm các ID được khai báo và phạm vi provenance. `independent_source_isolation_verified` còn yêu cầu khai báo đã kiểm nguồn thô và tính độc lập, không phải chỉ kiểm cache. Pipeline train hiện tại chủ động ghi `independence_verified: false` và `raw_sources_rechecked: false`: hash/cache hợp lệ không chứng minh các chiến dịch/phiên thật độc lập. Vì vậy một lần train mới hợp lệ có thể đạt mọi mục tiêu số học nhưng gate vẫn `insufficient_evidence` cho tới khi có review nguồn độc lập bổ sung. Quy trình CLI hiện tại không tự tạo chứng nhận này. Không sửa tay các cờ provenance chỉ để vượt gate; cần thực sự đối chiếu nguồn, lịch sử sử dụng dữ liệu và thiết kế holdout. Promotion model là quyết định review thủ công dựa trên toàn bộ bằng chứng.

Một lần pass chỉ hỗ trợ review trên những phiên, nhãn và giới hạn được khai báo. Báo cáo không tự tuyên bố candidate tốt hơn có ý nghĩa thống kê, không tự deploy, và luôn giữ `production_ready: false`. Các phiên SQLi/recon/auth nhiều bước, log mất đoạn, Wazuh outbox và khôi phục collector cần test chức năng riêng bên cạnh benchmark MLP.

## Kiểm thử công cụ

```powershell
& $InferPython -m unittest -v test_evaluate_lab
```

Bộ test tạo model rất nhỏ với trọng số cố định và các flow tự sinh để kiểm tra CLI, golden, accounting unknown, hai loại quyết định, chống trùng phiên/connection, thiếu provenance và chống ghi đè. Kết quả test này không được trích thành precision/recall thực tế của Lab A.
