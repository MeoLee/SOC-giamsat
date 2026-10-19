# Kiểm chứng Lab A 0.4 — 19/10/2026

**Đính chính bản phát hành:** các kết quả ban đầu dưới đây chạy trên source checkout; ZIP0.4 thiếu dashboard HTML và test offset chưa tương thích CRLF. Xem [nguyên nhân và sửa0.4.1](WINDOWS-FIX-VI.md). Bản sửa được kiểm tra lại trên ZIP giải nén; chưa xác nhận317/317 trên Windows thật.

Đã chạy trên Linux/Python3.12, bằng cả venv cloud đang có và **venv mới độc lập do Setup-AI.ps1 thực sự cài**. Dependency trực tiếp: torch2.11.0+cpu, numpy2.3.5, scikit-learn1.8.0, matplotlib3.10.8. Đây là kiểm chứng source/pipeline, không phải benchmark model thật trên Lab A.

| Kiểm tra | Kết quả |
|---|---|
| `python run_checks.py` trong venv mới | 317 ca nhận diện; **315 đạt**, hai ca riêng Windows bỏ qua; không error/failure. |
| `lab_scenarios.py replay` | **38/38 đạt**, không phát traffic, không gọi Docker/model thật. |
| `Setup-AI.ps1 -Mode Cpu` | Chạy thật: tạo venv mới, cài dependencies qua TLS/index chính thức, CPU import và Doctor config đạt. |
| PowerShell hướng dẫn | 14 khối trong README/cài-train và bốn khối label SSH parse đạt; runbook scenarios có 11 khối đã parse trước đó. |
| Training smoke | Synthetic prepare→train→export→CPU golden verify; checkpoint pause/resume; chỉ lớp có data active. |
| Chống dữ liệu giả thành thật | Marker synthetic giữ qua wrapper, label/session, cache nền và metadata; các regression đạt. |
| Provenance/split | Chặn cùng capture/alias/sourcehash/flow qua split; rehash nguồn sau đọc; output create-only. |
| Bundle integrity | Active mask, threshold, preprocessor, SPEC, numeric NPZ preflight/finite/shape và golden broadcasting/corruption đều có negative tests. |
| Context/live | Sweep vs repeated-port, HTTP requests vs flows, partial/late/duplicate/missing/truncate/capacity, error raw refs và degraded status. |

Hai Windows test bị bỏ qua là atomic replacement và missing path trên Windows thật. Mô phỏng file lock, bounded retry, checkpoint/status recovery vẫn đã chạy trên Linux. Script PowerShell chạy trong runtime PowerShell Linux; chưa chứng minh mọi thao tác Win32/GPU.

Chưa có model bundle, dataset và GPU/containers thật của người dùng trong cloud. Vì vậy **chưa đo FPR/recall mới, chưa train weights thật, chưa xác nhận đường AI→Wazuh→indexer hoặc cài lại toàn bộ SOC bằng Compose**. Các phép đo đó cần thực hiện theo runbook trên lab; không gộp chúng vào số tests đã đạt.

Config gói bật distinct-port context shadow và tắt HTTP rate. Các threshold thử nghiệm không phải giá trị tối ưu đã được chứng minh. Context memory có giới hạn; không khẳng định toàn bộ Live chạy vô hạn với bộ nhớ cố định vì dedup phiên cũ vẫn có thể tăng theo log.

Các file máy đọc được về môi trường/kết quả nằm trong `VALIDATION-04.json` cạnh tài liệu này. File `VALIDATION-VI.md` cũ là kết quả lịch sử của bản0.3.
