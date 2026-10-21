# SOC-giamsat

- **[0.4.12 — DVWA web flood, baseline cùng route và Wazuh Medium/High](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.12-DVWA-Web-Flood-20261021.zip)** — bản vá từ0.4.11, giữ nhãn Chuyển file độc qua SSH.
- [Cài cập nhật và một bài baseline → scan → web flood → recovery](lab-a/docs/WEB-FLOOD-DVWA-0412-VI.md). High cần bằng chứng suy giảm, không chỉ số request hoặc dự đoán DoS.

- **[0.4.11.1 — Đổi nhãn thành “Chuyển file độc qua SSH”](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/soc-ai-attack-chain-file-label-v0.4.11.1.ndjson)**. Import trực tiếp trong Saved objects, bật overwrite conflicts; 5 objects, cùng dashboard Attack Chain. Chú thích EICAR vẫn được giữ trong bằng chứng.

- **[0.4.11 — Scan → chuyển EICAR → bằng chứng VT, dashboard Attack Chain](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.11-EICAR-Chain-20261021.zip)** (bản vá phẳng từ 0.4.10.2 đã cài VT).
- [Cập nhật và một kịch bản Kali Bash](lab-a/docs/EICAR-CHAIN-0411-VI.md) · [Full source 0.4.11](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.11-Research-20261021.zip).

- **[0.4.10.2 — Severity/VT đã sửa restart timeout](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.2-Severity-VT-20261021.zip)** (nâng từ 0.4.9.2).
- [Máy đã có 0.4.10/0.4.10.1: vá restart và cài lại VT](lab-a/docs/VT-RESTART-FIX-04102-VI.md).

- **[0.4.10.1 — Severity/VT đã sửa parser logtest](https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.10.1-Severity-VT-20261021.zip)** (nâng từ 0.4.9.2).
- [Máy đã có 0.4.10: chỉ vá lỗi matched thừa signature_id](lab-a/docs/WAZUH-LOGTEST-PARSER-FIX-04101-VI.md).

- **[0.4.10 — Severity theo bằng chứng và VirusTotal opt-in](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.10-Severity-VT-20261021.zip)** (vá lên 0.4.9.2).
- [Nghiên cứu severity Wazuh](lab-a/docs/SEVERITY-POLICY-0410-VI.md) · [Một bài VT-01 bằng EICAR](lab-a/docs/VIRUSTOTAL-01-VI.md).

- **[0.4.9.2 — Tự ẩn hành vi đơn lẻ hết hạn, giữ chain nhiều bước](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9.2-Chain-Retention-20261021.zip)** (vá lên 0.4.9.1).
- [Cách cập nhật source/dashboard và kiểm tra chính sách lưu chain](lab-a/docs/CHAIN-RETENTION-0492-VI.md).

- **[0.4.9.1 — Sửa lỗi bộ cài Wazuh/logtest](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9.1-Installer-Fix-20261021.zip)** (vá lên 0.4.9).
- [Cách cập nhật, tiếp tục cài và test chain bằng Kali Bash](lab-a/docs/WAZUH-INSTALLER-FIX-0491-VI.md).
- [Full source 0.4.9.1](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9.1-Research-20261021.zip).

- **[0.4.9 — Kali Bash thủ công, sơ đồ chain và tách episode](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9-Manual-Chain-20261021.zip)**
- [Hướng dẫn đầy đủ, chia theo nhóm](https://github.com/MeoLee/SOC-giamsat/blob/main/lab-a/docs/SCENARIO-RESEARCH-049-VI.md)
- [Full source 0.4.9](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.9-Research-20261021.zip)

Các liên kết dưới đây là bản lịch sử; chỉ import dashboard unified trong bản đang dùng.


- **[0.4.8 — Unified Attack Chains, nâng thẳng từ 0.4.6](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.8-Unified-Chains-20261020.zip)**
- [Hướng dẫn cài, một dashboard và kịch bản](https://github.com/MeoLee/SOC-giamsat/blob/main/lab-a/docs/ATTACK-CHAINS-048-VI.md)

- **[0.4.7 — Hồ sơ Chain trong Wazuh, tiếng Việt, bấm Chain ID](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.7-Chain-Profile-VI-20261020.zip)**
- [File Dashboard đầy đủ 9 objects — import trực tiếp](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/soc-ai-chain-profile-v0.4.7.ndjson)
- [Full source 0.4.7](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.7-Research-20261020.zip)

- [AI Lab A 0.4 — bắt đầu, cài mới, train và kiểm thử](lab-a/README-START-VI.md)
- [Chi tiết chain, kịch bản năm bước và nguồn Attack Flow/ATT&CK](lab-a/docs/CHAIN-INVESTIGATION-VI.md)
- [Cập nhật 0.4.5/0.4.6 — Chain Investigation, gồm sửa lỗi shard](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.6-Chain-Investigation-Shard-Fix-20261020.zip)
- [Full source 0.4.6 gồm sửa shard và Doctor log rỗng](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.6-Research-Doctor-Fix-20261020.zip)
- [Bản vá Doctor khi log endpoint mới còn rỗng](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.6-Doctor-Fix-20261020.zip)
- [Hướng dẫn tiếp tục Live sau lỗi log rỗng](lab-a/docs/DOCTOR-EMPTY-LOG-FIX-VI.md)
- [Sửa No mapping found for data.event_time và import lại](lab-a/docs/CHAIN-SHARD-FIX-VI.md)
- [Tải ZIP 0.4.5 với bảng Attack Chain Detail và Scoring](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.5-Research-20261020.zip)
- [Cập nhật 0.4.4 lên 0.4.5 và import dashboard](https://github.com/MeoLee/SOC-giamsat/raw/refs/heads/main/downloads/SOC-AI-Lab-A-v0.4.5-Chain-Dashboard-20261020.zip)
- [Triển khai bảng Wazuh và kiểm thử chain theo bằng chứng](lab-a/docs/CHAIN-DASHBOARD-VI.md)
- [Phân tích ca HTTP burst thật: 33 kết nối, một MLP false positive](lab-a/docs/HTTP-BURST-REVIEW-20261020-VI.md)
- [Cập nhật 0.4.4 và kiểm thử HTTP burst/quét cổng](lab-a/docs/RECON-FIX-VI.md)
- [Sửa Live dừng khi ghép HTTP status từ EVE/Wazuh](lab-a/docs/LIVE-SQLI-FIX-VI.md)
- [Bản vá và chẩn đoán runner chain SSH](lab-a/docs/CHAIN-SSH-FIX-VI.md)
- [Wazuh realtime, chấm điểm, attack chain và kịch bản kiểm thử](lab-a/docs/WAZUH-REALTIME-VI.md)
- [Train bằng giao diện HTML và bản vá dashboard](lab-a/docs/TRAIN-DASHBOARD-VI.md)
- [Bản vá cho máy đã cài 0.4](lab-a/docs/WINDOWS-FIX-VI.md)
- [AI Lab A — bản hợp nhất ứng viên và hướng dẫn Windows](lab-a/README-HOP-NHAT-VI.md)
- [Phân tích A/B và lộ trình cải tiến](lab-a/docs/PHAN-TICH-A-B-VI.md)
- [Phạm vi kiểm chứng](lab-a/docs/VALIDATION-VI.md)
- [Công cụ export cấu hình để nghiên cứu](tools/research-export/README-VI.md)

Các gói tải trực tiếp nằm trong [downloads](downloads/). Bản AI là source, không kèm weights/dataset/checkpoint và chưa được triển khai lên máy Windows của người dùng. Không dùng kết quả synthetic replay để tuyên bố accuracy.
