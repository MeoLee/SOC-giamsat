# Hồ sơ kỹ thuật SOC–AI Lab

Sáu tài liệu DOCX, đối chiếu runtime0.4.15.2 (commit313ceed), ngày21/10/2026.

Tổng84trang theo LibreOffice khi kiểm tra dàn trang; MicrosoftWord có thể phân trang khác.

## Tệp chính

- 00_Chi_Dan_Pham_Vi_Va_Thuat_Ngu.docx — 5trang
- 01_Kien_Truc_Thu_Log_Chuan_Hoa.docx — 12trang
- 02_Model_AI_Du_Lieu_Huan_Luyen_Danh_Gia.docx — 13trang
- 03_Danh_Muc_Rule_Va_Description.docx — 24trang
- 04_Su_Kien_Cham_Diem_Attack_Chain_Dashboard.docx — 17trang
- 05_Kiem_Thu_Tai_Lap_Dong_Goi_Van_Hanh.docx — 13trang

Phụ lụcCSV:50mục gồm30customWazuhrules,4SuricataSIDs,16nativeWazuhrules liênquan. Description nguyênvăn, kèmconditions vàgiảithích.

Phạm vi: chưa cómodel.json/metrics.json đầyđủ của run cuối trong đầu vào; tài liệu không tự tạoaccuracy/F1/FPR hoặc hyperparameter thựcnghiệm. Golden verification không thay đánhgiáaccuracy. Softmax chưa calibration; next-step là curated hypothesis, khôngphải learned forecast.

Không nhúng privatekey, VTkey, rawsessions hay dataset. Tài liệu không phải bằngchứng nghiệmthu deployment sạch.

Nguon_Va_Checksum.json lưuhashDOCX vàsourcefiles đểđối chiếu.
