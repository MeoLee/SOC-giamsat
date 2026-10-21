# Bản gộp HTTP flood và SYN pressure 0.4.13

Cài trực tiếp lên bản 0.4.11/0.4.11.1 đang dùng; không cần cài 0.4.12 trước. Giữ model, live-config và VirusTotal API key. Dừng monitor bằng Ctrl+C, đợi LIVE_DONE trước khi giải nén bản vá phẳng vào thư mục project.

## Cài trên PowerShell

```powershell
$ErrorActionPreference = 'Stop'
$project = 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
Set-Location $project
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
$zip = Join-Path $env:TEMP 'SOC-AI-0413-SYN-HTTP.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/MeoLee/SOC-giamsat/main/downloads/SOC-AI-Lab-A-v0.4.13-SYN-HTTP-Flood-20261021.zip' -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $project -Force
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Kali-Tools.ps1
if ($LASTEXITCODE -ne 0) { throw 'Cài Kali tools chưa đạt.' }
& $py .\setup_recon.py --container ubuntu-endpoint
if ($LASTEXITCODE -ne 0) { throw 'Cài SYN collection chưa đạt.' }
& $py .\setup_suricata_web.py --container ubuntu-endpoint
if ($LASTEXITCODE -ne 0) { throw 'Cài HTTP rules chưa đạt.' }
& $py .\setup_wazuh.py --manager single-node-wazuh.manager-1
if ($LASTEXITCODE -ne 0) { throw 'Cài Wazuh rules chưa đạt.' }
& $py .\setup_attack_chains.py --http-flood --syn-flood
if ($LASTEXITCODE -ne 0) { throw 'Cấu hình detector chưa đạt.' }
```

Installer Wazuh tự restart và kiểm tra; không restart thủ công. Suricata giữ file -S đang dùng và reload rule. Không cần nhập lại API key. Nếu một lệnh lỗi, dừng ở lệnh đó.

Wazuh Dashboard → Management → Saved objects → Import:
`dashboards/soc-ai-attack-chain-unified.ndjson`, bật overwrite. Chỉ import file này, giữ một dashboard **Attack Chain**. Không import dashboard lịch sử khác.

## Bật AI, để chạy suốt demo

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-SOC-Monitor.ps1 `
  -Model 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507' `
  -PythonPath 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
```

Đợi READY; AI tự lưu session, không cần nhập session cho Kali. Mở PowerShell thứ hai:

```powershell
docker exec -it kali-attacker bash
```

## Một kịch bản: scan → SYN pressure

Gõ lần lượt trong Kali Bash. `hping3 --version` phải chạy được; nếu chưa có, cài `apt-get update` rồi `apt-get install -y hping3` trong Kali và kiểm tra lại trước demo.

```bash
export TARGET=172.20.0.3
hping3 --version
curl --max-time 3 -s -o /dev/null -w 'HTTP=%{http_code} time=%{time_total}\n' "http://$TARGET/dvwa/login.php"
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
timeout 15s hping3 -S -p 80 -i u20000 -c 400 "$TARGET"
curl --max-time 3 -s -o /dev/null -w 'HTTP=%{http_code} time=%{time_total}\n' "http://$TARGET/dvwa/login.php"
```

Đợi curl baseline có HTTP hợp lệ trước khi nmap. Scan xong thực hiện hping3 trong vòng 90 giây. 400 gói, 50 gói/giây, khoảng 8 giây; không dùng `--flood`, spoof IP, `--rand-source`, hoặc bỏ giới hạn. Ctrl+C để dừng. Kernel Kali có thể trả RST cho SYN-ACK; đây không phải bằng chứng kết nối half-open. Curl trước/sau hỗ trợ kiểm tra thủ công, không được detector tự dùng làm bằng chứng suy giảm.

Mở **Attack Chain**, Last 15 minutes, Refresh 2–5 giây. Kỳ vọng:
**Quét cổng / khám phá dịch vụ → Nghi vấn SYN flood / áp lực kết nối TCP**.
Node SYN có số flow/10s và TCP/80; bấm Chain ID xem bằng chứng. Điểm ưu tiên dự kiến 60 (base50 + scan10), Medium. Chờ 95 giây sau hành động cuối để hiện giả thuyết bước tiếp theo, không phải dự báo xác suất. Chờ 95 giây giữa hai chuỗi độc lập. Candidate một bước hết hạn sau90s; chain đã thành hình được giữ.

Threat Hunting query:
```text
rule.id: "119219"
```

119219 level8: >=100 flow SYN duy nhất/10s vào cùng sensor/source/target/port; dedup flow_id+source_port. Không dùng số cổng để gọi SYN flood, không dùng MLP/client report làm nhãn. Thu thập SID9900003 đã có, không cần thêm signature gán DoS từ số SYN đơn thuần. Không có nhánh tự nâng SYN lên High/Critical khi chưa có handshake/backlog/service-health telemetry. SYN không mang HTTP URI nên không thể quy riêng vào DVWA thay vì web server cổng80.

Nếu không thấy: kiểm tra console `[SYN-LOAD]`, Doctor, source EVE và SID9900003, filter session mới; không lọc `agent.name: ubuntu-endpoint` cho alert AI vì bridge mang agent manager. Không tự tăng tải để ép kết quả. Thu thập đầy đủ packet chưa được chứng minh; tốc độ thấp hơn ngưỡng không tạo cảnh báo là đúng.

## Nhánh HTTP flood vẫn có trong cùng bản

Hướng dẫn và các bước baseline → flood → recovery trong `WEB-FLOOD-DVWA-0412-VI.md` vẫn áp dụng sau khi cài gói gộp này. Không cần cài gói cũ. HTTP119217 level8; HTTP119218 level12 chỉ khi có baseline cùng route và suy giảm được chứng minh theo ngưỡng. Hai detector độc lập; hping3 không tạo HTTP GET.

## Nguồn tham khảo

- hping3 manual: https://www.kali.org/tools/hping3/
- MITRE T1498.001 Direct Network Flood: https://attack.mitre.org/techniques/T1498/001/
- MITRE T1499 Endpoint Denial of Service: https://attack.mitre.org/techniques/T1499/
- Suricata rules thresholding: https://docs.suricata.io/en/latest/rules/thresholding.html
- Wazuh rule classification: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html

Đây là ngưỡng vận hành minh bạch của lab, chưa phải detector SYN flood có xác nhận tác động. MITRE không quy định điểm60 hoặc ngưỡng100; chưa gán ATT&CK chỉ từ rate để tránh khẳng định quá bằng chứng.
