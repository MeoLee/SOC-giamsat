# Nhóm 2 — Thao tác từng bước trong Kali Bash, quan sát chain live

Làm [chuẩn bị](00-PREPARE-VI.md). Bật monitor một lần ở Windows và giữ READY.
Mở `docker exec -it kali-attacker bash`, đặt TARGET/SOURCE/LABUSER như nhóm 1.
Mỗi khối dưới đây là một bước để gõ ở Kali; không chạy host runner và không
nhập SESSION. Nếu đang kiểm chứng hai bài độc lập trên cùng endpoint, chờ
95 giây sau bài trước rồi bắt đầu Nmap mới.

## 2.0 Bài đầu tiên: scan → SQLi attempt

Bước 1:

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Mở dashboard: một Chain ID, bước Quét cổng, risk 40.

Bước 2:

```bash
curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit"
```

Cùng ID phải có `Quét cổng → Dấu hiệu thử SQL injection`, risk 70. Bấm Chain
ID để xem sơ đồ và evidence. HTTP 302 không chứng minh DB bị khai thác.

Bước 3: ngừng tạo traffic liên quan ≥95 giây, refresh Dashboard. Status chuyển
`quiescent`, xuất hiện mũi tên nét đứt tới giả thuyết tác động database/application.
Ô giả thuyết không làm tăng 2 observed stages hoặc điểm 70.

Muốn chứng minh truy vấn DVWA có tác động, thay bước 2 bằng helper sqli trong
nhóm 1.3; report xác minh kết quả là bằng chứng riêng, không phải training label.

## 2.1 Scan → password guessing → login → shell/file có telemetry

File gốc yêu cầu reverse shell. Bài kiểm thử đầy đủ **được engine hiện hỗ trợ**
là chuỗi 5 bước có hai probe cố định, không phải reverse shell:

```text
Scan → Password guessing → Login success → Fixed shell execution → Verified benign transfer
```

Nếu bạn gõ một reverse shell bất kỳ qua SSH, flow mã hóa không cho AI biết
đã chạy bash. Cần process audit + parent/session/socket evidence khác để mở
rộng detector. Không ghi nhầm probe này là C2 hoặc chiếm quyền toàn bộ host.

Cài `setup_chain_telemetry.py --username soctest` ở Windows trước khi bật monitor.
Trong Kali, chuẩn bị server một file mẫu (không liên quan SESSION của collector):

```bash
export TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
python3 /usr/local/lib/soc-lab/lab_transfer_server.py --token "$TOKEN" --bind "$SOURCE" --peer "$TARGET" > "/tmp/soc-probe-server-$TOKEN.log" 2>&1 &
export PROBE_SERVER_PID=$!
```

Server chỉ phục vụ fixed text và peer Ubuntu trên port 18080. TOKEN chỉ liên
kết hành động probe với nhau, không phải tên kịch bản hoặc collector session.

Bước 1, scan:

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Bước 2, chạy dòng SSH dưới đây tối đa 8 lần, mỗi lần nhập một mật khẩu sai có
chủ đích. Dừng nếu reset/lockout, không coi reset là thất bại xác thực:

```bash
ssh -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o StrictHostKeyChecking=accept-new "$LABUSER@$TARGET"
```

Khi raw đủ 8 failures/60 giây thì cùng ID có bước guessing, risk 75. Nếu chỉ
7 thì mới auth context, giữ partial và chưa kỳ vọng full five-stage chain.

Bước 3, login đúng và thực hiện hai probe trong **cùng SSH connection**:

```bash
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password "$LABUSER@$TARGET" "python3 /usr/local/lib/soc-lab/endpoint_probe.py --token $TOKEN"
```

Nhập password SSH đúng tại prompt. Probe thực thi `/bin/sh -c 'id; uname -s'`
rồi tải text cố định, kiểm tra bytes/hash; log root-owned liên kết bằng đúng
source port của `SSH_CONNECTION`, user và token. Nó không giám sát mọi command.

Khi đủ evidence: cùng Chain ID có 5 bước, 4 mũi tên liền, risk 95. Stage counts
không tăng vì HTTP/Suricata có nhiều bản sao. Threat Hunting vẫn có auth/sensor/
model events, dashboard Attack Chain chỉ tập trung chain. Có thể có 119205
và chain high 119214; từng stage là 119213.

Sau ≥95 giây không còn hành động: ô giả thuyết cuối gợi ý kiểm tra thực thi
file/persistence/kết nối ra ngoài; **chưa quan sát**, chưa có probability và
không cộng điểm. Không vì vậy tự gọi đây là full kill chain.

Lưu `/tmp/soc-lab-transfer-$TOKEN.jsonl` và server log để đối chiếu peer, path,
bytes/hash. Server có giới hạn lifetime và số response. Nếu còn chạy, dừng
đúng PID vừa khởi tạo:

```bash
kill "$PROBE_SERVER_PID"
```

Nếu server đã tự hết hạn và kill báo No such process, kiểm tra log; không dùng
pkill để dừng các process khác. Không đổi SSH/PAM protections cho bài này.

## 2.2 File upload → execution / kiểm tra sudo / persistence

Đây là vùng mà file gốc gộp quá nhiều kết luận. Phải báo kết quả **từng phase**;
Lab A hiện chưa có general process audit đủ để tự ghép cả chuỗi này từ hành
động tùy ý. Việc không có node shell/persistence trong AI là thiếu telemetry,
không được điền bằng bước giả thuyết để thành chuỗi hoàn chỉnh.

### Phase A: upload PHP probe cố định qua DVWA, rồi thực thi id

Cài FIM trước, chờ baseline. Có thể bắt đầu bằng Nmap nếu muốn quan sát scan
riêng. Tại Kali:

```bash
python3 /opt/soc-lab/dvwa_cli.py upload-fixed-probe --target "$TARGET" --output "/tmp/soc-upload-$(date +%s).json"
```

Nhập password DVWA. Helper upload thật qua form DVWA low, xử lý CSRF/cookie,
với tên `soc-lab-<32 hex>.php`, rồi request file. PHP chỉ chạy `/usr/bin/id`,
không nhận `cmd` hoặc bất kỳ lệnh tùy ý. `fixed_execution_proof=true` cần marker
và output `uid=...`, không chấp nhận server trả source PHP như text.

Native Wazuh kỳ vọng 119250 hoặc 554 với đúng path uploads. Đối chiếu report,
SHA256 file, Apache POST/GET và FIM. FIM riêng không chứng minh upload qua HTTP
hoặc thực thi; chính report/response độc lập và access log giúp chứng minh
các phase đó. AI hiện không tự lấy report này để tạo observed execution stage.

### Phase B: kiểm tra sudo policy, không tự tuyên bố leo quyền

```bash
ssh "$LABUSER@$TARGET"
```

Trong **Ubuntu SSH shell**:

```bash
id
sudo -l
```

Nhập password nếu sudo hỏi. Denied / not in sudoers là **đối chứng âm**, không
phải privilege escalation. Nếu sudo chưa cài thì phase chưa chạy. Không cấp
NOPASSWD hoặc thêm user vào sudo chỉ để tạo alert cho báo cáo. Nếu phát hiện
misconfiguration thật của lab, ghi chính xác quyền được cấp và command/output
trước khi thiết kế phase nâng quyền riêng. Log sudo có thể vào auth.log/native
Wazuh; generic auth normalizer hiện không suy ra effective-root process từ đó.

### Phase C: persistence bằng user cron vô hại, chỉ khi cron có thật

Kiểm tra ngay trong Ubuntu SSH shell:

```bash
command -v crontab
pgrep -x cron
```

Nếu thiếu binary/daemon, đánh dấu **NOT RUN**; không coi một file crontab mẫu
là persistence đã thực thi. Nếu có cron đang chạy, lưu nguyên trạng trước:

```bash
export CRON_TAG=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
export CRON_BACKUP=$(mktemp /tmp/soc-cron-backup.XXXXXX)
crontab -l > "$CRON_BACKUP"
```

Nếu `crontab -l` báo không có crontab, file backup rỗng được giữ làm bằng chứng
ban đầu; ghi lại exit/output. Nếu là lỗi quyền/hệ thống, dừng trước khi cài.
Không chạy hai operator chỉnh cùng một user crontab trong bài này.

```bash
export CRON_TEST=$(mktemp /tmp/soc-cron-test.XXXXXX)
cat "$CRON_BACKUP" > "$CRON_TEST"
printf '\n* * * * * /usr/bin/touch /var/lib/soc-lab/fim/cron-%s.txt # SOC-LAB-%s\n' "$CRON_TAG" "$CRON_TAG" >> "$CRON_TEST"
crontab "$CRON_TEST"
crontab -l
```

Chờ tối đa khoảng 70 giây rồi kiểm tra:

```bash
stat "/var/lib/soc-lab/fim/cron-$CRON_TAG.txt"
```

File do cron tạo, thời gian phù hợp, crontab đã cài và daemon hoạt động là
bằng chứng cho cơ chế user-cron của bài tập. FIM 119253/554 là bằng chứng file,
chưa đủ để AI xác định cron/actor. Không gọi đây là root persistence hoặc
leo quyền nếu user vẫn là soctest.

Ngay sau khi lưu bằng chứng, restore đúng crontab trước bài:

```bash
crontab "$CRON_BACKUP"
crontab -l
rm -- "/var/lib/soc-lab/fim/cron-$CRON_TAG.txt" "$CRON_TEST"
exit
```

Nếu ban đầu không có crontab, restore file rỗng tương đương không có job; giữ
backup/output đến khi nộp. Không xóa crontab người khác và không append job
vô hạn. Đối chiếu thay đổi bất ngờ do operator khác trước khi restore.

Cleanup PHP upload bằng đúng path helper in, **tại Windows** (root được dùng
chỉ cho cleanup file www-data-owned, không tính là bước attacker):

```powershell
$artifact = Read-Host 'Dán artifact_path của PHP probe, không phải SESSION'
if ($artifact -notmatch '^/opt/soc-lab/DVWA/hackable/uploads/soc-lab-[a-f0-9]{32}\.php$') { throw 'Path ngoài artifact của bài.' }
docker exec --user 0 ubuntu-endpoint rm -- $artifact
```

Kết quả phase A/C có thể thành công nhưng toàn chuỗi 2.2 vẫn **partial** nếu
chưa chứng minh phase nâng quyền hoặc chưa có actor/process telemetry. Để tự
nhận dạng đầy đủ cần auditd/Sysmon/eBPF trên môi trường hỗ trợ kernel/capability,
source parser và liên kết process/session; không bật audit kernel VM chung
của Docker Desktop một cách mặc định trong gói này.

## 2.3 Scan → HTTP pressure đồng thời SQLi

Đây là bài nhiều nhánh được engine hỗ trợ. Kỳ vọng sơ đồ root nối tới hai
nhánh, không vẽ rằng HTTP pressure gây ra SQLi. Trong Kali:

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

Lấy baseline:

```bash
for i in $(seq 1 20); do curl --noproxy '*' --fail --silent --show-error --max-time 3 "http://$TARGET/soc-lab-health"; sleep 1; done
```

Khởi động load giới hạn ở background, rồi gõ ngay request SQLi:

```bash
python3 /opt/soc-lab/bounded_http_load.py "$TARGET" > "/tmp/soc-load-$(date +%s).json" &
export LOAD_PID=$!
curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit"
wait "$LOAD_PID"
```

Thường có 3 observed stages: scan, pressure, SQLi. Risk khỏe = max(45,60)+10+5
= **75**, không phải DoS đã thành công. Nếu baseline/degradation đủ điều kiện
thì pressure nâng thành nghi DoS, risk 90. Chưa chứng minh cố tình gây nhiễu.
Chờ ≥95 giây để xem hai hướng điều tra tiếp riêng theo terminal branch.

## 2.4 VirusTotal / Active Response

**DEFERRED theo yêu cầu.** Không chạy payload ELF, không gửi hash/file/API key,
không cài 87105 integration hoặc firewall-drop tự động trong gói này. Bài FIM
và benign transfer ở nhóm 1.5 vẫn giúp kiểm tra đường dữ liệu nền trước khi
bổ sung VirusTotal sau.

## 2.5 Kiểm tra việc tách chain

Trong cùng monitor, làm 2.0 xong, chờ 95 giây. Ghi Chain ID cũ và số bước.
Bắt đầu 2.1 hoặc 2.3 bằng Nmap mới. Dashboard phải có ID mới; ID cũ giữ lại,
không bị đổi thành bài mới. Raw event IDs security của hai chain phải không
trùng. Mỗi branch trong sơ đồ chỉ trỏ tới parent stage của chính chain đó.

Nếu hai bài cùng IP/đích chạy song song hoặc quá sát mà không có session
telemetry phân biệt, hệ thống chỉ đưa giả thuyết episode. Không có giải pháp
đảm bảo tách tác nhân/ý đồ tuyệt đối từ dữ liệu mạng giống nhau. Với dữ liệu
đến trễ, có thể có revision hoặc case cũ superseded; không đếm history update
là những cuộc tấn công khác nhau.

Kết thúc theo [phần kiểm tra bằng chứng](00-PREPARE-VI.md#kết-thúc-và-kiểm-tra-bằng-chứng).
Lưu ảnh graph, raw logs, snapshot/replay, report helper DVWA/server và kết quả
độc lập; không dùng dự đoán MLP hoặc rule match làm ground truth.
