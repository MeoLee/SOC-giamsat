# Nhóm 1 — Hành động đơn lẻ từ Kali Bash

Từ [0.4.9.2](../CHAIN-RETENTION-0492-VI.md), bài chỉ có một bước sẽ tự ẩn khỏi
Attack Chain dashboard sau idle timeout; alert và raw vẫn giữ để đối chiếu.

Làm [chuẩn bị](00-PREPARE-VI.md), bật monitor và mở Kali Bash trước. Biến
`TARGET=172.20.0.3`, `SOURCE=172.20.0.4`, `LABUSER=soctest`. Mỗi bài độc lập:
chờ 95 giây sau bài trước, hoặc mở capture mới nếu đang làm báo cáo đối chứng.
Các lệnh attacker dưới đây không hỏi SESSION.

## 1.0 Đối chứng bình thường

Trong Kali:

```bash
curl --noproxy '*' --max-time 5 -i "http://$TARGET/soc-lab-health"
```

Kỳ vọng HTTP 200, HTTP observation 119210 khi flush. Flow MLP có thể đến sau
khi đóng flow/timeout; model không bắt buộc phải cho BENIGN để coi request
này là bình thường. Kịch bản/response độc lập quyết định ý nghĩa bài control.
Không được tạo distinct-port scan từ một cổng duy nhất. Nếu có model false
positive, lưu riêng; không hạ threshold chỉ để làm mất cảnh báo.

## 1.1 Recon

```bash
nmap -sT -Pn -n --max-retries 0 --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32,80,443 "$TARGET"
```

34 cổng trong một IP private; không dùng `-O`/raw SYN làm điều kiện mặc định
vì Docker có thể thiếu capabilities. `-sT` vẫn là kết nối thật và đủ kiểm tra
port diversity. Tool version `nmap --version` phải chạy được trước bài.

Kiểm tra: EVE có SID 9900003; AI có ≥20 cổng khác nhau trong 10 giây; Threat
Hunting có 119203, chain có 119212, 1 bước scan, risk 40. 9900003 là collection
observation, không phải mỗi SYN đều là một cuộc tấn công. 80/443 đóng không
làm bài scan thất bại nếu probe/refusal vẫn được thu đủ.

Nếu nmap `Operation not permitted` do file capabilities, giữ output `getcap`
và Docker capabilities. Không chuyển container sang privileged để thử lại.
Nếu cùng bản nmap đã sửa capability trước đó thì không cần sửa lần nữa.

## 1.2 Password guessing SSH

Xác minh `soctest` tồn tại; không dùng admin/ubuntu trong file gốc nếu chưa tạo.
Chạy dòng sau, nhập **mật khẩu sai có chủ đích**, không dùng mật khẩu thật:

```bash
ssh -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o StrictHostKeyChecking=accept-new "$LABUSER@$TARGET"
```

Lặp bằng phím ↑ rồi Enter, tối đa 8 lần, trong cửa sổ 60 giây khi điều kiện
lab cho phép. Không dùng rockyou vô hạn. `Permission denied (password)` là
client outcome dự kiến; kiểm tra từng `Failed password` ở auth.log. SSH reset,
connection refused/timeout hoặc exit 255 chung không phải password failure.

Khi raw đủ 8 password failures đúng nguồn/host/account trong 60 giây: có
`repeated_auth_failures`, standalone base 65; sau scan cùng episode là 75.
Native Wazuh có thể xuất 5760/5763 hoặc nhánh auth tương ứng, không bắt buộc
5712. Tần suất Wazuh có semantics riêng, không buộc bằng chính xác ngưỡng AI.

**Lỗi đã gặp trên lab của bạn:** 7 failures rồi reset ở lần 8. Khi đó ghi partial;
chain sau scan chỉ có auth context, chưa đủ guessing. Dừng nhánh, chờ SSH policy
cho phép lại; không tắt PAM/lockout/PerSourcePenalties để ép kết quả. Giữ auth.log
và thời gian từng lần thử. Các bước HTTP của bài khác vẫn có thể được kiểm tra.

Đối chứng đăng nhập đúng, không có chuỗi failure trước đó:

```bash
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password "$LABUSER@$TARGET"
```

Trong shell Ubuntu gõ `id`, `exit`. Nếu không có audit/process telemetry, AI
chỉ biết auth success; không tự thêm bước shell chỉ vì operator đã gõ `id`.

## 1.3 SQLi indicator và kiểm chứng kết quả DVWA

Một request để kiểm tra đường phát hiện:

```bash
curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit"
```

Kỳ vọng chữ ký Suricata 9900101 → native 86601 và AI sensor 119209; Apache
TSV → 119206; native Apache có thể có 31103. Một operation có nhiều event
bằng chứng, không phải nhiều chain. Standalone SQLi risk 60; có scan trước 70.
302 redirect tới login vẫn có thể match indicator; chưa chứng minh khai thác.

Để kiểm chứng SQLi thật trên **DVWA low** bằng hai hằng số, không dump DB:

```bash
python3 /opt/soc-lab/dvwa_cli.py sqli --target "$TARGET" --output "/tmp/soc-sqli-$(date +%s).json"
```

Nhập password DVWA tại prompt (lab default thường `password`, user `admin`).
Helper login/CSRF và cookie nằm trong memory, không in/lưu credentials. Nó
so sánh baseline rồi yêu cầu kết quả `First name: SOCLAB_UNION_PROOF` và
`Surname: SOCLAB_SECOND_COLUMN`, tránh nhầm marker chỉ được phản chiếu trong
URL. `query_result_proof=true` mới xác nhận query cố định có tác động lên kết
quả. AI live vẫn ghi SQLi attempt, chưa tự lấy file report này làm nhãn/model
hoặc tự tuyên bố database compromise. Nếu schema/login/security khác, helper
dừng và giữ đó là incomplete; không reset DB chỉ để test qua.

Không chạy đồng thời sqlmap enumeration hoặc dump khi đo bài single request.
Có thể nghiên cứu sqlmap riêng sau khi đã xác nhận session/cookie và giới hạn
request; bản hướng dẫn hiện dùng truy vấn cố định để dễ truy vết.

## 1.4 HTTP pressure / điều kiện nghi DoS

Baseline trong Kali:

```bash
for i in $(seq 1 20); do curl --noproxy '*' --fail --silent --show-error --max-time 3 "http://$TARGET/soc-lab-health"; sleep 1; done
```

Tải có giới hạn:

```bash
python3 /opt/soc-lab/bounded_http_load.py "$TARGET"
```

100 request, tối đa 20 starts/s và 4 concurrent, timeout 2 giây, không follow
redirect hoặc dùng proxy. Đếm Apache TSV: ≥60 requests/10 giây → HTTP pressure.
Standalone risk 45; scan trước là 55. Server trả toàn bộ 200 nhanh thì đây là
kết quả đúng, không báo đã DoS thành công.

Nghi DoS chỉ khi có baseline khỏe ≥10 request trong 120 giây và sau đó burst
có ≥20% và ≥5 request 5xx hoặc duration ≥1 giây. Khi đủ điều kiện mới có
`possible_http_dos`, base 75. Kiểm tra tài nguyên và lỗi ứng dụng độc lập;
nguyên nhân vẫn chưa được chứng minh. Không tự gán DDoS từ một nguồn.

Không áp dụng kết luận này cho `slowhttptest -H`: các connection chưa hoàn tất
có thể **chưa xuất hiện trong access.log**. Bộ đếm request hoàn thành có điểm
mù đó. Không chạy 1000 slow connections trên Apache 16 workers để ép cảnh báo;
bài slow-header cần telemetry active connections/worker health và profile
riêng trước khi đánh giá detector.

## 1.5 File transfer và FIM, không VirusTotal

Cần cài FIM từ phần chuẩn bị và chờ baseline xong. Trong Kali:

```bash
export TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
export EXPORTDIR=$(mktemp -d /tmp/soc-lab-file.XXXXXX)
printf 'SOC LAB BENIGN FILE TRANSFER\n' > "$EXPORTDIR/probe.txt"
sha256sum "$EXPORTDIR/probe.txt"
python3 -m http.server 18081 --bind "$SOURCE" --directory "$EXPORTDIR" > "$EXPORTDIR/server.log" 2>&1 &
export FILESERVER_PID=$!
```

Từ Kali điều khiển Ubuntu qua SSH bằng tài khoản lab, tải đúng một file:

```bash
ssh "$LABUSER@$TARGET" "curl --noproxy '*' --fail --silent --show-error --max-time 5 --output /var/lib/soc-lab/fim/$TOKEN.txt http://$SOURCE:18081/probe.txt && sha256sum /var/lib/soc-lab/fim/$TOKEN.txt"
```

Nhập password SSH đúng, so SHA256 hai phía. Đây là transfer thật của text vô
hại; có access log ở server Kali. Native FIM kỳ vọng 119253 hoặc 554 với
`syscheck.path=/var/lib/soc-lab/fim/<TOKEN>.txt`. Không gán malware chỉ vì có
file mới, không có 87105 trong đợt này. FIM thiếu source IP/SSH session nên AI
không tự kéo file vào một attack chain chỉ dựa theo thời gian.

Trong Threat Hunting, bỏ filter `data.soc_ai_producer` nếu đang dùng; native
FIM không có field đó. Lọc `agent.name: "ubuntu-endpoint"` và `syscheck.path`
của artifact, hoặc `rule.groups: "soc_lab_fim"`.

Thử sửa và xóa, mỗi lần đợi alert trước khi làm tiếp:

```bash
ssh "$LABUSER@$TARGET" "printf 'LAB MODIFIED\n' >> /var/lib/soc-lab/fim/$TOKEN.txt"
ssh "$LABUSER@$TARGET" "rm -- /var/lib/soc-lab/fim/$TOKEN.txt"
kill "$FILESERVER_PID"
```

Kỳ vọng 119251/550 khi sửa, 119252/553 khi xóa. Xóa do operator cleanup không
phải bằng chứng defense evasion. Thư mục EXPORTDIR chứa log bằng chứng nên giữ
đến khi chép ra để nộp báo cáo; server đã dừng.

## 1.6 Firewall trong Docker — chỉ làm khi có kernel log thật

Bài này có gate riêng. Ở **PowerShell Windows**:

```powershell
docker exec ubuntu-endpoint iptables -S
docker exec ubuntu-endpoint sh -c 'test -r /var/log/kern.log && tail -n 5 /var/log/kern.log'
```

Nếu iptables báo thiếu quyền hoặc kernel log không đọc được: đánh dấu
**NOT RUN — thiếu capability/log transport**, giữ readiness report. Root
trong container không đồng nghĩa có NET_ADMIN. Docker Desktop dùng kernel
VM chung; không mặc định có syslog kernel trong Ubuntu container. Không dùng
`logger` viết log giả rồi coi là packet đã bị firewall chặn. Không dùng
privileged, host network hoặc flush iptables cho bài này.

Nếu đã có NET_ADMIN **và đường chuyển kernel log vào file thật**, mở Ubuntu
Bash ở terminal riêng:

```powershell
docker exec -it ubuntu-endpoint bash
```

Trong **Ubuntu Bash** tạo đúng chain riêng, không sửa policy toàn cục:

```bash
iptables -N SOC_LAB_TEST
iptables -A SOC_LAB_TEST -m limit --limit 5/second --limit-burst 10 -j LOG --log-prefix 'SOC_LAB_FW_DROP '
iptables -A SOC_LAB_TEST -j DROP
iptables -I INPUT 1 -s 172.20.0.4 -d 172.20.0.3 -p tcp -m multiport --dports 4444,5555,6666 -j SOC_LAB_TEST
```

Nếu chain đã tồn tại, dừng và xem `iptables -S SOC_LAB_TEST`; không append
trùng. Trước khi mở Ubuntu Bash, tại PowerShell chạy:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.4-research'
$py = 'E:\SOC-Lab\AI\.venv-ai04-cpu\Scripts\python.exe'
& $py .\setup_scenario_fim.py --kernel-log /var/log/kern.log
if ($LASTEXITCODE -ne 0) { throw 'Kernel input chưa đạt; chưa chạy bài firewall.' }
```

Installer chỉ nhận file thật đã tồn tại, backup, thêm input syslog, validate
và restart Agent trước bài.
Prefix một token giúp decoder kernel tách action/port đúng.

Trong **Kali Bash**:

```bash
nmap -sT -Pn -n --max-retries 0 --max-rate 2 --host-timeout 10s -p 4444,5555,6666 "$TARGET"
```

Kiểm tra Ubuntu: `iptables -nvL SOC_LAB_TEST`; counter phải tăng, kernel log
mới có đúng SRC/DST/DPT/prefix và thời gian. Wazuh 119254 chỉ xác nhận kernel
observation đã decode; quyết định DROP phải đối chiếu rule và counter. Ba
cổng không đủ threshold 20 để tạo scan chain; đây là control hợp lý.

Cleanup tại **Ubuntu Bash** sau khi lưu counter/log:

```bash
iptables -D INPUT -s 172.20.0.4 -d 172.20.0.3 -p tcp -m multiport --dports 4444,5555,6666 -j SOC_LAB_TEST
iptables -F SOC_LAB_TEST
iptables -X SOC_LAB_TEST
```

Chỉ xóa chain của bài này. Không `iptables -F` toàn bộ.

Mẫu localfile phải được thêm làm sibling trong ossec_config Agent, không tạo
file kern.log giả; backup config trước khi sửa:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

Chạy `docker exec ubuntu-endpoint /var/ossec/bin/wazuh-logcollector -t` rồi
`docker exec ubuntu-endpoint /var/ossec/bin/wazuh-control restart` ở Windows.
Nếu không có đường kernel transport thật thì bỏ qua bài này, không thêm input
trỏ tới file không tồn tại.
