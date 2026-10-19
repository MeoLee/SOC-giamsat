# Kịch bản kiểm thử AI Lab A

Chạy replay trước để kiểm tra chương trình; sau đó mới thu capture thật để đo chất lượng. Bắt đầu cài đặt từ [README-START-VI.md](../README-START-VI.md); quy trình tạo môi trường và train từ đầu ở [INSTALL-TRAIN-VI.md](INSTALL-TRAIN-VI.md). `lab_scenarios.py` chỉ có ba lệnh `plan`, `replay`, `register`. Công cụ **không chạy Docker, không phát traffic, không train và không thực thi tấn công**. Các lệnh Docker/SSH/HTTP trong tài liệu này do người vận hành chủ động chạy trên lab riêng.

## 1. Replay ngay, chưa cần Docker hoặc model

Mở PowerShell trong thư mục mã nguồn mới. Ví dụ Python inference đã có NumPy:

```powershell
$py = 'E:\SOC-Lab\AI\.venv-infer\Scripts\python.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$replay = "E:\SOC-Lab\AI\scenario-replay-$stamp"
& $py .\lab_scenarios.py plan
& $py .\lab_scenarios.py replay --output $replay
if ($LASTEXITCODE -ne 0) { throw 'Replay chưa đạt; đọc replay-report.json.' }
& $py -m unittest test_lab_scenarios -v
```

Thư mục output phải mới. Gói hiện tại kiểm tra 38 điều kiện replay và có 18 ca unittest cho tooling. Các fixtures dùng địa chỉ tài liệu `192.0.2.0/24`; không có gói tin được gửi tới các địa chỉ đó.

Replay kiểm tra đúng code normalizer/correlation/context/cursor/outbox đang dùng, không dùng model giả để tuyên bố độ chính xác:

- SSH: login bình thường, dưới ngưỡng, tám lỗi rồi success, success trước burst, khác user/source/host, ngoài cửa sổ và log tới trễ qua hai lần poll.
- HTTP: URL đối chứng và SQL indicator; HTTP 200 không trở thành bằng chứng khai thác thành công.
- Context shadow: 32 cổng khác nhau so với 32 kết nối cùng cổng; HTTP bình thường so với burst khi bật ngưỡng fixture rõ ràng.
- Thu log: partial newline, mất một source, source khác vẫn commit, rename inode và đọc đuôi cũ, resume từ cursor đã commit, mất inode phải ghi gap.
- Outbox: sender lỗi, pending bền qua restart, giữ event ID và manager ban đầu.

**38/38 chỉ chứng minh các hợp đồng phần mềm này đạt.** Nó không chứng minh FPR, recall, chống DDoS hoặc hoạt động thực tế trên Windows. Fixture, `synthetic-outbox.sqlite` và mọi output replay phải để ngoài dataset thật. Tool gắn `synthetic:true`, `accuracy_evidence:false`; không đổi cờ này để đưa fixture qua quality gate.

## 2. Chuẩn bị phiên thật và bằng chứng

Ubuntu endpoint tiếp tục là máy có Wazuh agent. Không cài agent vào Kali để chạy các ca này. Asset mapping giúp xác định máy đích; không tạo whitelist IP attacker và không dùng `--endpoints` để che traffic khác trong AI Live.

Mỗi ca dùng một capture riêng. Chạy ít nhất hai ngày/đợt độc lập, đổi source port, thời lượng, người dùng lab và nội dung normal. Train, validation và final test phải khác capture; final test không được dùng chọn threshold/model hoặc trộn vào train. Nếu đã xem final test rồi chỉnh model theo kết quả, dành đợt capture mới cho lần kiểm chứng cuối.

Trước khi phát traffic, xác nhận cặp container và mạng Docker riêng. Chỉ chọn đúng network dùng cho dịch vụ lab, không lấy địa chỉ Internet hay mạng công ty:

```powershell
docker inspect --format '{{json .NetworkSettings.Networks}}' kali-attacker
docker inspect --format '{{json .NetworkSettings.Networks}}' ubuntu-endpoint
docker network ls
$labNetwork = 'TEN_NETWORK_DOCKER_CUA_LAB' # Thay bằng tên thực ở hai kết quả inspect.
$networkInfo = docker network inspect $labNetwork | ConvertFrom-Json
$clientInfo = docker inspect kali-attacker | ConvertFrom-Json
$endpointInfo = docker inspect ubuntu-endpoint | ConvertFrom-Json
if ($networkInfo.Driver -ne 'bridge') { throw 'Chỉ dùng bridge network Docker riêng của lab.' }
$clientAddress = $clientInfo.NetworkSettings.Networks.PSObject.Properties[$labNetwork].Value.IPAddress
$target = $endpointInfo.NetworkSettings.Networks.PSObject.Properties[$labNetwork].Value.IPAddress
function Test-LabPrivateIPv4([string]$address) {
    $parsed = [System.Net.IPAddress]::Parse($address)
    $bytes = $parsed.GetAddressBytes()
    return ($bytes.Length -eq 4 -and ($bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)))
}
if (-not $clientAddress -or -not $target -or $clientAddress -eq $target -or
    -not (Test-LabPrivateIPv4 $clientAddress) -or -not (Test-LabPrivateIPv4 $target)) {
    throw 'Hai container phải có hai địa chỉ RFC1918 khác nhau trên đúng bridge lab.'
}
Write-Host "Lab: $clientAddress -> $target tren $labNetwork"
```

Phần guard này kiểm tra địa chỉ và network cho các lệnh kế tiếp; nó không chứng minh toàn bộ Docker đã cô lập khỏi Internet. Không đổi `$target` sang host ngoài cặp lab đã kiểm tra. Kiểm tra interface Suricata sau mỗi lần tạo lại network; tên `eth0`/`eth1` có thể đổi.

Kiểm tra nguồn bằng doctor, rồi mở AI Live trong một cửa sổ PowerShell riêng:

```powershell
$baseline = 'E:\SOC-Lab\AI\runs\MODEL_BASELINE_DA_XAC_MINH'
$benchRoot = 'E:\SOC-Lab\AI\benchmark-captures'
& $py .\lab_doctor.py --config .\live-config.json --model $baseline --runtime
if ($LASTEXITCODE -ne 0) { throw 'Sửa source/model trước khi chạy kịch bản.' }
& $py -u .\lab_live.py --model $baseline --config .\live-config.json `
    --output-dir $benchRoot --interval 1 --grace 30 --heartbeat-seconds 5
```

Ghi đường dẫn `SESSION:` vào nhật ký ca. Mặc định Live mới không có `--resume`; khởi động lại tạo phiên khác. Chỉ collector độc lập `soc_live_collector.py` có `--resume` cho phiên chưa đóng. Không mở hai watcher chung một outbox.

Trước ca, ghi giờ có timezone, source/target, lệnh, tên người thực hiện và kết quả dự kiến vào operator log. Sau ca, ghi kết quả quan sát thực, không sửa thành kết quả AI muốn. Bằng chứng thứ hai là auth log, Apache log, PCAP hoặc kết quả ứng dụng độc lập. Giữ bytes gốc và SHA256; không đưa mật khẩu, cookie hoặc token vào repo.

Nhấn Ctrl+C **một lần**, đợi hết grace và đóng phiên. Flow có thể chỉ xuất hiện khi kết nối đóng hoặc Suricata timeout; nếu chưa có completed flow thì chờ và thu lại, không tự bù counter. Phiên dùng benchmark phải `closed:true`, `status:completed`, không gap/partial/lỗi source. Việc capture đóng không chứng minh mọi packet đã được sensor thấy.

## 3. Các ca thật có giới hạn

Các lệnh dưới đây giả sử guard ở trên đã chạy và các tiện ích có sẵn trong Kali. Chúng không tự cài phần mềm. Lưu stdout/stderr cùng giờ bắt đầu/kết thúc làm transcript. Nếu lệnh thất bại hoặc timeout, ghi đúng kết quả; không coi ca đã chạy đủ.

| Ca | Thao tác | Kỳ vọng cần đo |
|---|---|---|
| normal-ssh | Login đúng, giữ phiên ngắn/dài khác nhau, chạy lệnh thông thường rồi thoát | FPR/unknown của completed flows; không có burst auth giả |
| normal-http | Trang health/login, id=1, catalog, tools, assets/script.js, O'Reilly | Không có SQL indicator cho URL đối chứng; 404 bình thường vẫn có thể là negative |
| scan-many-ports | 32 cổng TCP, tối đa 5 probe/giây, một endpoint | Context nhiều cổng xuất hiện; MLP/rule/context báo riêng |
| repeat-single-port | 32 lần kết nối cùng cổng SSH, nhịp tương đương | Không có tín hiệu **distinct-port**; SYN rule cũ vẫn có thể báo và phải ghi hạn chế |
| ssh-fail-success | Tài khoản lab riêng, 8 lỗi/60 giây rồi đúng mật khẩu | Same host/source/account; `suspicious_login_sequence`, không tự xác nhận compromise |
| ssh-negative-controls | Dưới ngưỡng; success trước, khác user/source/host hoặc muộn | Không ghép thành success sau burst sai thực thể; failure-only có thể vẫn là nghi vấn |
| web-sqli-indicator | Tối đa 2 GET SQLi không phá dữ liệu trên DVWA riêng | Bằng chứng request SQL; không có lớp MLP SQLi, HTTP 200 chưa chứng minh thành công |
| http-bounded-burst | Một nguồn, tối đa 5 request/giây, cửa sổ bắt đầu 10 giây | Rate/latency/status và context shadow; **không gọi là DDoS** |

Login normal dùng tài khoản lab có thật, nhập mật khẩu trực tiếp tại prompt:

```powershell
$labUser = 'TEN_TAI_KHOAN_LAB'
docker exec -it kali-attacker timeout 30 ssh -o ConnectTimeout=5 -o ConnectionAttempts=1 `
    -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no `
    -o PreferredAuthentications=password "$labUser@$target" true
```

Ca fail-success dùng chính lệnh trên với timeout mỗi lần 8 giây, nhập mật khẩu cố ý sai tám lần rồi đúng một lần. Chỉ dùng tài khoản test được chuẩn bị cho ca; kiểm tra policy lockout trước. Xác nhận auth log có đủ tám failure trong 60 giây, không lấy số lần bấm chạy làm số failure. Tách phiên đối chứng khác account/source/host. Flow login đúng sau đó không tự mang nhãn `SSH-Patator`; nếu cần benchmark MLP, chọn riêng các flow có bằng chứng đồng nhất hoặc giữ ca này cho kiểm thử correlation.

Normal HTTP, khoảng một request/giây, tổng sáu request:

```powershell
$normalPaths = @('/soc-lab-health','/dvwa/login.php','/catalog','/tools','/assets/script.js','/?author=O%27Reilly')
foreach ($path in $normalPaths) {
    docker exec kali-attacker curl --max-time 3 --retry 0 --silent --show-error `
        --output /dev/null --write-out '%{http_code} %{time_total}\n' "http://${target}${path}"
    Start-Sleep -Seconds 1
}
```

Để thu normal HTTP đủ lớn cho train, dùng công cụ `collect_normal_http.py` hiện có theo hướng dẫn Quality; công cụ đó ghép client/server bằng tuple và thời gian. Sáu URL ở đây là bộ đối chứng heuristic nhỏ, chưa đủ chứng minh FPR thấp.

Scan có giới hạn; `-sT` dùng TCP connect, không quét public và không dùng toàn bộ 65.535 cổng:

```powershell
docker exec kali-attacker timeout 30 nmap -sT -Pn -n --max-retries 0 `
    --scan-delay 200ms --max-parallelism 1 --max-rate 5 --host-timeout 25s -p 1-32 $target
```

Đối chứng cùng một cổng, giới hạn 32 lần và 30 giây; `nc` chỉ thử kết nối TCP, không thử mật khẩu:

```powershell
docker exec kali-attacker timeout 30 sh -c 'i=0; while [ "$i" -lt 32 ]; do nc -z -w 1 "$1" 22; i=$((i+1)); sleep 0.2; done' soc-repeat $target
```

Context dùng bucket thời gian UTC cố định. Một sweep bị tách hai phía ranh giới cửa sổ có thể không đạt ngưỡng ở cả hai bucket; chạy thêm ca ranh giới và ghi kết quả. Không sửa thời gian log để làm ca đạt.

SQLi: đăng nhập DVWA bằng tài khoản lab, giữ cookie trong Kali tại file riêng `/tmp/lab-dvwa-cookie` có quyền chỉ chủ sở hữu đọc. Gửi mỗi URL tối đa một lần, `--max-time 5 --retry 0`; lưu response để kiểm tra ứng dụng. Nếu chưa có cookie hợp lệ, redirect/login page không phải khai thác thành công. Ví dụ một GET đọc dữ liệu, không có câu lệnh thay đổi database:

```powershell
$sqliPath = '/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%201%2C2--%20-&Submit=Submit'
docker exec kali-attacker curl --max-time 5 --retry 0 --silent --show-error `
    --cookie /tmp/lab-dvwa-cookie --output /tmp/lab-sqli-response.html `
    --write-out '%{http_code} %{time_total}\n' "http://${target}${sqliPath}"
```

Không đưa cookie vào bằng chứng chia sẻ. Ghi hash response và nhận xét kết quả ứng dụng đã kiểm tra. Kỳ vọng `possible_web_sqli` chỉ cho biết request có chỉ dấu SQL; không đổi nhãn Bot thành SQLi và không đưa flow SQLi vào một lớp MLP hiện chưa có.

HTTP burst có giới hạn, tối đa 50 request, một nguồn. Vòng lặp dừng khởi tạo request sau 10 giây, mỗi request timeout ba giây; request cuối có thể hoàn tất sau mốc 10 giây:

```powershell
$burstClock = [System.Diagnostics.Stopwatch]::StartNew()
$requests = 0
while ($burstClock.Elapsed.TotalSeconds -lt 10 -and $requests -lt 50) {
    docker exec kali-attacker curl --max-time 3 --retry 0 --silent --show-error `
        --output /dev/null --write-out '%{http_code} %{time_total}\n' "http://${target}/soc-lab-health"
    $requests++
    Start-Sleep -Milliseconds 200
}
Write-Host "Requests=$requests elapsed=$($burstClock.Elapsed.TotalSeconds)"
```

Đây là bài thử rate indicator và vận hành, không phải benchmark lớp DDoS. HTTP context mặc định tắt; chỉ bật shadow khi đã có baseline workload. Không lấy ngưỡng fixture 20 request làm ngưỡng production/lab tối ưu. Với MLP, chỉ dùng nhãn DDoS khi có bộ dữ liệu/chứng cứ phù hợp cho hành vi đó; không dùng tên scenario để gán nhãn hàng loạt.

## 4. Đăng ký capture thật cho benchmark

Không đưa cả log nền của một capture vào lớp attack vì vừa chạy một lệnh attack. `register` yêu cầu khung thời gian và cặp source/target rõ ràng; có thể giới hạn cổng đích. Chỉ flow có **toàn bộ start/end nằm trong khung**, đúng chiều source/target và đúng cổng mới được chọn. Flow bắc qua ranh giới và chiều ngược bị loại, không âm thầm đổi nhãn. Các ca có kết quả lẫn lộn phải tách bằng bằng chứng chặt hơn hoặc dùng preparer per-flow riêng.

Tạo một thư mục bằng chứng ngoài repo, chép [evidence-template.json](../scenarios/evidence-template.json) vào đó thành `evidence.json`. Đặt `operator-log.txt` và auth/server excerpt/PCAP thật cạnh file này. Điền:

- `capture_session_id`: đúng `session_id` trong `session.json` đã đóng; khác đợt capture phải dùng ID khác.
- `scenario`, `expected_attack`: theo hành vi được xác nhận, không theo kết quả AI/rule. Với retry cùng cổng được xác nhận bình thường có thể là false; burst có chủ đích không tự đồng nghĩa lớp DDoS.
- `collected_at`, `flow_scope.start_time/end_time`: ISO datetime có timezone, ví dụ `+07:00` hoặc `Z`; không giả định múi giờ từ máy đọc.
- `src_ip`, `dest_ip`, `dest_ports`: đúng endpoints trong EVE/PCAP. Mapping asset không thay thế tuple của gói tin.
- `all_selected_flows_share_outcome`: template cố ý đặt false. Chỉ đổi thành true sau khi đã đối chiếu mọi flow trong scope có cùng verdict binary; không dùng cho capture hỗn hợp failure/success/background.
- `artifacts`: tối thiểu một operator log/transcript **và** một auth/web log, PCAP hoặc kết quả ứng dụng. Đường dẫn tương đối trong thư mục bằng chứng; không dùng AI output hoặc rule alert làm sự thật duy nhất.

Ví dụ đăng ký normal SSH làm final test, sau khi đã điền bằng chứng thực:

```powershell
$closedCapture = 'E:\SOC-Lab\AI\benchmark-captures\raw\THU_MUC_SESSION_DA_DONG'
$evidence = 'E:\SOC-Lab\AI\benchmark-evidence\normal-ssh-day2\evidence.json'
$registered = 'E:\SOC-Lab\AI\benchmarks\normal-ssh-day2-final'
& $py .\lab_scenarios.py register --session $closedCapture --evidence $evidence `
    --output $registered --id normal-ssh-day2-final --role test `
    --scenario normal-ssh --expected benign --expected-class BENIGN
if ($LASTEXITCODE -ne 0) { throw 'Chưa đăng ký được; đọc lỗi và giữ nguyên capture gốc.' }
```

Tool kiểm tra trạng thái đóng/hoàn tất, mọi hash source, bằng chứng, scope và completed-flow schema; tạo mới `flows.ndjson`, `manifest.json`, `selection-report.json`, copy bằng chứng và hash. Nó **không chứng minh lời khai của người vận hành đúng**, không tự xác minh PCAP khớp flow, không train hoặc thay threshold. Bằng chứng cần được người nghiên cứu xem lại. Không có labels được thêm vào từng flow; đây là manifest benchmark, không phải manifest train.

Manifest dùng `soc-lab-benchmark/1.0`, root và session đều `synthetic:false`, evidence độc lập, provenance capture ID. Gọi `evaluate_lab.py --help` để dùng paired evaluator so baseline/candidate trên cùng tập đã khai báo. Một capture nhỏ chưa đủ qua quality gate; cần đủ nhiều phiên độc lập, đủ mẫu, nhiều loại normal/attack và không trùng bất kỳ role nào đã dùng trong quá trình train/chọn model. Không giảm yêu cầu chỉ để hiện PASS.

## 5. Ca lỗi vận hành và tiêu chí chấp nhận

Replay đã mô phỏng các lỗi dưới đây bằng transport trong bộ nhớ. Chỉ chạy biến thể thật trong bản sao lab có thể khôi phục. Không truncate/xóa auth/EVE của lab đang dùng để giả lập lỗi và không kill training worker để thử checkpoint.

| Ca | Cách thử thật có kiểm soát | Chấp nhận |
|---|---|---|
| Source không có | Config bản sao trỏ một source vào file không tồn tại; doctor phải fail trước live. Với mất source giữa phiên, giữ raw/checkpoint và xem last_error | Lỗi hiện rõ, không báo đầy đủ giả; nguồn khác không bị rollback |
| Rotation rename | Dùng cơ chế logrotate có sẵn trên bản sao endpoint, giữ inode cũ chưa nén; ghi vài dòng kiểm thử phân biệt trước/sau | Raw đọc nốt đuôi cũ, không lặp complete line; nếu inode mất phải ghi gap |
| Collector restart | Collector độc lập, đóng bất thường trong lab sao chép rồi `--resume` chính thư mục chưa đóng | Kiểm tra `.uncommitted-*`, cursor và raw hash; Live chính tạo phiên mới, không giả định resume tự động |
| Container recreate | Chỉ trên bản sao, tạo lại sensor khi đang collector | Có gap vì container ID đổi; không tuyên bố capture lossless |
| Wazuh outage | Ưu tiên replay. Nếu cần thật, tạm pause đúng manager lab trong khối try/finally rồi unpause; gửi một smoke event bằng outbox riêng | Pending giữ qua restart, retry cùng event_id, không mất cảnh báo âm thầm |

Ví dụ outage thực chỉ đụng manager lab đã biết; luôn unpause trong `finally`. Không chạy chung outbox với AI Live:

```powershell
$manager = 'single-node-wazuh.manager-1'
$outbox = "E:\SOC-Lab\AI\outage-test-$stamp.sqlite"
docker pause $manager
if ($LASTEXITCODE -ne 0) { throw 'Không pause được manager; không chạy bước tiếp.' }
try {
    & $py .\wazuh_bridge.py --outbox $outbox --manager $manager --smoke-test
    # Trong outage, PENDING/ERROR là kết quả dự kiến; giữ lại outbox.
} finally {
    docker unpause $manager
}
& $py .\wazuh_bridge.py --outbox $outbox --manager $manager
```

Đối chiếu cùng `event_id` ở outbox, manager JSON log, Wazuh `alerts.json` và indexer nếu có. Ack append manager chỉ xác nhận đã ghi log; smoke `--verify-alert` chỉ xác nhận alert manager. Không tự ghi rằng dashboard/indexer đã nhận nếu chưa truy vấn ở đó. Tất cả ca outage/rotation/degraded giữ cho nghiên cứu độ bền; không nhập vào benchmark model bằng lệnh `register`.

## 6. Bảng kết quả nên gửi lại

Mỗi hàng ghi capture ID, role, scenario, giờ có timezone, raw hashes, số flow chọn/loại, số request/auth event, verdict độc lập, số prediction/unknown/error, số context signal và correlation case, outbox pending cuối, link bằng chứng. Báo riêng model, rule, correlation và context; chúng trả lời các câu hỏi khác nhau. FPR/recall của model phải đi cùng mẫu số, coverage và độ bất định; không thay unknown thành BENIGN. Bộ replay và các ca thật nhỏ là bước kiểm chứng triển khai trước khi chấp nhận model mới.
