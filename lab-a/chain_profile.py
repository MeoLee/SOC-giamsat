"""Native Wazuh/OpenSearch Vega case reader; no endpoint or model changes.

Read existing compact correlation messages, including older 0.4.6 messages.
Recommendations are a local investigation runbook, never event evidence.
"""
import json
from urllib.parse import quote

PROFILE_ID = 'soc-ai-chain-profile-dashboard-v1'
READER_ID = 'soc-ai-chain-profile-reader-v1'

# Display names, evidence requirements and follow-up hypotheses are curated.
# ATT&CK does not prescribe a mandatory technique order or predict the future.
STEPS = [
    {'key':'observed_eicar_transfer','label':'Chuyển file EICAR qua SSH','technique':'T1105',
     'meaning':'Receiver ghi đúng phiên SSH và xác minh 68 bytes/hash của file thử antivirus EICAR. FIM và VirusTotal bổ sung bằng chứng vào bước này; không phải hành động mới. Không xác nhận mã độc thực, thực thi hay chiếm quyền.',
     'requirement':'Đối chiếu IP, account, source_port, token, artifact_path và hash. fim_alert_id phải trùng virustotal.source.alert_id trên cùng agent. vt_status cho biết VT đã về hay chưa.'},
    {'key':'observed_auth_failures','label':'Các lần sai mật khẩu — ngữ cảnh','technique':'unmapped',
     'meaning':'Có failures sau scan, nhưng chưa đạt điều kiện burst theo account/cửa sổ. Không gán brute force hoặc tăng điểm chỉ từ những failure rời.',
     'requirement':'Đối chiếu auth.log, số failures, thời gian và lỗi SSH reset/lockout trong operator.json.'},
    {'key':'http_request_pressure','label':'Lưu lượng HTTP vượt ngưỡng','technique':'unmapped',
     'meaning':'Số request Apache vượt ngưỡng theo nguồn, đúng host/IP/service. Chưa đủ bằng chứng DoS hoặc suy giảm dịch vụ.',
     'requirement':'Đối chiếu request count/window, log server, baseline và lỗi/latency; loại trừ load test hợp lệ.'},
    {'key':'possible_http_dos','label':'Áp lực HTTP kèm suy giảm dịch vụ','technique':'T1499',
     'meaning':'Rate vượt ngưỡng kèm tăng 5xx hoặc request chậm so với baseline trước đó. Đây là nghi vấn DoS; chưa chứng minh nguyên nhân hoặc ý đồ.',
     'requirement':'Kiểm tra baseline, 5xx, latency và tài nguyên/service health độc lập; chưa xác nhận outage hay DDoS.'},
    {'key': 'possible_recon', 'label': 'Quét cổng / khám phá dịch vụ', 'technique': 'T1046',
     'meaning': 'Nhiều cổng đích được truy cập trong cửa sổ phát hiện. Chưa chứng minh đăng nhập hoặc khai thác thành công.',
     'requirement': 'Đối chiếu IP nguồn/đích, số cổng khác nhau, ngưỡng và thời gian; loại trừ máy quét được phép.'},
    {'key': 'repeated_auth_failures', 'label': 'Thử sai mật khẩu nhiều lần', 'technique': 'T1110.001',
     'meaning': 'Log SSH server ghi đủ password failures theo cùng nguồn, host và tài khoản. Lỗi reset kết nối không được tính là sai mật khẩu.',
     'requirement': 'Đọc auth.log và từng lần từ chối; kiểm tra ngưỡng/cửa sổ, PAM, lockout và chính sách SSH trước khi kết luận.'},
    {'key': 'auth_success_after_failures', 'label': 'Đăng nhập thành công sau chuỗi thất bại', 'technique': 'T1078',
     'meaning': 'Có auth success sau chuỗi sai mật khẩu được ghép theo nguồn, host, tài khoản và cửa sổ thời gian. Chưa chứng minh tài khoản bị đánh cắp.',
     'requirement': 'Xác nhận chủ tài khoản, mục đích đăng nhập, cổng nguồn của phiên SSH và thời điểm success.'},
    {'key': 'observed_shell_execution', 'label': 'Thực thi shell trong bài lab', 'technique': 'T1059.004',
     'meaning': 'Probe ghi hành động shell cố định thành công, liên kết với đúng phiên SSH. Đây là telemetry của bài tập, không phải giám sát mọi lệnh trên host.',
     'requirement': 'Đối chiếu command, return code, user, IP, source port, token và timestamp với log SSH độc lập.'},
    {'key': 'observed_file_transfer', 'label': 'Tải file mẫu có kiểm chứng', 'technique': 'T1105',
     'meaning': 'Probe nhận file mẫu vô hại, đúng bytes và SHA256 sau shell trong cùng phiên/token. T1105 là ứng viên mô phỏng; chưa chứng minh tải công cụ độc hại hoặc C2.',
     'requirement': 'Đối chiếu URL, SHA256, bytes và bằng chứng HTTP server trong operator.json; không chỉ dựa vào HTTP status.'},
    {'key': 'possible_web_sqli', 'label': 'Dấu hiệu thử SQL injection', 'technique': 'unmapped',
     'meaning': 'Có chữ ký hoặc bằng chứng HTTP chứa mẫu SQLi. HTTP 200/302 không chứng minh khai thác thành công; chưa đủ bối cảnh để gán technique khai thác.',
     'requirement': 'Đọc request, rule, log ứng dụng và database; kiểm tra thay đổi dữ liệu hoặc lỗi truy vấn có liên quan.'},
]
FOLLOW_UP = [
    {'after':'observed_eicar_transfer','label':'Giả thuyết: thử thực thi file hoặc tiếp tục thao tác trên host',
     'detail':'Đây là hướng điều tra, chưa quan sát. Cần process/audit telemetry và liên kết đúng file/hash/phiên. Bài tập chỉ chuyển EICAR, không thực thi; kết quả VT không chứng minh infection, persistence, C2 hoặc leo thang.'},
    {'after':'observed_auth_failures','label':'Giả thuyết: thử tiếp, ngừng thử hoặc kết nối bị chặn',
     'detail':'Đối chiếu auth server và SSH policy; chỉ nâng thành password guessing khi đủ ngưỡng trong cửa sổ. Reset không phải auth failure.'},
    {'after':'http_request_pressure','label':'Giả thuyết: ảnh hưởng khả dụng nếu tải tiếp tục tăng',
     'detail':'Theo dõi 5xx, latency, service health và tài nguyên so với baseline. Rate cao chưa đủ tạo nhãn DoS.'},
    {'after':'possible_http_dos','label':'Giả thuyết: tiếp tục suy giảm dịch vụ hoặc phục hồi',
     'detail':'Đối chiếu health checks và tài nguyên. Tìm nguyên nhân khác như lỗi ứng dụng; không tự gán DDoS từ một nguồn.'},
    {'after': 'possible_recon', 'label': 'Giả thuyết: thử thông tin đăng nhập hoặc dò lỗ hổng dịch vụ',
     'detail': 'Theo dõi password failures (T1110.001) và request khai thác. Cần log server đủ ngưỡng hoặc bằng chứng ứng dụng; một port scan không xác nhận các hành vi này.'},
    {'after': 'repeated_auth_failures', 'label': 'Giả thuyết: tiếp tục thử mật khẩu hoặc đăng nhập thành công',
     'detail': 'Theo dõi auth success cùng nguồn/host/tài khoản (ứng viên T1078). Kiểm tra SSH reset/lockout nếu luồng thử bị ngắt; không suy ra success từ việc không còn failures.'},
    {'after': 'auth_success_after_failures', 'label': 'Giả thuyết: thực thi lệnh / khám phá host sau đăng nhập',
     'detail': 'Cần process telemetry hoặc probe cùng phiên SSH để ghi nhận shell (T1059.004). Log Accepted password tự nó không cho biết đã chạy lệnh gì.'},
    {'after': 'observed_shell_execution', 'label': 'Giả thuyết: tải file hoặc tiếp tục khám phá host',
     'detail': 'Theo dõi process, file và kết nối mạng. Bước transfer chỉ được ghi nhận khi có bytes/hash và liên kết đúng phiên (ứng viên T1105).'},
    {'after': 'observed_file_transfer', 'label': 'Giả thuyết ngoài bài tập: thực thi file, persistence hoặc liên lạc ra ngoài',
     'detail': 'Hiện chưa có bằng chứng cho các hành vi đó. Cần process tree, audit/file changes và network telemetry; bài tập dùng file văn bản vô hại. HTTP GET không đủ để gán T1071/C2.'},
    {'after': 'possible_web_sqli', 'label': 'Giả thuyết: tác động lên database hoặc ứng dụng',
     'detail': 'Cần database audit/application logs, truy vấn và kết quả tương ứng. Dấu hiệu SQLi hoặc HTTP 302 chỉ xác nhận request được quan sát, không xác nhận dữ liệu đã bị truy cập.'},
]


def link_template():
    # UrlFormat prepends the current origin/basePath/app for relative URLs.
    # Encode the KQL/Rison wrapper; the formatter encodes the value separately.
    state = '(query:(language:kuery,query:\'data.chain_id: "CHAIN_PLACEHOLDER"\'))'
    encoded = quote(state, safe='').replace('CHAIN_PLACEHOLDER', '{{value}}')
    return 'dashboards#/view/'+PROFILE_ID+'?_a='+encoded


def formula(name, expr):
    return {'type': 'formula', 'as': name, 'expr': expr}


def spec(sort):
    # All values remain plain text. No HTML injection or external data sources.
    latest = {'top_hits': {'size': 1, 'sort': sort, '_source': ['data', 'timestamp', 'rule.id']}}
    sessions = {'terms': {'field': 'data.session_id', 'size': 10, 'missing': '__legacy__'},
                'aggs': {'latest': latest}}
    chains = {'terms': {'field': 'data.chain_id', 'size': 100}, 'aggs': {'sessions': sessions}}
    cases = {'filter': {'bool': {'filter': [
        {'term': {'data.soc_ai_producer': 'soc-ai-live'}},
        {'term': {'data.soc_ai_kind': 'correlation'}}, {'exists': {'field': 'data.chain_id'}}]}},
        'aggs': {'chains': chains}}
    data = [{'name': 'records', 'url': {
        '%context%': True, '%timefield%': 'timestamp', 'index': 'wazuh-alerts-*',
        'body': {'size': 0, 'aggs': {'cases': cases}}},
        'format': {'property': 'aggregations.cases.chains.buckets'},
        'transform': [{'type': 'flatten', 'fields': ['sessions.buckets'], 'as': ['session']},
                      formula('d', 'datum.session.latest.hits.hits[0]._source.data')]},
        {'name': 'selected', 'source': 'records', 'transform': [
            {'type': 'filter', 'expr': "length(data('records')) == 1"}]},
        {'name': 'steps', 'values': STEPS},
        {'name': 'stageRows', 'source': 'selected', 'transform': [
            formula('keys', r"split(datum.d.attack_chain || datum.d.stages || '', ' -> ')"),
            formula('details', r"split(datum.d.chain_stage_details || '', '\n')"),
            {'type': 'flatten', 'fields': ['keys', 'details'], 'as': ['key', 'detail']},
            {'type': 'window', 'ops': ['row_number'], 'as': ['number']},
            {'type': 'lookup', 'from': 'steps', 'key': 'key', 'fields': ['key'],
             'values': ['label', 'technique', 'meaning', 'requirement'],
             'as': ['label', 'technique', 'meaning', 'requirement'], 'default': 'Chưa có diễn giải'},
            formula('order', '100+datum.number'),
            formula('heading', r"'BƯỚC '+datum.number+' — '+datum.label+' ['+datum.technique+'] — ĐÃ QUAN SÁT'"),
            formula('body', r"'Bằng chứng gốc: '+(datum.detail || 'Revision này thiếu chi tiết; đọc evidence_file.')+'\nÝ nghĩa: '+datum.meaning+'\nCần đối chiếu: '+datum.requirement")]},
        {'name': 'followup', 'values': FOLLOW_UP},
        {'name': 'nextRows', 'source': 'selected', 'transform': [
            formula('keys', r"split(datum.d.attack_chain || datum.d.stages || '', ' -> ')"),
            formula('last', 'peek(datum.keys)'),
            {'type': 'lookup', 'from': 'followup', 'key': 'after', 'fields': ['last'],
             'values': ['label', 'detail'], 'as': ['label', 'detail'], 'default': 'Cần điều tra thêm'},
            formula('order', '200'), formula('heading', r"'BƯỚC TIẾP THEO CÓ THỂ XẢY RA — CHƯA QUAN SÁT'"),
            formula('body', r"datum.label+'\n'+datum.detail+'\nĐây là gợi ý điều tra theo bằng chứng hiện có, không phải dự báo của mô hình hoặc một chuỗi bắt buộc. Không cộng vào stage count hay risk score.'")]},
        {'name': 'overview', 'source': 'selected', 'transform': [
            formula('order', '1'), formula('heading', r"'HỒ SƠ '+datum.d.chain_id"),
            formula('body', r"'Session ID: '+datum.d.session_id+'\nSource IP: '+datum.d.source_ip+' → Target IP: '+datum.d.target_ip+' | Target host: '+datum.d.target_host+' | Account: '+(datum.d.username || 'Chưa xác định')+'\nCase status: '+datum.d.case_status+' | Stage count: '+datum.d.attack_chain_stage_count+' | Evidence events (unique): '+(datum.d.chain_evidence_count || 'Chưa có')+'\nFirst observed (UTC): '+(datum.d.chain_started_at || 'Chưa có')+'\nLast observed (UTC): '+(datum.d.chain_last_seen_at || datum.d.event_time)+' | Duration (seconds): '+(datum.d.chain_duration_seconds || '0')+'\nChuỗi đã quan sát: '+join(pluck(data('stageRows'), 'label'), ' → ')")]},
        {'name': 'risk', 'source': 'selected', 'transform': [
            formula('order', '2'), formula('heading', r"'ĐIỂM VÀ PHẠM VI KẾT LUẬN'"),
            formula('body', r"'Risk level: '+datum.d.risk_level+' | Risk score: '+datum.d.risk_score+'/100 = min(95, Base score '+datum.d.risk_score_base+' + Preceding scan bonus '+datum.d.risk_score_recon_bonus+')'+'\nPolicy: '+datum.d.risk_policy+' — mức ưu tiên điều tra theo chính sách Lab A, không phải xác suất tấn công hay điểm do MITRE quy định.'+'\nChuỗi dưới đây sắp theo bằng chứng/thời gian; quan hệ nhân quả và việc chiếm quyền vẫn chưa được xác nhận. ATT&CK IDs là ứng viên, không phải kết luận độc hại.'")]},
        {'name': 'reason', 'source': 'selected', 'transform': [
            formula('order', '3'), formula('heading', r"'LÝ DO GHÉP CHUỖI — NỘI DUNG GỐC TỪ ENGINE'"),
            formula('body', r"(datum.d.activity || 'Revision này chưa có diễn giải của engine; mở evidence_file.')+'\nCác bước được ghép theo IP, host, tài khoản, thời gian và (với probe) cùng phiên SSH/token. Đọc từng stage bên dưới để kiểm tra điều kiện thực tế.'")]},
        {'name': 'coverage', 'source': 'selected', 'transform': [
            formula('order', '210'), formula('heading', r"'ĐỘ BAO PHỦ VÀ DỮ LIỆU CÒN THIẾU'"),
            formula('body', r"'Endpoint evidence scope: '+(datum.d.endpoint_evidence_scope || 'Chưa có thông tin')+'\n'+(indexof(datum.d.attack_chain || '', 'auth_success_after_failures')<0 ? 'Chưa có bước auth success trong case này; không suy ra đã đăng nhập. Đối chiếu auth.log/119208 và operator.json để biết failures chưa đủ ngưỡng hoặc kịch bản bị dừng.\n' : '')+'Chỉ hiển thị các stage đã được engine ghép; log rời chưa đạt điều kiện không tự thành stage. Không có stage không chứng minh hành vi không xảy ra. Thông số này không xác nhận sensor thu đủ packet/log.'+'\nNếu dùng probe: chỉ ghi hai hành động cố định của bài lab, không phải audit tổng quát/chống sửa log. Không xác nhận C2 hoặc toàn bộ kill chain.'")]},
        {'name': 'evidence', 'source': 'selected', 'transform': [
            formula('order', '220'), formula('heading', r"'TRUY VẾT BẰNG CHỨNG VÀ CÁCH KIỂM TRA'"),
            formula('body', r"'Evidence file (trên máy chạy Live): '+datum.d.evidence_file+'\nEvidence IDs (mẫu, không phải toàn bộ): '+toString(datum.d.evidence_ids || [])+'\nMở correlation-cases.json để xem đầy đủ stage/evidence_ids/source_refs. Kiểm tra raw auth, Suricata, endpoint-probe và operator.json theo Session ID; event trên Wazuh là bản tóm tắt.'+'\n'+(toString(datum.d.graph_evidence_ids_omitted)=='true' ? 'Graph gửi Wazuh đã bỏ evidence IDs trong node để giữ giới hạn message; file case local giữ các liên kết đầy đủ.\n' : '')+'Trong panel bản ghi bên dưới, mở mũi tên trái để đọc toàn bộ field ở Table/JSON, gồm data.attack_chain_json, data.activity và data.chain_stage_details.'")]},
        {'name': 'rows', 'source': ['overview', 'risk', 'reason', 'stageRows', 'nextRows', 'coverage', 'evidence'],
         'transform': [
             # Wrap even unbroken URLs, IDs and paths. Keep every character.
             formula('wrappedHeading', r"trim(replace(replace(datum.heading, regexp('.{1,'+columns+'}(?=\\s|$)|.{1,'+columns+'}', 'g'), '$&\n'), regexp('\n{2,}', 'g'), '\n'))"),
             formula('wrapped', r"trim(replace(replace(datum.body, regexp('.{1,'+columns+'}(?=\\s|$)|.{1,'+columns+'}', 'g'), '$&\n'), regexp('\n{2,}', 'g'), '\n'))"),
             formula('headingLines', r"length(split(datum.wrappedHeading, '\n'))"),
             formula('lines', r"length(split(datum.wrapped, '\n'))"),
             formula('rowHeight', '(datum.headingLines+datum.lines)*21+38'),
             {'type': 'collect', 'sort': {'field': 'order'}},
             {'type': 'window', 'sort': {'field': 'order'}, 'ops': ['sum'],
              'fields': ['rowHeight'], 'as': ['bottom'], 'frame': [None, 0]},
             formula('top', 'datum.bottom-datum.rowHeight')]},
        {'name': 'drawRows', 'source': 'rows', 'transform': [
            formula('scrollable', 'contentHeight>height-40')]}]
    return {'$schema': 'https://vega.github.io/schema/vega/v5.json', 'padding': 12,
        'autosize': {'type': 'fit', 'contains': 'padding'},
        'config': {'kibana': {'renderer': 'svg'}, 'text': {'font': 'Arial'}},
        'signals': [{'name': 'columns', 'update': 'max(20,floor((width-48)/9.5))'},
                    {'name': 'contentHeight', 'update': "length(data('rows')) ? peek(data('rows')).bottom+20 : 150"},
                    {'name': 'scrollY', 'value': 0, 'on': [
                        {'events': {'type': 'wheel', 'consume': True,
                                    'filter': ['event.item && event.item.datum && event.item.datum.scrollable']},
                         'update': 'clamp(scrollY+event.deltaY,0,max(0,contentHeight-height+40))'},
                        {'events': '@scrollDown:click', 'update': 'clamp(scrollY+400,0,max(0,contentHeight-height+40))'},
                        {'events': '@scrollUp:click', 'update': 'max(0,scrollY-400)'},
                        {'events': {'signal': 'contentHeight'},
                         'update': 'clamp(scrollY,0,max(0,contentHeight-height+40))'},
                        {'events': {'signal': 'height'},
                         'update': 'clamp(scrollY,0,max(0,contentHeight-height+40))'}]}],
        'data': data,
        'marks': [
            {'type': 'rect', 'zindex': 5, 'encode': {'update': {'x': {'value': 0},
                'y': {'value': 0}, 'width': {'signal': 'width'}, 'height': {'value': 40},
                'fill': {'value': 'white'}}}},
            {'type': 'text', 'zindex': 10, 'encode': {'update': {'x': {'value': 8}, 'y': {'value': 20},
                'fontSize': {'value': 13}, 'fill': {'value': '#24516b'},
                'text': {'signal': "contentHeight>height-40 ? 'Cuộn chuột trong hồ sơ hoặc bấm ▲ / ▼ để xem tiếp.' : 'Bằng chứng đã quan sát và hướng điều tra tiếp'"}}}},
            *[{'name': name, 'type': 'text', 'zindex': 10, 'encode': {'update': {
                'x': {'signal': 'width-'+str(x)}, 'y': {'value': 20}, 'text': {'value': label},
                'fontSize': {'value': 20}, 'cursor': {'value': 'pointer'},
                'fill': {'value': '#006bb4'}, 'tooltip': {'value': tip}}}}
              for name,x,label,tip in [('scrollUp',65,'▲','Cuộn lên'),('scrollDown',25,'▼','Cuộn xuống')]],
            {'type': 'group', 'clip': True, 'encode': {'update': {
                'x': {'value': 0}, 'y': {'value': 40}, 'width': {'signal': 'width'},
                'height': {'signal': 'height-40'}}}, 'marks': [
            {'type': 'text', 'encode': {'update': {'x': {'value': 12}, 'y': {'value': 35},
                'fontSize': {'value': 16}, 'fill': {'value': '#24516b'},
                'text': {'signal': "length(data('records'))==0 ? 'Chưa có chain trong khoảng thời gian/bộ lọc này. Chọn lại thời gian.' : length(data('records'))>1 ? 'Có nhiều chain/phiên. Lọc data.chain_id và data.session_id để mở đúng hồ sơ.' : ''"}}}},
            {'type': 'rect', 'from': {'data': 'drawRows'}, 'encode': {'update': {
                'x': {'value': 0}, 'y': {'signal': 'datum.top-scrollY'}, 'width': {'signal': 'width'},
                'height': {'field': 'rowHeight'}, 'cornerRadius': {'value': 6},
                'fill': {'signal': "datum.order==200 ? '#fff4d6' : datum.order>=100 && datum.order<200 ? '#edf6fc' : '#f3f5f7'"},
                'stroke': {'value': '#ccd6df'}}}},
            {'type': 'text', 'from': {'data': 'drawRows'}, 'encode': {'update': {
                'x': {'value': 16}, 'y': {'signal': 'datum.top-scrollY+16'}, 'baseline': {'value': 'top'},
                'text': {'field': 'wrappedHeading'}, 'lineBreak': {'value': '\n'},
                'fontWeight': {'value': 'bold'}, 'fontSize': {'value': 15},
                'lineHeight': {'value': 21}, 'fill': {'value': '#173a53'}}}},
            {'type': 'text', 'from': {'data': 'drawRows'}, 'encode': {'update': {
                'x': {'value': 16}, 'y': {'signal': 'datum.top-scrollY+16+datum.headingLines*21'},
                'baseline': {'value': 'top'}, 'text': {'field': 'wrapped'}, 'lineBreak': {'value': '\n'},
                'fontSize': {'value': 14}, 'lineHeight': {'value': 21}, 'fill': {'value': '#172b3a'}}}}]}]}


def profile_objects(sort):
    state = {'title': 'Hồ sơ Chain — diễn biến và hướng điều tra', 'type': 'vega',
             'params': {'spec': json.dumps(spec(sort), ensure_ascii=False)}, 'aggs': []}
    reader = {'type': 'visualization', 'id': READER_ID, 'references': [], 'attributes': {
        'title': state['title'], 'description': 'Bằng chứng đã quan sát và giả thuyết tiếp theo được tách riêng.',
        'version': 1, 'uiStateJSON': '{}', 'visState': json.dumps(state, ensure_ascii=False),
        'kibanaSavedObjectMeta': {'searchSourceJSON': '{"query":{"language":"kuery","query":""},"filter":[]}'}}}
    dashboard = {'type': 'dashboard', 'id': PROFILE_ID, 'references': [
        {'name': 'reader', 'type': 'visualization', 'id': READER_ID},
        {'name': 'evidence', 'type': 'search', 'id': 'soc-ai-chain-investigation-evidence-v1'}],
        'attributes': {'title': 'SOC Lab A - Hồ sơ Chain', 'description': 'Bấm Chain ID từ dashboard Điều tra Chain để mở hồ sơ đầy đủ.',
            'version': 1, 'panelsJSON': json.dumps([
                {'panelIndex': '1', 'panelRefName': 'reader', 'type': 'visualization', 'version': '2.19.3',
                 'embeddableConfig': {}, 'gridData': {'x': 0, 'y': 0, 'w': 48, 'h': 48, 'i': '1'}},
                {'panelIndex': '2', 'panelRefName': 'evidence', 'type': 'search', 'version': '2.19.3',
                 'embeddableConfig': {}, 'gridData': {'x': 0, 'y': 48, 'w': 48, 'h': 15, 'i': '2'}}]),
            'optionsJSON': '{"useMargins":true,"hidePanelTitles":false}',
            'timeRestore': True, 'timeFrom': 'now-30d', 'timeTo': 'now',
            'refreshInterval': {'pause': True, 'value': 5000},
            'kibanaSavedObjectMeta': {'searchSourceJSON': '{"query":{"language":"kuery","query":""},"filter":[]}'}}}
    return [reader, dashboard]
