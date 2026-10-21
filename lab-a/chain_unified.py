"""One native dashboard: active chain list, scoped branch reader and revisions."""
import argparse
import copy
import json
from urllib.parse import quote
from pathlib import Path
from chain_dashboard import encoded, latest_source_sort
from chain_profile import spec as reader_spec

DASHBOARD_ID='soc-ai-attack-chain-unified-v2'
INDEX_ID='soc-ai-attack-chain-index-v2'
READER_ID='soc-ai-attack-chain-reader-v2'
POLICY_ID='soc-ai-attack-chain-guide-v2'
SEARCH_ID='soc-ai-attack-chain-evidence-v2'
QUERY='data.soc_ai_producer: "soc-ai-live" and data.soc_ai_kind: ("attack_chain" or "chain_stage")'
# Select latest per chain/session first, then apply retention. Numeric conversion
# is intentional: Wazuh stores dynamic numeric fields as keyword strings too.
VISIBLE_EXPR=("toString(datum.d.chain_active)!='false' && ("
              "toNumber(datum.d.attack_chain_stage_count)>=2 || ("
              "toNumber(datum.d.attack_chain_stage_count)==1 && "
              "isValid(toDate(datum.d.chain_last_seen_at || datum.d.event_time)) && "
              "visibilityNow-toNumber(toDate(datum.d.chain_last_seen_at || datum.d.event_time))"
              "<1000*toNumber(datum.d.chain_idle_seconds || 90)))")
# History stores revisions of formed chains only. Excluding exact zero/one
# works with keyword counts ('10' must not compare lexically below '2').
HISTORY_QUERY=QUERY+' and data.attack_chain_stage_count: * and not data.attack_chain_stage_count: ("0" or "1")'


def visibility_clock():
    # Expire old/stopped-session singletons even if no new event arrives and
    # dashboard auto refresh is paused. No browser deletion or index mutation.
    return {'name':'visibilityNow','init':'now()',
            'on':[{'events':{'type':'timer','throttle':1000},'update':'now()'}]}



def reader():
    v=copy.deepcopy(reader_spec(latest_source_sort()))
    data={d['name']:d for d in v['data']}
    v['signals'].append(visibility_clock())
    data['records']['transform'].append({'type':'filter','expr':VISIBLE_EXPR})
    cases=data['records']['url']['body']['aggs']['cases']
    cases['filter']['bool']['filter'][1]['term']['data.soc_ai_kind']='attack_chain'
    # Last revision must be selected BEFORE applying active state. Otherwise an
    # old active revision would resurrect a superseded standalone case.
    data['selected']['transform'].append({'type':'filter','expr':"toString(datum.d.chain_active)!='false'"})
    stages={'name':'stageDocuments','url':{'index':'wazuh-alerts-*','body':{
        'size':1000,'sort':[{'timestamp':{'order':'desc','unmapped_type':'date'}}],
        '_source':['data','timestamp'], 'query':{'bool':{
            'must':['%dashboard_context-must_clause%'], 'must_not':['%dashboard_context-must_not_clause%'],
            'filter':['%dashboard_context-filter_clause%',{'range':{'timestamp':{'%timefilter%':True}}},
                {'term':{'data.soc_ai_producer':'soc-ai-live'}},{'term':{'data.soc_ai_kind':'chain_stage'}}]}}}},
        'format':{'property':'hits.hits'},'transform':[{'type':'formula','as':'d','expr':'datum._source.data'}]}
    v['data'].insert(2,stages)
    transforms=data['stageRows']['transform']
    lookup=next(t for t in transforms if t['type']=='lookup')
    data['stageRows'].update(source='stageDocuments',transform=[
        {'type':'filter','expr':"length(data('selected'))==1 && datum.d.chain_id==data('selected')[0].d.chain_id && datum.d.session_id==data('selected')[0].d.session_id && datum.d.chain_revision_id==data('selected')[0].d.chain_revision_id"},
        {'type':'window','groupby':['d.stage_id'],'ops':['row_number'],'as':['duplicateRank']},
        {'type':'filter','expr':'datum.duplicateRank==1'},
        {'type':'formula','as':'key','expr':'datum.d.stage_name'},
        {'type':'collect','sort':{'field':['d.start_time','d.stage_id'],'order':['ascending','ascending']}},
        {'type':'window','ops':['row_number'],'as':['number']},lookup,
        {'type':'formula','as':'order','expr':'1000+datum.number'},
        {'type':'formula','as':'heading','expr':"'BƯỚC '+datum.number+' — '+datum.label+' ['+datum.technique+'] — ĐÃ QUAN SÁT'"},
        {'type':'formula','as':'body','expr':r"'Stage ID: '+datum.d.stage_id+' | Branch ID: '+datum.d.branch_id+'\nCategory: '+datum.d.stage_category+' | Account: '+(datum.d.username || 'Chưa xác định')+'\nParent stage IDs: '+toString(datum.d.parent_stage_ids || [])+'\nBằng chứng: '+datum.d.stage_details+'\nÝ nghĩa: '+datum.meaning+'\nCần đối chiếu: '+datum.requirement+'\nEvidence IDs (mẫu): '+toString(datum.d.evidence_ids || [])"}])
    next_lookup=next(t for t in data['nextRows']['transform'] if t['type']=='lookup')
    next_lookup['fields']=['key']
    data['nextRows'].update(source='stageRows',transform=[
        {'type':'project','fields':['d','key']},
        {'type':'filter','expr':"toString(datum.d.is_terminal)=='true' && length(data('selected'))==1 && toString(data('selected')[0].d.next_step_ready)=='true'"},next_lookup,
        {'type':'window','ops':['row_number'],'as':['nextNumber']},
        {'type':'formula','as':'order','expr':'2000+datum.nextNumber'},
        {'type':'formula','as':'heading','expr':"'HƯỚNG ĐIỀU TRA TIẾP — NHÁNH '+datum.d.branch_id+' — CHƯA QUAN SÁT'"},
        {'type':'formula','as':'body','expr':r"datum.label+'\n'+datum.detail+'\nĐây là runbook giả thuyết, không phải dự báo của MLP. Không thêm vào stage count/risk score.'"}])
    for t in data['risk']['transform']:
        if t.get('as')=='body':t['expr']=t['expr'].replace("+datum.d.risk_score_recon_bonus+')'", "+datum.d.risk_score_recon_bonus+' + Diversity bonus '+datum.d.risk_score_diversity_bonus+')'")
    for t in data['overview']['transform']:
        if t.get('as')=='body':
            t['expr']=t['expr'].replace('Chuỗi đã quan sát:', 'Timeline các nhánh:').replace("' → '","' | '")
            t['expr']+=r"+'\nCategories: '+datum.d.categories+' | Branch count: '+datum.d.branch_count+' | Accounts: '+(datum.d.accounts || 'Chưa xác định')+'\nRecon observed: '+datum.d.recon_observed"
    data['coverage']['transform'][0]['expr']='3000'
    for t in data['coverage']['transform']:
        if t.get('as')=='body':
            t['expr']=r"'Endpoint evidence scope: '+(datum.d.endpoint_evidence_scope || 'Chưa có thông tin')+'\nChỉ hiển thị bước có bằng chứng đạt điều kiện. Không có stage không chứng minh hành vi không xảy ra; không xác nhận sensor thu đủ mọi packet/log.\nEICAR receiver chỉ ghi thao tác nhận file thử cố định qua SSH, không audit mọi lệnh/SCP. File + VT cần cùng agent, path, hash và FIM alert ID. Kết quả VT đến muộn không tạo bước, không kéo dài episode. Không tự suy ra thực thi, C2, persistence hoặc leo thang. Probe bài lab không chống sửa log.'"
    data['evidence']['transform'][0]['expr']='3010'
    for t in data['evidence']['transform']:
        if t.get('as')=='body':
            t['expr']=r"'Evidence file: '+datum.d.evidence_file+'\nMở mục chains trong correlation-cases.json để đọc đầy đủ stages, branches, parent_stage_ids, evidence_ids và baseline_evidence_ids. Đối chiếu event IDs/source_refs với raw logs. Wazuh giữ mẫu evidence IDs; không thay thế hồ sơ local.\nBảng cuối dashboard cho mở toàn bộ field của summary/stage ở Table/JSON. Đối chiếu cùng chain_revision_id; revision là cập nhật, không phải các cuộc tấn công khác nhau.'"
    for t in data['reason']['transform']:
        if t.get('as')=='body':t['expr']=r"'Các nhánh dùng chung nguồn, đúng IP/host đích và một cửa sổ có giới hạn. Root scan nối tới từng nhánh; thứ tự hiển thị không khẳng định brute force gây ra SQLi/DoS. Auth giữ riêng account/phiên SSH.\n'+datum.d.activity"
    warning={'name':'revisionCoverage','source':'selected','transform':[
        {'type':'formula','as':'order','expr':'4'},
        {'type':'formula','as':'heading','expr':"'ĐỘ ĐẦY ĐỦ CỦA REVISION'"},
        {'type':'formula','as':'body','expr':"'Chain revision: '+datum.d.chain_revision_id+' | Đã nhận '+length(data('stageRows'))+'/'+datum.d.stage_revision_count+' stage documents. '+(length(data('stageRows'))==toNumber(datum.d.stage_revision_count) ? 'Đủ stage của revision đang đọc.' : 'Đang thiếu stage của cùng revision; Refresh sau khi indexer nhận đủ. Không ghép stage cũ để lấp phần thiếu.')"}]}
    v['data'].insert(v['data'].index(data['rows']),warning);data['rows']['source'].append('revisionCoverage')
    def recolor(marks):
        for m in marks:
            if m['type']=='rect' and m.get('from'):
                m['encode']['update']['fill']['signal']="datum.order>=2000 && datum.order<3000 ? '#fff4d6' : datum.order>=1000 && datum.order<2000 ? '#edf6fc' : '#f3f5f7'"
            recolor(m.get('marks',[]))
    recolor(v['marks'])
    for mark in v['marks']:
        for child in mark.get('marks',[]):
            text=child.get('encode',{}).get('update',{}).get('text',{})
            if 'signal' in text and "length(data('records'))==0" in text['signal']:
                text['signal']="length(data('records'))==0 ? 'Chưa có chain trong thời gian/bộ lọc này.' : length(data('records'))>1 ? 'Bấm Chain ID ở danh sách để mở đúng hồ sơ và phiên.' : length(data('selected'))==0 ? 'Ứng viên một bước đã hết thời gian chờ hoặc chain đã được thay thế. Quay lại danh sách tất cả chain.' : ''"
    return v


def listing():
    # Reuse the same guarded aggregation contract as the case reader.
    source=copy.deepcopy(reader()['data'][0]);source['name']='records'
    link_prefix='#/view/'+DASHBOARD_ID+"?_g=(refreshInterval:(pause:!t,value:2000))&_a=(query:(language:kuery,query:'data.chain_id:%20%22"
    link_suffix="%22'))"
    cols=[('Chain ID',0,'chain_id'),('Source IP',.25,'source_ip'),('Target IP',.38,'target_ip'),
          ('Risk score',.51,'risk_score'),('Stage count',.61,'attack_chain_stage_count'),('Categories',.72,'categories')]
    return {'$schema':'https://vega.github.io/schema/vega/v5.json','padding':10,
        'autosize':{'type':'fit','contains':'padding'},'config':{'kibana':{'renderer':'svg'}},
        'signals':[visibility_clock(),{'name':'page','value':0,'on':[
            {'events':'@next:click','update':"min(page+1,max(0,ceil(length(data('active'))/8)-1))"},
            {'events':'@prev:click','update':'max(0,page-1)'},
            {'events':{'signal':'visibilityNow'},'update':"min(page,max(0,ceil(length(data('active'))/8)-1))"}]}],
        'data':[source,{'name':'active','source':'records','transform':[
            {'type':'filter','expr':"toString(datum.d.chain_active)!='false'"},
            {'type':'collect','sort':{'field':'d.event_time','order':'descending'}},
            {'type':'window','ops':['row_number'],'as':['n']}]},
            {'name':'visible','source':'active','transform':[{'type':'filter','expr':'datum.n>page*8 && datum.n<=page*8+8'}]}],
        'marks':[
            *[{'type':'text','encode':{'update':{'x':{'signal':f'width*{x}'},'y':{'value':20},
                'fontWeight':{'value':'bold'},'text':{'value':label},'fontSize':{'value':13}}}} for label,x,f in cols],
            *[{'type':'text','from':{'data':'visible'},'encode':{'update':{
                'x':{'signal':f'width*{x}'},'y':{'signal':'50+(datum.n-page*8-1)*30'},
                'fontSize':{'value':12},'fill':{'value':'#006bb4' if f=='chain_id' else '#172b3a'},
                'text':{'signal':'datum.d.'+f},'limit':{'signal':f'width*{.24 if f=="chain_id" else .12 if f!="categories" else .27}'},
                **({'href':{'signal':json.dumps(link_prefix)+"+datum.d.chain_id+"+json.dumps(link_suffix)},
                    'cursor':{'value':'pointer'}} if f=='chain_id' else {})}}} for label,x,f in cols],
            {'name':'prev','type':'text','encode':{'update':{'x':{'value':10},'y':{'value':308},
                'text':{'value':'◀ Trước'},'cursor':{'value':'pointer'},'fill':{'value':'#006bb4'}}}},
            {'name':'next','type':'text','encode':{'update':{'x':{'value':100},'y':{'value':308},
                'text':{'value':'Sau ▶'},'cursor':{'value':'pointer'},'fill':{'value':'#006bb4'}}}},
            {'type':'text','encode':{'update':{'x':{'value':200},'y':{'value':308},'text':{
                'signal':"'Trang '+(page+1)+' | '+length(data('active'))+' chain/ứng viên đang hiển thị (tối đa 100 ID × 10 phiên; lọc thời gian nếu cần)'"},'fontSize':{'value':11}}}}]}


def workspace():
    v=reader(); table=listing()
    # A single Vega view keeps selection/loading state local to one panel.
    v['signals']+=[s for s in table['signals'] if s['name']!='visibilityNow']+[{'name':'chainClicked','value':None,'on':[{'events':'@chainSelect:click','force':True,'update':"opensearchDashboardsAddFilter({bool:{filter:[{match_phrase:{'data.chain_id':datum.d.chain_id}},{match_phrase:{'data.session_id':datum.d.session_id}}]}}, '"+'wazuh-alerts-*'+"', 'Chain / Session')"}]}]
    v['data']+=table['data'][1:]
    for mark in v['marks']:
        if mark.get('type')=='group':
            mark['encode']['update']['y']['value']=380
            mark['encode']['update']['height']['signal']='height-380'
        else:
            y=mark.get('encode',{}).get('update',{}).get('y',{})
            if 'value' in y:y['value']+=340
    for mark in table['marks']:
        update=mark.get('encode',{}).get('update',{})
        if 'href' in update:
            update.pop('href');mark['name']='chainSelect'
    for mark in v['marks']:
        update=mark.get('encode',{}).get('update',{})
        if mark.get('type')=='group':
            update['y']={'signal':'graphHeight+445'}
            update['height']={'signal':'max(100,height-graphHeight-445)'}
        elif 'y' in update and 'value' in update['y']:
            update['y']={'signal':'graphHeight+'+str(update['y']['value']+65)}
    v['marks']=table['marks']+v['marks']
    for mark in v['marks']:
        update=mark.get('encode',{}).get('update',{})
        for item in update.values():
            if isinstance(item,dict) and isinstance(item.get('signal'),str):
                item['signal']=item['signal'].replace('height-40','height-graphHeight-445').replace('height-380','height-graphHeight-445')
    # The reader's scroll region starts below the chain list.
    for signal in v['signals']:
        if signal['name']=='scrollY':
            for on in signal['on']:on['update']=on['update'].replace('height+40','height+graphHeight+445')
    for data in v['data']:
        if data['name']=='drawRows':data['transform'][0]['expr']='contentHeight>height-graphHeight-445'
    from chain_graph import add_graph
    return add_graph(v)

def objects():
    query={'query':{'language':'kuery','query':HISTORY_QUERY},'filter':[], 'indexRefName':'index'}
    index={'type':'index-pattern','id':INDEX_ID,'references':[],'attributes':{
        'title':'wazuh-alerts-*','timeFieldName':'timestamp','fields':encoded([
            {'name':x,'type':'date' if x=='timestamp' else 'string',
             'esTypes':['date' if x=='timestamp' else 'keyword'],'aggregatable':True,
             'searchable':True,'readFromDocValues':True} for x in ['timestamp','data.chain_id','data.branch_id',
             'data.stage_name','data.chain_revision_id','data.risk_score','data.attack_chain_stage_count','data.session_id','data.soc_ai_kind','data.soc_ai_producer']]),
        'fieldFormatMap':'{}','allowNoIndex':True}}
    def visual(identifier,title,kind,params):
        return {'type':'visualization','id':identifier,'references':[],'attributes':{
            'title':title,'version':1,'uiStateJSON':'{}','visState':encoded({'title':title,'type':kind,'params':params,'aggs':[]}),
            'kibanaSavedObjectMeta':{'searchSourceJSON':encoded({'query':{'language':'kuery','query':''},'filter':[]})}}}
    policy=visual(POLICY_ID,'Cách đọc và điều tra Attack Chain','markdown',{'fontSize':12,'openLinksInNewTab':False,
        'markdown':'**Một dashboard cho attack chain.** Bấm Chain ID để lọc và đọc các nhánh ngay bên dưới; tạm Pause auto refresh khi đọc chi tiết dài. '
        '[Quay lại tất cả chain và bật refresh](#/view/'+DASHBOARD_ID+'?_a='+quote("(filters:!(),query:(language:kuery,query:''))",safe='')+'&_g='+quote('(refreshInterval:(pause:!f,value:2000))',safe='')+')'+
        '\n\n**Điểm:** max điểm hành vi +10 nếu có recon trước +5 nếu có ≥2 nhóm hành vi độc lập; cap 95. Đây là ưu tiên điều tra, không phải xác suất. '
        'EICAR là file thử antivirus: transfer có kiểm chứng = 40; khi VT dương tính liên kết đúng file = base tối thiểu 75 (85 nếu có scan trước). VT là bằng chứng bổ sung, không là bước tấn công mới; không xác nhận infection. '
        '**HTTP:** web flood/áp lực request =45; nghi vấn DoS có baseline khỏe cùng route và suy giảm =75. Đọc request/window, p95,5xx và http_route trong từng bước; High không đồng nghĩa DoS thành công. '
        'HTTP rate cao là pressure; nghi vấn DoS cần baseline tốt rồi mới có suy giảm 5xx/latency. Không ép mọi cuộc tấn công phải có scan đã quan sát. '
        'Bật monitor rồi thao tác trong Kali Bash. Một bước là ứng viên tạm thời; hết ngưỡng idle (mặc định 90 giây, chờ 95 giây để kiểm thử) thì tự ẩn, không xóa log/alert. Chỉ giữ lâu dài chain có ít nhất hai bước đã quan sát. Chain nhiều bước tạm lắng vẫn được giữ và hiện gợi ý nét đứt; đây là runbook, chưa có xác suất dự đoán được kiểm định. Mỗi nhánh có parent stage IDs và bằng chứng; cùng nguồn/đích/thời gian chưa chứng minh cùng ý đồ hay quan hệ nhân quả. '
        'Event thường tiếp tục xem ở Threat Hunting.'})
    detail=visual(READER_ID,'Attack Chain — danh sách, các nhánh và hồ sơ','vega',{'spec':encoded(workspace())})
    search={'type':'search','id':SEARCH_ID,'references':[{'name':'index','type':'index-pattern','id':INDEX_ID}],
        'attributes':{'title':'Lịch sử chain từ hai bước — mở dòng để đọc JSON','version':1,
            'columns':['data.chain_id','data.branch_id','data.stage_name','data.risk_score','data.chain_revision_id'],
            'sort':[['timestamp','desc']], 'kibanaSavedObjectMeta':{'searchSourceJSON':encoded(query)}}}
    panels=[];refs=[];y=0
    for i,(row,height) in enumerate([(policy,6),(detail,64),(search,12)],1):
        ref='panel_'+str(i);refs.append({'name':ref,'type':row['type'],'id':row['id']})
        panels.append({'panelIndex':str(i),'panelRefName':ref,'type':row['type'],'version':'2.19.3',
            'embeddableConfig':{},'gridData':{'x':0,'y':y,'w':48,'h':height,'i':str(i)}});y+=height
    dash={'type':'dashboard','id':DASHBOARD_ID,'references':refs,'attributes':{
        'title':'Attack Chain','description':'Sơ đồ bước → bước, episode riêng, bằng chứng file/VirusTotal và gợi ý điều tra sau khi tạm lắng.',
        'version':1,'panelsJSON':encoded(panels),'optionsJSON':'{"useMargins":true,"hidePanelTitles":false}',
        'timeRestore':True,'timeFrom':'now-24h','timeTo':'now','refreshInterval':{'pause':False,'value':2000},
        'kibanaSavedObjectMeta':{'searchSourceJSON':encoded({'query':{'language':'kuery','query':''},'filter':[]})}}}
    return [index,policy,detail,search,dash]


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=Path(__file__).with_name('dashboards')/'soc-ai-attack-chain-unified.ndjson')
    a=p.parse_args();a.output.write_text(''.join(encoded(r)+'\n' for r in objects()),encoding='utf-8')
    print('UNIFIED_DASHBOARD:',a.output,'(5 objects, ONE dashboard)')
