"""Native Vega DAG: observed parents have arrows; follow-ups are dashed hypotheses."""


def add_graph(view):
    view['signals'] += [
        {'name':'graphHeight','update':"min(430,max(150,(length(data('graphBranches'))+1)*105))"},
        {'name':'graphContentHeight','update':"max(130,(length(data('graphBranches'))+1)*105)"},
        {'name':'graphScroll','value':0,'on':[
            {'events':{'type':'wheel','consume':True,'filter':['event.item && event.item.datum && event.item.datum.graphScrollable']},'update':'clamp(graphScroll+event.deltaY,0,max(0,graphContentHeight-graphHeight))'},
            {'events':'@graphDown:click','update':'clamp(graphScroll+105,0,max(0,graphContentHeight-graphHeight))'},
            {'events':'@graphUp:click','update':'max(0,graphScroll-105)'},
            {'events':{'signal':'graphHeight'},'update':'clamp(graphScroll,0,max(0,graphContentHeight-graphHeight))'}]},
        {'name':'graphColumns','update':"max(3,(length(data('graphDepth')) ? data('graphDepth')[0].maxDepth : 1)+2)"},
        {'name':'graphCell','update':'max(70,(width-30)/graphColumns)'},
        {'name':'graphBox','update':'max(58,graphCell-20)'}]
    view['data'] += [
        {'name':'graphBranches','source':'stageRows','transform':[
            {'type':'filter','expr':"datum.d.branch_id!='recon'"},
            {'type':'formula','as':'branch','expr':'datum.d.branch_id'},
            {'type':'aggregate','groupby':['branch'],'fields':['d.start_time'],'ops':['min'],'as':['first']},
            {'type':'collect','sort':{'field':['first','branch']}},
            {'type':'window','ops':['row_number'],'as':['lane']}]},
        {'name':'graphDepth','source':'stageRows','transform':[
            {'type':'formula','as':'depth','expr':"isValid(datum.d.stage_position) ? toNumber(datum.d.stage_position) : datum.number-1"},
            {'type':'aggregate','fields':['depth'],'ops':['max'],'as':['maxDepth']}]},
        {'name':'graphNodes','source':'stageRows','transform':[
            {'type':'project','fields':['d','label','technique','number']},
            {'type':'lookup','from':'graphBranches','key':'branch','fields':['d.branch_id'],'values':['lane'],'as':['lane'],'default':0},
            {'type':'formula','as':'depth','expr':"isValid(datum.d.stage_position) ? toNumber(datum.d.stage_position) : datum.number-1"},
            {'type':'formula','as':'gx','expr':'10+datum.depth*graphCell'},
            {'type':'formula','as':'gy','expr':"(datum.d.branch_id=='recon' ? max(0,(length(data('graphBranches'))-1)/2) : max(0,datum.lane-1))*105+12"},
            {'type':'formula','as':'parent','expr':"length(datum.d.parent_stage_ids || []) ? datum.d.parent_stage_ids[0] : ''"},
            {'type':'formula','as':'graphScrollable','expr':'graphContentHeight>graphHeight'},
            {'type':'formula','as':'nodeTitle','expr':r"replace(datum.label,regexp('.{1,'+max(8,floor(graphBox/8))+'}(?=\\s|$)|.{1,'+max(8,floor(graphBox/8))+'}', 'g'),'$&\n')"}]},
        {'name':'graphEdges','source':'graphNodes','transform':[
            {'type':'filter','expr':"datum.parent!=''"},
            {'type':'lookup','from':'graphNodes','key':'d.stage_id','fields':['parent'],'values':['gx','gy'],'as':['px','py']},
            {'type':'filter','expr':'isValid(datum.px) && isValid(datum.py)'},
            {'type':'formula','as':'path','expr':"'M'+(datum.px+graphBox)+','+(datum.py+38)+'H'+(datum.gx-10)+'V'+(datum.gy+38)+'H'+datum.gx"}]},
        {'name':'graphFuture','source':'graphNodes','transform':[
            {'type':'project','fields':['d','gx','gy','depth','graphScrollable']},
            {'type':'filter','expr':"toString(datum.d.is_terminal)=='true' && length(data('selected'))==1 && toString(data('selected')[0].d.next_step_ready)=='true'"},
            {'type':'lookup','from':'followup','key':'after','fields':['d.stage_name'],'values':['label','detail'],'as':['label','detail'],'default':'Cần điều tra thêm'},
            {'type':'formula','as':'futureX','expr':'datum.gx+graphCell'},
            {'type':'formula','as':'nodeTitle','expr':r"replace(datum.label,regexp('.{1,'+max(8,floor(graphBox/8))+'}(?=\\s|$)|.{1,'+max(8,floor(graphBox/8))+'}', 'g'),'$&\n')"}]}]
    def text(value,x,y,size=12,**extra):
        return {'type':'text','encode':{'update':{'x':{'value':x},'y':{'value':y},'text':{'value':value},'fontSize':{'value':size},**extra}}}
    marks=[
        {'type':'path','from':{'data':'graphEdges'},'encode':{'update':{
            'path':{'field':'path'},'y':{'signal':'-graphScroll'},'stroke':{'value':'#3077a4'},'strokeWidth':{'value':2},
            'tooltip':{'signal':"datum.d.parent_relation=='same_source_target_time_hypothesis' ? 'Cùng nguồn/đích/episode — liên quan theo thời gian, chưa chứng minh nhân quả' : 'Thứ tự đã quan sát trong cùng nhánh'"}}}},
        {'type':'symbol','from':{'data':'graphEdges'},'encode':{'update':{
            'x':{'field':'gx'},'y':{'signal':'datum.gy+38-graphScroll'},'shape':{'value':'triangle-right'},'size':{'value':70},'fill':{'value':'#3077a4'}}}},
        {'type':'rect','from':{'data':'graphNodes'},'encode':{'update':{
            'x':{'field':'gx'},'y':{'signal':'datum.gy-graphScroll'},'width':{'signal':'graphBox'},'height':{'value':78},'cornerRadius':{'value':6},
            'fill':{'value':'#e9f4ff'},'stroke':{'value':'#3077a4'},'tooltip':{'signal':"datum.d.stage_id+' | '+datum.d.branch_id+' | '+datum.d.stage_details"}}}},
        {'type':'text','from':{'data':'graphNodes'},'encode':{'update':{
            'x':{'signal':'datum.gx+7'},'y':{'signal':'datum.gy+9-graphScroll'},'baseline':{'value':'top'},'fontSize':{'value':11},'fontWeight':{'value':'bold'},'fill':{'value':'#173a53'},
            'text':{'field':'nodeTitle'},'lineBreak':{'value':'\n'},'lineHeight':{'value':13},'limit':{'signal':'graphBox-12'},
            'tooltip':{'signal':"datum.label+' ['+datum.technique+'] | '+datum.d.start_time+' → '+datum.d.end_time"}}}},
        {'type':'text','from':{'data':'graphNodes'},'encode':{'update':{
            'x':{'signal':'datum.gx+7'},'y':{'signal':'datum.gy+70-graphScroll'},'fontSize':{'value':9},'fill':{'value':'#35566b'},
            'text':{'signal':"datum.d.stage_name=='observed_reverse_shell' ? 'PID '+datum.d.pid+' · UID '+datum.d.effective_uid+' → '+datum.d.peer_ip+':'+datum.d.peer_port : datum.d.stage_name=='syn_connection_pressure' ? datum.d.syn_connection_count+' SYN flows/'+datum.d.window_seconds+'s · TCP/'+datum.d.target_port : datum.d.stage_name=='http_request_pressure' || datum.d.stage_name=='possible_http_dos' ? datum.d.request_count+' req/'+datum.d.window_seconds+'s · p95='+round(toNumber(datum.d.burst_p95_us)/1000)+'ms · 5xx='+datum.d.server_5xx_count : datum.d.stage_name=='observed_eicar_transfer' ? (datum.d.vt_status=='detected_test_file' ? 'EICAR · VT: '+datum.d.vt_positives+' detections' : 'EICAR · VT: '+(datum.d.vt_status || 'đang chờ')) : 'ĐÃ QUAN SÁT'"},
            'limit':{'signal':'graphBox-12'},'tooltip':{'signal':"datum.d.stage_details"}}}},
        {'type':'rule','from':{'data':'graphFuture'},'encode':{'update':{
            'x':{'signal':'datum.gx+graphBox'},'x2':{'field':'futureX'},'y':{'signal':'datum.gy+38-graphScroll'},'stroke':{'value':'#b98100'},'strokeDash':{'value':[5,4]},'strokeWidth':{'value':2}}}},
        {'type':'symbol','from':{'data':'graphFuture'},'encode':{'update':{'x':{'field':'futureX'},'y':{'signal':'datum.gy+38-graphScroll'},'shape':{'value':'triangle-right'},'size':{'value':70},'fill':{'value':'#b98100'}}}},
        {'type':'rect','from':{'data':'graphFuture'},'encode':{'update':{
            'x':{'field':'futureX'},'y':{'signal':'datum.gy-graphScroll'},'width':{'signal':'graphBox'},'height':{'value':78},'cornerRadius':{'value':6},
            'fill':{'value':'#fff4d6'},'stroke':{'value':'#b98100'},'strokeDash':{'value':[5,4]},'tooltip':{'signal':"datum.detail+' | Giả thuyết chưa quan sát, không phải xác suất đã hiệu chỉnh.'"}}}},
        {'type':'text','from':{'data':'graphFuture'},'encode':{'update':{
            'x':{'signal':'datum.futureX+7'},'y':{'signal':'datum.gy+9-graphScroll'},'baseline':{'value':'top'},'fontSize':{'value':10},'text':{'field':'nodeTitle'},'lineBreak':{'value':'\n'},'lineHeight':{'value':12},'limit':{'signal':'graphBox-12'},'fill':{'value':'#785700'},'tooltip':{'field':'detail'}}}},
        {'type':'text','from':{'data':'graphFuture'},'encode':{'update':{
            'x':{'signal':'datum.futureX+7'},'y':{'signal':'datum.gy+70-graphScroll'},'fontSize':{'value':9},'text':{'value':'CHƯA QUAN SÁT'},'fill':{'value':'#785700'}}}}
    ]
    view['marks'] += [text('SƠ ĐỒ CHAIN — xanh: đã quan sát; vàng nét đứt: giả thuyết tiếp theo',8,350,13,fontWeight={'value':'bold'}),
        {'type':'text','encode':{'update':{'x':{'value':8},'y':{'value':371},'fontSize':{'value':11},'fill':{'value':'#35566b'},'text':{'signal':"length(data('selected'))!=1 ? 'Chọn một Chain ID để xem sơ đồ.' : 'Status: '+(data('selected')[0].d.chain_status || 'legacy')+' | Không có hoạt động '+(data('selected')[0].d.chain_idle_seconds || '?')+' giây → tạm lắng, chưa chứng minh tấn công kết thúc.'"}}}},
        {'name':'graphUp','type':'text','encode':{'update':{'x':{'signal':'width-65'},'y':{'value':371},'text':{'value':'▲'},'cursor':{'value':'pointer'}}}},
        {'name':'graphDown','type':'text','encode':{'update':{'x':{'signal':'width-25'},'y':{'value':371},'text':{'value':'▼'},'cursor':{'value':'pointer'}}}},
        {'type':'group','clip':True,'encode':{'update':{'x':{'value':0},'y':{'value':385},'width':{'signal':'width'},'height':{'signal':'graphHeight'}}},'marks':marks}]
    return view
