"""HTTP evidence normalizer. SQL syntax indicators are not an ML label.

Preserve the raw request target. Decode query percent encoding at most twice;
never HTML-unescape an actual server log. TSV is emitted by SOC Web Lab v0.1.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import re
from urllib.parse import unquote_plus

UNION = re.compile(r'\bunion(?:\s|/\*[^*]{0,200}\*/)+(?:all\s+|distinct\s+)?select\b', re.I)
TAUTOLOGY = re.compile(r"['\"]\s*(?:or|and)\s+(?:\(?\s*)?(?:'([0-9]{1,8})'\s*=\s*'\1'|([0-9]{1,8})\s*=\s*\2)(?:\b|\s|\)|;|--|#)", re.I)
COMBINED = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^]]+)\]\s+"((?:\\.|[^"\\])*)"\s+(\d{3})\s+(\d+|-)')
MONTHS = {name:i for i,name in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'),1)}


def stamp(value): return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')


def epoch_micro(value):
    if not re.fullmatch(r'[0-9]{1,18}', value): raise ValueError('Invalid HTTP epoch microseconds')
    sec, micro = divmod(int(value), 1000000)
    return datetime.fromtimestamp(sec, timezone.utc).replace(microsecond=micro)


def apache_unescape(value):
    replacements = {'n':'\n','r':'\r','t':'\t','b':'\b','f':'\f','v':'\v','\\':'\\','"':'"'}
    def one(match):
        token = match.group()[1:]
        return chr(int(token[1:],16)) if token.startswith('x') else replacements.get(token, '\\'+token)
    return re.sub(r'\\x[0-9a-fA-F]{2}|\\.', one, value)


def integer(value, minimum, maximum, field):
    if not value.isdigit() or not minimum <= int(value) <= maximum:
        raise ValueError('Invalid HTTP '+field)
    return int(value)


def normalize_http_status(value):
    """Canonical HTTP status for native EVE and Wazuh-decoded views.

    Missing status stays unknown. Numeric strings are common in Wazuh, but
    booleans, floats and malformed values must not become invented statuses.
    """
    if value is None:
        return None
    if isinstance(value,str) and re.fullmatch(r'[0-9]{3}',value):
        value=int(value)
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError('Invalid HTTP status')
    return value


def analyze_target(target):
    if len(target) > 65536: raise ValueError('HTTP request target too long')
    query = target.partition('?')[2]
    views = [query]
    for _ in range(2):
        decoded = unquote_plus(views[-1], errors='replace')
        if decoded == views[-1]: break
        views.append(decoded)
    indicators = []
    if any(UNION.search(v) for v in views): indicators.append('sql_union_select')
    if any(TAUTOLOGY.search(v) for v in views): indicators.append('sql_quoted_tautology')
    return {'request_target':target, 'url_path':target.partition('?')[0],
            'decoded_query':views[-1], 'url_decode_passes':len(views)-1,
            'sql_indicators':indicators}


def apache_tsv(raw):
    text = raw.decode('utf-8-sig').rstrip('\r\n')
    fields = text.split('\t')
    if len(fields) != 12: raise ValueError('Expected 12 tab-separated Apache fields; inspect LogFormat')
    begin, end, src, sport, dst, dport, method, target, status, size, elapsed, agent = fields
    start, finish = epoch_micro(begin), epoch_micro(end)
    if finish < start: raise ValueError('HTTP end precedes start')
    target = apache_unescape(target)
    if not re.fullmatch(r'[A-Z][A-Z0-9_-]{0,31}', method): raise ValueError('Invalid HTTP method')
    return {'schema_version':'soc-http-event/0.1', 'record_id':'http:'+hashlib.sha256(raw).hexdigest(),
        'event_time':stamp(start), 'available_time':stamp(finish), 'evidence_provider':'apache_tsv',
        'source_ip':str(ipaddress.ip_address(src)), 'source_port':integer(sport,0,65535,'source port'),
        'target_ip':str(ipaddress.ip_address(dst)), 'destination_port':integer(dport,1,65535,'target port'),
        'http_method':method, 'http_status':integer(status,100,599,'status'),
        'response_body_bytes':integer(size,0,10**15,'response bytes'),
        'duration_us':integer(elapsed,0,10**15,'duration'),
        'user_agent':apache_unescape(agent), **analyze_target(target)}


def apache_combined(raw, host, target_ip=None):
    text = raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw
    match = COMBINED.match(text.strip())
    if not match: return None
    src, date, request, status, size = match.groups()
    parts = re.fullmatch(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})',date)
    if not parts: raise ValueError('Invalid Apache timezone timestamp')
    day, mon, year, hour, minute, second, sign, zh, zm = parts.groups()
    if mon not in MONTHS: raise ValueError('Invalid Apache month')
    offset = timedelta(hours=int(zh),minutes=int(zm))*(1 if sign=='+' else -1)
    t = datetime(int(year),MONTHS[mon],int(day),int(hour),int(minute),int(second),tzinfo=timezone(offset))
    req = re.fullmatch(r'(\S+) (.*?) HTTP/\S+', apache_unescape(request))
    if not req: raise ValueError('Unsupported Apache request line')
    method, target = req.groups()
    return {'schema_version':'soc-http-event/0.1', 'record_id':'http:'+hashlib.sha256(text.encode()).hexdigest(),
        'event_time':stamp(t), 'available_time':None, 'evidence_provider':'wazuh_apache',
        'target_host':host, 'source_ip':str(ipaddress.ip_address(src)), 'source_port':None,
        'target_ip':target_ip, 'destination_port':None, 'http_method':method,
        'http_status':normalize_http_status(status), 'response_body_bytes':int(size) if size!='-' else None,
        'duration_us':None, **analyze_target(target)}


def sql_evidence(event):
    if not event['sql_indicators']: return None
    # Request-level views remain distinct from sensor alerts; cases do not claim
    # that their total evidence count is the number of unique HTTP requests.
    return {k:v for k,v in event.items() if k not in ('schema_version','record_id','user_agent')} | {
        'kind':'web.sqli_indicator', 'http_record_id':event['record_id'],
        'success_proven':False}


def build_web_cases(events, config, digest):
    from collections import Counter, defaultdict
    from lab_correlation import instant
    groups = defaultdict(list)
    scans = [e for e in events if e['kind']=='network.possible_recon']
    for e in events:
        if e['kind']=='web.sqli_indicator':
            bucket = int(instant(e['event_time']).timestamp())//300
            groups[(e['target_host'],e['source_ip'],bucket)].append(e)
    result = []
    for (host, src, bucket), timeline in groups.items():
        clusters = [sorted(timeline,key=lambda e:(e['event_time'],e['event_id']))]
        for cluster in clusters:
            first, last = cluster[0], cluster[-1]
            earlier = sorted([e for e in scans if e['target_host']==host and e['source_ip']==src
                and 0<(instant(first['event_time'])-instant(e['event_time'])).total_seconds()<=config['recon_window_seconds']],key=lambda e:e['event_time'])
            stages = []
            if earlier:
                stages.append({'name':'possible_recon','start_time':earlier[0]['event_time'],
                    'end_time':earlier[-1]['event_time'],'evidence_ids':[e['event_id'] for e in earlier]})
            stages.append({'name':'possible_web_sqli','start_time':first['event_time'],
                'end_time':last['event_time'],'evidence_ids':[e['event_id'] for e in cluster],
                'evidence_count':len(cluster),'success_proven':False})
            # Also support replay of older normalized records containing strings.
            # Counts describe evidence views, not unique HTTP requests.
            statuses=Counter(normalize_http_status(e.get('http_status')) for e in cluster)
            statuses.pop(None,None)
            result.append({'schema_version':'soc-correlation-case/0.1',
                'case_id':'case:'+digest(['web',host,src,bucket]),
                'target_host':host,'target_ip':first['target_ip'],'source_ip':src,'username':None,
                'status':'possible_web_sqli','first_seen':stages[0]['start_time'],'last_seen':last['event_time'],
                'stages':stages,'confirmed_compromise':False,'training_label':None,
                'http_status_counts':{str(code):statuses[code] for code in sorted(statuses)},
                'evidence_providers':sorted({e.get('evidence_provider','unknown') for e in cluster}),
                'sample_request_target':next((e.get('request_target') for e in cluster if e.get('request_target')),None),
                'explanation':'HTTP SQL syntax indicators observed. Rule/heuristic evidence, not an MLP SQLi prediction; exploitation success is not proven.'})
    return result
