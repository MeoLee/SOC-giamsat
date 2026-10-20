"""Generate additive OpenSearch Dashboards saved objects for Wazuh chain events.

Uses a dedicated index-pattern ID; does not change mappings, default index,
credentials or existing dashboards. Top Hit metrics show the latest revision
per chain rather than adding or averaging risk scores across revisions.
"""
import argparse
import copy
import json
from pathlib import Path

INDEX_ID = 'soc-ai-chain-alerts-v1'
TABLE_ID = 'soc-ai-attack-chain-detail-v1'
SEARCH_ID = 'soc-ai-chain-history-v1'
POLICY_ID = 'soc-ai-chain-policy-v1'
DASHBOARD_ID = 'soc-ai-attack-chain-dashboard-v1'
QUERY = 'data.soc_ai_producer: "soc-ai-live" and data.soc_ai_kind: "correlation" and data.chain_id: *'
DETAIL_DASHBOARD_ID = 'soc-ai-chain-investigation-dashboard-v1'
CONTEXT_ID = 'soc-ai-chain-investigation-context-v1'
EVIDENCE_ID = 'soc-ai-chain-investigation-evidence-v1'
CONTEXT_COLUMNS = [
    ('data.source_ip', 'Source IP'),
    ('data.target_ip', 'Target IP'),
    ('data.target_host', 'Target host'),
    ('data.username', 'Account'),
    ('data.chain_started_at', 'First observed (source time)'),
    ('data.chain_last_seen_at', 'Last observed (source time)'),
    ('data.chain_duration_seconds', 'Duration (seconds)'),
    ('data.chain_evidence_count', 'Evidence events (unique)'),
    ('data.chain_password_failure_count', 'Password failures'),
    ('data.risk_score_base', 'Base score'),
    ('data.risk_score_recon_bonus', 'Preceding scan bonus'),
]
DETAIL_COLUMNS = ['data.chain_id', 'data.chain_stage_details', 'data.conclusion',
                  'data.evidence_file', 'data.session_id']
COLUMNS = [
    ('data.risk_level', 'Risk level'),
    ('data.risk_score', 'Risk score (0-100)'),
    ('data.techniques', 'Candidate techniques'),
    ('data.attack_type', 'Observed sequence'),
    ('data.conclusion', 'Conclusion'),
    ('data.attack_summary', 'Stage summary'),
    ('timestamp', 'Last update'),
]


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def latest_source_sort():
    """Query old daily indices without requiring a new field mapping there.

    Top Hits does not inherit Discover's default unmapped sort options. An
    exists/query/time filter alone does not prevent sort construction on every
    shard. Declare the absent type in the query instead of editing index data.
    """
    return [{'data.event_time': {'order': 'desc', 'unmapped_type': 'keyword', 'missing': '_last'}},
            {'timestamp': {'order': 'desc', 'unmapped_type': 'date', 'missing': '_last'}}]


def source():
    return {'query': {'language': 'kuery', 'query': QUERY}, 'filter': [],
            'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index'}


def index_reference():
    return [{'name': 'kibanaSavedObjectMeta.searchSourceJSON.index',
             'type': 'index-pattern', 'id': INDEX_ID}]


def objects():
    names = {name for name, _ in COLUMNS} | {
        'data.chain_id', 'data.case_id', 'data.case_status', 'data.session_id',
        'data.soc_ai_producer', 'data.soc_ai_kind', 'data.attack_chain_stage_count',
        'data.source_ip', 'data.target_ip', 'data.target_host', 'data.username',
        'data.risk_score_base', 'data.risk_score_recon_bonus', 'data.risk_policy',
        'data.risk_basis', 'data.confirmed_compromise', 'data.techniques_are_hypotheses',
    }
    fields = [{'name': name, 'type': 'date' if name == 'timestamp' else 'string',
               'esTypes': ['date' if name == 'timestamp' else 'keyword'],
               'aggregatable': True, 'searchable': True, 'readFromDocValues': True}
              for name in sorted(names)]
    fields.append({'name': '_source', 'type': '_source', 'esTypes': ['_source'],
                   'aggregatable': False, 'searchable': False, 'readFromDocValues': False})
    index = {'type': 'index-pattern', 'id': INDEX_ID, 'references': [], 'attributes': {
        'title': 'wazuh-alerts-*', 'timeFieldName': 'timestamp', 'fields': encoded(fields),
        'fieldFormatMap': '{}', 'allowNoIndex': True}}
    aggs = [{'id': '1', 'enabled': True, 'type': 'terms', 'schema': 'bucket',
             'params': {'field': 'data.chain_id', 'orderBy': '_key', 'order': 'asc',
                        'size': 100, 'customLabel': 'Chain ID'}}]
    for i, (field, label) in enumerate(COLUMNS, 2):
        aggs.append({'id': str(i), 'enabled': True, 'type': 'top_hits', 'schema': 'metric',
                     'params': {'field': field, 'aggregate': 'concat', 'size': 1,
                                'sortField': 'timestamp', 'sortOrder': 'desc', 'customLabel': label}})
    table = {'type': 'visualization', 'id': TABLE_ID, 'references': index_reference(),
             'attributes': {'title': 'Attack Chain Detail - latest revision',
                 'description': 'One row per correlation case; every column uses its latest timestamp.',
                 'version': 1, 'uiStateJSON': '{}',
                 'visState': encoded({'title': 'Attack Chain Detail - latest revision', 'type': 'table',
                     'params': {'perPage': 10, 'showPartialRows': False, 'showMetricsAtAllLevels': False,
                                'showTotal': False, 'totalFunc': 'sum', 'percentageCol': ''}, 'aggs': aggs}),
                 'kibanaSavedObjectMeta': {'searchSourceJSON': encoded(source())}}}
    search = {'type': 'search', 'id': SEARCH_ID, 'references': index_reference(),
              'attributes': {'title': 'Attack chain transitions - event history', 'version': 1,
                  'description': 'Individual chain revisions, not distinct attacks or stage counts.',
                  'columns': ['data.chain_id', 'data.case_status', 'data.attack_chain_stage_count',
                              'data.risk_score', 'data.source_ip', 'data.target_ip', 'data.username'],
                  'sort': [['timestamp', 'desc']],
                  'kibanaSavedObjectMeta': {'searchSourceJSON': encoded(source())}}}
    policy = {'type': 'visualization', 'id': POLICY_ID, 'references': [], 'attributes': {
        'title': 'How to read chain risk', 'version': 1, 'uiStateJSON': '{}',
        'visState': encoded({'title': 'How to read chain risk', 'type': 'markdown', 'aggs': [],
            'params': {'markdown': '**Latest revision per chain.** Filter by `data.session_id`, source, target or account. '
                'Risk is an operational priority, not attack probability. '
                '\n\n**Risk policy:** '
                '40: scan; 65: password guessing; 85: login after failures; '
                '+10 with preceding scan (cap 95). Medium 40-69; High 70-100. '
                'ATT&CK IDs are candidates from observed evidence. Compromise remains unconfirmed. '
                'The history below contains updates, not additional attacks.',
                'fontSize': 12, 'openLinksInNewTab': True}}),
        'kibanaSavedObjectMeta': {'searchSourceJSON': encoded({'query': {'language': 'kuery', 'query': ''}, 'filter': []})}}}
    panels = []
    references = []
    for number, kind, identifier, y, height in (
        ('1', 'visualization', POLICY_ID, 0, 5),
        ('2', 'visualization', TABLE_ID, 5, 18),
        ('3', 'search', SEARCH_ID, 23, 12),
    ):
        ref = 'panel_'+number
        panels.append({'panelIndex': number, 'panelRefName': ref, 'type': kind,
                       'version': '2.19.3', 'embeddableConfig': {},
                       'gridData': {'x': 0, 'y': y, 'w': 48, 'h': height, 'i': number}})
        references.append({'name': ref, 'type': kind, 'id': identifier})
    dashboard = {'type': 'dashboard', 'id': DASHBOARD_ID, 'references': references,
                 'attributes': {'title': 'SOC Lab A - Attack Chain & Scoring', 'version': 1,
                     'description': 'Evidence-based chain summaries and explainable operational risk.',
                     'panelsJSON': encoded(panels), 'optionsJSON': encoded({'useMargins': True, 'hidePanelTitles': False}),
                     'timeRestore': True, 'timeFrom': 'now-15m', 'timeTo': 'now',
                     'refreshInterval': {'pause': False, 'value': 1000},
                     'kibanaSavedObjectMeta': {'searchSourceJSON': encoded({'query': {'language': 'kuery', 'query': ''}, 'filter': []})}}}
    return [index, table, search, policy, dashboard]


def detail_objects():
    """A separate dashboard; importing it cannot overwrite the user's v0.4.5 UI.

    The original five saved objects intentionally remain byte-for-byte stable.
    Click a Chain ID for the native case reader; expand evidence for raw fields.
    """
    rows = copy.deepcopy(objects())
    identifiers = {
        INDEX_ID: 'soc-ai-chain-investigation-alerts-v1',
        TABLE_ID: 'soc-ai-chain-investigation-summary-v1',
        SEARCH_ID: 'soc-ai-chain-investigation-history-v1',
        POLICY_ID: 'soc-ai-chain-investigation-policy-v1',
        DASHBOARD_ID: DETAIL_DASHBOARD_ID,
    }
    for row in rows:
        row['id'] = identifiers[row['id']]
        for ref in row['references']:
            ref['id'] = identifiers[ref['id']]
    index, summary, history, policy, dashboard = rows
    fields = json.loads(index['attributes']['fields'])
    known = {f['name'] for f in fields}
    detail_names = {f for f, _ in CONTEXT_COLUMNS} | set(DETAIL_COLUMNS) | {
        'data.attack_chain_json', 'data.activity', 'data.endpoint_evidence_scope', 'data.event_time',
        'data.graph_evidence_ids_omitted', 'data.evidence_count', 'data.evidence_ids',
        'data.distinct_destination_ports', 'data.port_threshold', 'data.port_window_seconds',
    }
    for name in sorted(detail_names):
        if name not in known:
            fields.append({'name': name, 'type': 'string', 'esTypes': ['keyword'],
                           'aggregatable': True, 'searchable': True, 'readFromDocValues': True})
    index['attributes']['fields'] = encoded(fields)
    from chain_profile import link_template, profile_objects
    index['attributes']['fieldFormatMap'] = encoded({'data.chain_id': {
        'id': 'url', 'params': {'urlTemplate': link_template(),
                              'labelTemplate': '{{value}}', 'openLinkInCurrentTab': True}}})
    # Wazuh's outer timestamp is a millisecond-resolution date. Several case
    # transitions can share that millisecond. event_time is normalized UTC with
    # fixed microsecond precision and stored as a custom keyword by Wazuh.
    # Sorting on it selects the latest source evidence instead of an arbitrary
    # revision in a timestamp tie, including when delivery is out of order.
    summary_state = json.loads(summary['attributes']['visState'])
    for metric in summary_state['aggs'][1:]:
        metric['params']['sortField'] = 'data.event_time'
        metric['params']['json'] = encoded({'sort': latest_source_sort()})
    summary['attributes']['visState'] = encoded(summary_state)
    history['attributes']['sort'] = [['timestamp', 'desc'], ['data.event_time', 'desc']]
    # These timestamps are preserved as source strings, not mappings forced on
    # an already indexed Wazuh custom field. The time picker uses Wazuh timestamp.
    context = copy.deepcopy(summary)
    context['id'] = CONTEXT_ID
    context['attributes'].update(title='Chain context and score breakdown - latest revision',
        description='Source, account, event times and evidence counts from the latest case revision.')
    state = json.loads(context['attributes']['visState'])
    state['title'] = context['attributes']['title']
    state['aggs'] = state['aggs'][:1]
    for i, (field, label) in enumerate(CONTEXT_COLUMNS, 2):
        state['aggs'].append({'id': str(i), 'enabled': True, 'type': 'top_hits', 'schema': 'metric',
                             'params': {'field': field, 'aggregate': 'concat', 'size': 1,
                                        'sortField': 'data.event_time', 'sortOrder': 'desc', 'customLabel': label,
                                        'json': encoded({'sort': latest_source_sort()})}})
    context['attributes']['visState'] = encoded(state)
    evidence = copy.deepcopy(history)
    evidence['id'] = EVIDENCE_ID
    evidence['attributes'].update(title='Chain evidence - expand a revision for full text',
        description='Each row is a published revision. Expand the left arrow, then read Table or JSON.',
        columns=DETAIL_COLUMNS)
    # Localize explanatory UI, keeping property keys and table headers intact.
    translated = {
        summary['id']: 'Chi tiết Chain — bản cập nhật mới nhất',
        context['id']: 'Bối cảnh và cách tính điểm — bản cập nhật mới nhất',
        evidence['id']: 'Bằng chứng Chain — mở dòng để xem toàn bộ field',
        history['id']: 'Lịch sử cập nhật Chain',
        policy['id']: 'Cách đọc Chain và mở hồ sơ chi tiết',
    }
    for row in (summary, context, evidence, history, policy):
        row['attributes']['title'] = translated[row['id']]
        if 'visState' in row['attributes']:
            state = json.loads(row['attributes']['visState'])
            state['title'] = row['attributes']['title']
            row['attributes']['visState'] = encoded(state)
    state = json.loads(policy['attributes']['visState'])
    state['params']['markdown'] = (
        '**Bấm Chain ID để mở Hồ sơ Chain ngay trong Wazuh:** đọc đầy đủ từng bước, '
        'thời gian, bằng chứng, cách tính điểm và gợi ý điều tra tiếp. '
        'Hồ sơ mặc định tìm trong 30 ngày; đổi khoảng thời gian nếu cần. '
        'Các bước gợi ý chưa xảy ra không được cộng vào stage count hoặc risk score.'
        '\n\n**Điểm ưu tiên điều tra:** scan 40; thử mật khẩu 65; đăng nhập sau chuỗi sai 85; '
        '+10 nếu có scan trước đó, chặn 95. Medium 40–69, High 70–100. '
        'Đây là chính sách Lab A, không phải xác suất tấn công. ATT&CK IDs là ứng viên từ bằng chứng; '
        'chưa xác nhận bị chiếm quyền. Lịch sử là các revision, không phải số cuộc tấn công.'
        '\n\n**Điều tra:** lọc `data.session_id` hoặc `data.chain_id`. '
        'Case chỉ có scan thì hiển thị một bước; các failure chưa đủ ngưỡng không thành stage. '
        'Trong bảng bằng chứng, mở mũi tên trái để xem Table/JSON và đường dẫn `data.evidence_file`.'
        '\n\n[Nguồn ATT&CK](https://attack.mitre.org/) · '
        '[Attack Flow](https://github.com/center-for-threat-informed-defense/attack-flow) · '
        '[Wazuh ATT&CK](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)')
    policy['attributes']['visState'] = encoded(state)
    panel_specs = [
        ('1', 'visualization', policy['id'], 0, 7),
        ('2', 'visualization', summary['id'], 7, 12),
        ('3', 'visualization', context['id'], 19, 12),
        ('4', 'search', EVIDENCE_ID, 31, 15),
        ('5', 'search', history['id'], 46, 12),
    ]
    panels, references = [], []
    for number, kind, identifier, y, height in panel_specs:
        ref = 'panel_'+number
        panels.append({'panelIndex': number, 'panelRefName': ref, 'type': kind,
                       'version': '2.19.3', 'embeddableConfig': {},
                       'gridData': {'x': 0, 'y': y, 'w': 48, 'h': height, 'i': number}})
        references.append({'name': ref, 'type': kind, 'id': identifier})
    dashboard['references'] = references
    dashboard['attributes'].update(title='SOC Lab A - Điều tra Chain',
        description='Hồ sơ bằng chứng, bối cảnh và cách tính điểm ưu tiên điều tra.',
        panelsJSON=encoded(panels))
    return [index, summary, history, policy, context, evidence, dashboard,
            *profile_objects(latest_source_sort())]


def repair_objects():
    """Replace only the two affected visualizations in an installed dashboard."""
    return [row for row in detail_objects() if row['id'] in
            ('soc-ai-chain-investigation-summary-v1', CONTEXT_ID)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('dashboards')/'soc-ai-attack-chain.ndjson')
    parser.add_argument('--detail', action='store_true', help='Generate the separate Chain Investigation dashboard')
    args = parser.parse_args()
    if args.detail and args.output == Path(__file__).with_name('dashboards')/'soc-ai-attack-chain.ndjson':
        args.output = args.output.with_name('soc-ai-chain-investigation.ndjson')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = detail_objects() if args.detail else objects()
    args.output.write_text(''.join(encoded(row)+'\n' for row in rows), encoding='utf-8', newline='\n')
    print('DASHBOARD_SAVED_OBJECTS:', args.output)
    print('Import in Dashboards Management > Saved objects; no index mapping changes.')


if __name__ == '__main__':
    main()
