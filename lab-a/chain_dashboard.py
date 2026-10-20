"""Generate additive OpenSearch Dashboards saved objects for Wazuh chain events.

Uses a dedicated index-pattern ID; does not change mappings, default index,
credentials or existing dashboards. Top Hit metrics show the latest revision
per chain rather than adding or averaging risk scores across revisions.
"""
import argparse
import json
from pathlib import Path

INDEX_ID = 'soc-ai-chain-alerts-v1'
TABLE_ID = 'soc-ai-attack-chain-detail-v1'
SEARCH_ID = 'soc-ai-chain-history-v1'
POLICY_ID = 'soc-ai-chain-policy-v1'
DASHBOARD_ID = 'soc-ai-attack-chain-dashboard-v1'
QUERY = 'data.soc_ai_producer: "soc-ai-live" and data.soc_ai_kind: "correlation" and data.chain_id: *'
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('dashboards')/'soc-ai-attack-chain.ndjson')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(encoded(row)+'\n' for row in objects()), encoding='utf-8', newline='\n')
    print('DASHBOARD_SAVED_OBJECTS:', args.output)
    print('Import in Dashboards Management > Saved objects; no index mapping changes.')


if __name__ == '__main__':
    main()
