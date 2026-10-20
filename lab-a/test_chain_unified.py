import contextlib,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import sys
from chain_unified import objects,DASHBOARD_ID,INDEX_ID,READER_ID
from manage_chain_dashboards import candidates

class UnifiedTests(unittest.TestCase):
    def test_exactly_one_dashboard_and_no_external_vega_links(self):
        rows=objects();ids={(r['type'],r['id']) for r in rows}
        self.assertEqual([r['id'] for r in rows if r['type']=='dashboard'],[DASHBOARD_ID])
        self.assertEqual(len(rows),5)
        for r in rows:
            for ref in r['references']:self.assertIn((ref['type'],ref['id']),ids)
        reader=next(r for r in rows if r['id']==READER_ID)
        spec=json.loads(json.loads(reader['attributes']['visState'])['params']['spec'])
        self.assertIn('opensearchDashboardsAddFilter',json.dumps(spec))
        self.assertNotIn('"href"',json.dumps(spec))
        data={d['name']:d for d in spec['data']}
        self.assertIn('chain_revision_id',data['stageRows']['transform'][0]['expr'])
        self.assertIn('chain_active',data['active']['transform'][0]['expr'])
    def test_cleanup_preserves_native_dashboard_new_dashboard_and_all_components(self):
        rows=[{'type':'dashboard','id':'native','attributes':{'title':'Threat Hunting'}},
              {'type':'dashboard','id':DASHBOARD_ID,'attributes':{'title':'SOC Lab A - Attack Chain'}},
              {'type':'dashboard','id':'copy','attributes':{'title':'SOC Lab A - Chain Investigation'}},
              {'type':'visualization','id':'shared','attributes':{'title':'SOC Lab A - Chain Investigation'}}]
        self.assertEqual([r['id'] for r in candidates(rows)],['copy'])
    def test_manager_trace_accepts_final_high_summary_without_intermediate_medium(self):
        from wazuh_trace import rule_expectations
        operator={'expected_rule_ids':['119213','119214'],
                  'expected_rule_id_groups':[['119212','119214']]}
        high=rule_expectations(operator,{'119213':4,'119214':1})
        self.assertEqual(high['missing_expected_rule_ids'],[])
        self.assertEqual(high['missing_expected_rule_id_groups'],[])
        absent=rule_expectations(operator,{'119213':4})
        self.assertEqual(absent['missing_expected_rule_ids'],['119214'])
        self.assertEqual(absent['missing_expected_rule_id_groups'],[['119212','119214']])

    def test_runner_records_reset_and_continues_independent_http_phases(self):
        import chain_scenarios as mod
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);capture=root/'capture';capture.mkdir();out=root/'out'
            (capture/'correlation-cases.json').write_text(json.dumps({'config':{'attack_chain_enabled':True}}))
            auth_calls=[]
            def run(argv,**kwargs):
                if 'sshpass' in argv:
                    auth_calls.append(argv)
                    stderr=b'soctest@172.20.0.3: Permission denied (password).\n' if len(auth_calls)<8 else b'kex_exchange_identification: Connection reset by peer\n'
                    return SimpleNamespace(returncode=255,stdout=b'',stderr=stderr)
                return SimpleNamespace(returncode=0,stdout=b'{"requested":100}' if argv[-2:]==['-','172.20.0.3'] else b'',stderr=b'')
            argv=['chain_scenarios','--scenario','chain-mixed','--capture',str(capture),'--output',str(out)]
            with patch.object(sys,'argv',argv),patch.object(mod,'validate_capture',return_value=({'session_id':'test'},{})),patch.object(mod,'lab_scope',return_value={'target_ip':'172.20.0.3','source_ip':'172.20.0.4','client':'kali-attacker'}),patch.object(mod.subprocess,'run',side_effect=run),patch.object(mod.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):
                code=mod.main()
            report=json.loads((out/'operator.json').read_text())
            self.assertEqual(code,2);self.assertFalse(report['complete'])
            self.assertEqual(len(auth_calls),8)
            self.assertEqual(sum(s['client_outcome']=='password_rejected' for s in report['steps']),7)
            self.assertEqual(report['http_load']['requested'],100)
            self.assertIn('UNION',report['steps'][-1]['argv'][-1])
if __name__=='__main__':unittest.main()
