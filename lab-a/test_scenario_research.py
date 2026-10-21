import contextlib,io,json,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from setup_scenario_fim import config_update,PATHS
from setup_scenario_rules import check_collisions,RULE_PATH

class ScenarioResearchTests(unittest.TestCase):
    def test_scoped_fim_is_idempotent_preserves_unrelated_config_and_ignores_comments(self):
        original='<ossec_config><!-- <syscheck><disabled>yes</disabled></syscheck> --><client><server><address>manager</address></server></client><syscheck><disabled>yes</disabled><frequency>43200</frequency><directories realtime="yes">/etc</directories></syscheck><integration><name>existing</name></integration></ossec_config>'
        updated=config_update(original)
        self.assertEqual(config_update(updated),updated)
        self.assertIn('<client><server><address>manager</address></server></client>',updated)
        self.assertIn('<integration><name>existing</name></integration>',updated)
        self.assertIn('<frequency>43200</frequency>',updated)
        self.assertIn('>/etc</directories>',updated)
        self.assertIn('<disabled>no</disabled>',updated)
        self.assertIn('<alert_new_files>yes</alert_new_files>',updated)
        for path in PATHS:self.assertEqual(updated.count('>'+path+'</directories>'),1)
        new=config_update('<ossec_config><client/></ossec_config>')
        self.assertEqual(config_update(new),new)
    def test_kernel_input_is_optional_idempotent_and_rejects_conflicts(self):
        original='<ossec_config><client/></ossec_config>'
        updated=config_update(original,'/var/log/kern.log')
        self.assertEqual(updated.count('<location>/var/log/kern.log</location>'),1)
        self.assertEqual(config_update(updated,'/var/log/kern.log'),updated)
        self.assertNotIn('/var/log/kern.log',config_update(original))
        with self.assertRaises(ValueError):config_update(original,'/arbitrary/path')
        with self.assertRaises(ValueError):config_update('<ossec_config><localfile><log_format>json</log_format><location>/var/log/kern.log</location></localfile></ossec_config>','/var/log/kern.log')

    def test_fim_refuses_ambiguous_or_restricted_configuration(self):
        for text in ('<ossec_config><syscheck/><syscheck/></ossec_config>',
                     '<ossec_config><syscheck><directories restrict="x">/var/lib/soc-lab/fim</directories></syscheck></ossec_config>'):
            with self.assertRaises(ValueError):config_update(text)
    def test_scenario_rule_collisions_and_scope(self):
        text=Path(__file__).with_name('soc_scenario_rules.xml').read_text()
        check_collisions(text,{})
        with self.assertRaises(ValueError):check_collisions(text,{'/var/ossec/etc/rules/local_rules.xml':'<rule id="119250" level="7"/>'})
        with self.assertRaises(ValueError):check_collisions(text,{RULE_PATH:'<group name="user," />'})
        self.assertNotIn('if_matched_sid>31108',text)
        self.assertNotIn('virustotal',text.lower())
        self.assertIn('^(4444|5555|6666)$',text)
    def test_http_pressure_and_http_sqli_runner_execute_only_their_phases(self):
        import chain_scenarios as mod
        for scenario in ('http-pressure','chain-http-sqli'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);capture=root/'capture';capture.mkdir();out=root/'out';calls=[]
                (capture/'correlation-cases.json').write_text(json.dumps({'config':{'attack_chain_enabled':True}}))
                def run(argv,**kwargs):
                    calls.append(argv)
                    return SimpleNamespace(returncode=0,stdout=b'{"requested":100}' if argv[-2:]==['-','172.20.0.3'] else b'',stderr=b'')
                with patch.object(sys,'argv',['scenario','--scenario',scenario,'--capture',str(capture),'--output',str(out)]),patch.object(mod,'validate_capture',return_value=({'session_id':'test'},{})),patch.object(mod,'lab_scope',return_value={'target_ip':'172.20.0.3','source_ip':'172.20.0.4','client':'kali-attacker'}),patch.object(mod.subprocess,'run',side_effect=run),patch.object(mod.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):code=mod.main()
                report=json.loads((out/'operator.json').read_text())
                self.assertEqual(code,0);self.assertTrue(report['complete'])
                self.assertFalse(any('sshpass' in argv for argv in calls))
                self.assertEqual(any('nmap' in argv for argv in calls),scenario!='http-pressure')
                self.assertEqual(any('UNION' in argv[-1] for argv in calls),scenario=='chain-http-sqli')
                self.assertEqual('possible_recon' in report['required_stages'],scenario!='http-pressure')
                self.assertEqual(report['expected_rule_id_groups'],[['119212','119214']])

if __name__=='__main__':unittest.main()
