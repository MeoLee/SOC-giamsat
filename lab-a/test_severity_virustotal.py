import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import setup_virustotal as vt
from vt_lab_artifact import create,EICAR_MD5,EICAR_SHA256


class SeverityVirusTotalTests(unittest.TestCase):
    def test_rule_severity_depends_on_evidence_not_generic_sensor_or_mlp(self):
        rules={r.attrib['id']:r for r in ET.fromstring(Path(__file__).with_name('soc_ai_bridge_rules.xml').read_text())}
        for identifier,level in {'119202':5,'119203':8,'119204':10,'119205':13,'119206':12,
                                 '119209':8,'119214':12,'119215':12}.items():
            self.assertEqual(rules[identifier].attrib['level'],str(level))
        self.assertEqual(rules['119215'].findtext('if_sid'),'119209')
        self.assertEqual(rules['119215'].find('field').text,'^(9900101|9900102)$')
        self.assertEqual({k for k,r in rules.items() if int(r.attrib['level'])>=15},{'119220','119222'})

    def test_vt_config_is_scoped_idempotent_and_keeps_other_integrations(self):
        key='a'*64;before='<ossec_config><integration><name>custom-other</name><api_key>keep-me</api_key></integration></ossec_config>'
        after=vt.config_update(before,key)
        self.assertIn('keep-me',after);self.assertEqual(vt.config_update(after,key),after)
        root=ET.fromstring(after);node=root.findall('integration')[1]
        self.assertEqual(node.findtext('rule_id'),'119253')
        self.assertIsNone(node.find('group'));self.assertIsNone(node.find('hook_url'))
        self.assertEqual(node.findtext('alert_format'),'json')
        self.assertEqual(node.findtext('timeout'),'20');self.assertEqual(node.findtext('retries'),'0')
        rotated=vt.config_update(after,'b'*64)
        self.assertNotIn(key,rotated);self.assertIn('b'*64,rotated)

    def test_unmanaged_or_duplicate_integrations_and_bad_keys_are_rejected(self):
        existing='<integration><name>virustotal</name><api_key>existing</api_key></integration>'
        for text in ('<ossec_config>'+existing+'</ossec_config>','<ossec_config>'+existing*2+'</ossec_config>'):
            with self.assertRaises(ValueError):vt.config_update(text,'a'*64)
        for key in ('short','g'*64,'<secret>','a'*64+'\n'):
            with self.assertRaises(ValueError):vt.config_update('<ossec_config/>',key)

    def test_comments_and_multiple_config_roots_do_not_hide_real_integration(self):
        before='<ossec_config><!-- </ossec_config> --></ossec_config><ossec_config><global/></ossec_config>'
        after=vt.config_update(before,'a'*64)
        root=ET.fromstring('<document>'+after+'</document>')
        self.assertEqual(len(list(root.iter('integration'))),1)
        self.assertEqual(vt.config_update(after,'a'*64),after)

    def test_eicar_vector_is_exact_never_overwrites_and_control_is_different(self):
        with tempfile.TemporaryDirectory() as folder:
            eicar=create(folder,'eicar','one'); control=create(folder,'control','two')
            self.assertEqual(eicar['md5'],EICAR_MD5);self.assertEqual(eicar['sha256'],EICAR_SHA256)
            self.assertEqual(eicar['bytes'],68);self.assertFalse(eicar['real_malware']);self.assertFalse(eicar['executed'])
            self.assertNotEqual(control['sha256'],eicar['sha256'])
            with self.assertRaises(FileExistsError):create(folder,'eicar','one')
            for token in ('../outside','a/b','$(command)'):
                with self.assertRaises(ValueError):create(folder,'eicar',token)

    @unittest.skipIf(sys.platform=='win32','Requires symlink support')
    def test_artifact_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            real=Path(folder)/'real';real.mkdir();link=Path(folder)/'link';link.symlink_to(real,target_is_directory=True)
            with self.assertRaises(ValueError):create(link,'eicar','one')

    def test_payload_embeds_dependency_and_fits_windows_command_line(self):
        script=vt.remote_script();compile(script,'remote-vt','exec')
        self.assertTrue(script.endswith('install_remote(json.load(sys.stdin))\n'))
        self.assertIn("sys.modules['wazuh_install_checks']",script)
        self.assertLess(len(subprocess.list2cmdline(['docker','exec','manager','sh','-c',script])),32767)

    def test_api_key_only_sent_to_docker_stdin_not_argv(self):
        key='a'*64
        with patch.object(sys,'argv',['setup_virustotal']),patch.object(sys.stdin,'isatty',return_value=True), \
                patch.object(vt.getpass,'getpass',return_value=key), \
                patch.object(vt.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(vt.main(),0)
        args=run.call_args
        self.assertNotIn(key,' '.join(args.args[0]))
        self.assertEqual(json.loads(args.kwargs['input'])['api_key'],key)

    def test_failed_validation_restores_original_config_without_logging_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'var/ossec';(root/'etc/rules').mkdir(parents=True);(root/'integrations').mkdir()
            config=root/'etc/ossec.conf';old=b'<ossec_config><global/></ossec_config>';config.write_bytes(old)
            (root/'etc/rules/soc_scenario_rules.xml').write_text('SOC-SCENARIO MANAGED <rule id="119253" level="3"/>')
            for name in ('virustotal','virustotal.py'):(root/'integrations'/name).touch()
            source=Path(vt.__file__).read_text().replace('/var/ossec',root.as_posix())
            namespace={'__name__':'isolated_vt'};exec(source,namespace)
            output=io.StringIO();key='a'*64
            with patch.object(vt.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=key.encode(),stderr=b'validation failed')), \
                    patch('os.chown',create=True),patch.dict(sys.modules,{'requests':SimpleNamespace()}),contextlib.redirect_stdout(output):
                with self.assertRaises(RuntimeError):namespace['install_remote']({'api_key':key})
            self.assertEqual(config.read_bytes(),old)
            self.assertNotIn(key,output.getvalue());self.assertIn('[REDACTED]',output.getvalue())
            backups=list((root/'backup').glob('soc-vt-*/ossec.conf'))
            self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),old)


if __name__=='__main__':unittest.main()
