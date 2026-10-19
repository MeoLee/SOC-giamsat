import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('web_setup', Path(__file__).parent/'endpoint/setup_web.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class WebSetupTests(unittest.TestCase):
    def test_agent_input_is_idempotent_and_keeps_existing_suricata_auth(self):
        old = '<ossec_config><localfile><log_format>json</log_format><location>/var/log/suricata/eve-alerts.json</location></localfile><client><server><address>manager</address></server></client></ossec_config>\n<ossec_config></ossec_config>'
        new = web.agent_conf(old)
        self.assertEqual(web.agent_conf(new), new)
        self.assertIn('/var/log/suricata/eve-alerts.json', new)
        self.assertIn('<client><server>', new)
        self.assertEqual(new.count('/var/log/apache2/soc-lab-access.log'), 1)
        import xml.etree.ElementTree as ET
        root = ET.fromstring('<doc>'+new+'</doc>')
        self.assertFalse(list(root.iter('client'))[0].findall('localfile'))

    def test_agent_conf_duplicate_is_not_silently_accepted(self):
        entry = '<localfile><log_format>apache</log_format><location>/var/log/apache2/soc-lab-access.log</location></localfile>'
        with self.assertRaises(ValueError): web.agent_conf('<ossec_config>'+entry*2+'</ossec_config>')

    def test_commented_closing_tag_does_not_receive_inputs(self):
        text = '<ossec_config><!-- </ossec_config> --></ossec_config>'
        new = web.agent_conf(text)
        self.assertIn('<!-- </ossec_config> -->', new)
        self.assertIn('-->\n  <!-- SOC-LAB WEB INPUTS -->', new)

    def test_apache_conf_records_peer_endpoints_and_latency_for_all_vhosts(self):
        conf = web.apache_conf('172.20.0.0/24')
        for text in ('%a', '%A', '%{remote}p', '%{local}p', '%D', '%>s', '%{begin:usec}t', '%{end:usec}t', 'GlobalLog', 'Options -Indexes'):
            self.assertIn(text, conf)
        self.assertNotIn('Require all granted', conf)
        with self.assertRaises(ValueError): web.apache_conf('172.20.0.0/24\nRequire all granted')

    def test_autostart_preserves_old_services_and_is_idempotent(self):
        old = 'if [ "$$" -eq 1 ]; then\n suricata -D\nfi\n'
        new = web.startup_conf(old)
        self.assertEqual(web.startup_conf(new), new)
        self.assertIn('suricata -D', new)
        self.assertEqual(new.count('# BEGIN SOC-LAB WEB AUTOSTART'), 1)
        self.assertIn('"$$" -eq 1', new)

    def test_setup_token_attribute_order_is_supported(self):
        parser = web.TokenParser()
        parser.feed('<input value="abc123" type="hidden" name="user_token">')
        self.assertEqual(parser.value, 'abc123')


if __name__ == '__main__': unittest.main()
