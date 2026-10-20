import json
from pathlib import Path
import struct
import tempfile
import unittest

from lab_web import analyze_target, apache_tsv, apache_combined, normalize_http_status
from lab_correlation import DEFAULTS, Correlator, normalize_line, build_cases, digest
from configure_web_live import updated_config
from setup_suricata_web import merge_rules, test_pcap, remote_script

PAYLOAD = '/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20CONVERT%28CONCAT%280x71626a6a71%2CNULL%29%20USING%20utf8mb4%29%2CNULL--%20-&Submit=Submit'


def tsv(target=PAYLOAD,status=500,src='172.20.0.4',dst='172.20.0.3'):
    return ('\t'.join(['1792034292000000','1792034292002000',src,'41000',dst,'80','GET',target,str(status),'1024','2000','sqlmap/1.10.9'])+'\n').encode()


def combined(target=PAYLOAD,status=500):
    return f'172.20.0.4 - - [14/Oct/2026:23:18:12 -0400] "GET {target} HTTP/1.1" {status} 1024 "-" "sqlmap/1.10.9"'


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.config={**DEFAULTS,'all_agents':True,'assets':[{'host':'ubuntu-endpoint','ips':['172.20.0.3']}],
            'source_kinds':{'apache.tsv':'web','wazuh.jsonl':'wazuh','eve.jsonl':'eve','access.log':'raw'}}
        for name in self.config['source_kinds']: (self.root/name).touch()

    def test_user_union_payload_recognized_and_original_preserved(self):
        e=apache_tsv(tsv())
        self.assertEqual(e['sql_indicators'],['sql_union_select'])
        self.assertEqual(e['request_target'],PAYLOAD)
        self.assertEqual(e['source_port'],41000)
        self.assertEqual(e['duration_us'],2000)

    def test_benign_id_search_and_union_word_not_flagged(self):
        for target in ('/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit','/search?q=union+representatives','/search?q=selectivity','/soc-lab-health'):
            self.assertEqual(analyze_target(target)['sql_indicators'],[])

    def test_double_encoding_bounded_and_html_not_unescaped(self):
        e=analyze_target('/?q=UNION%2520ALL%2520SELECT')
        self.assertIn('sql_union_select',e['sql_indicators'])
        self.assertEqual(e['url_decode_passes'],2)
        e=analyze_target('/?q=UNION%252520ALL%252520SELECT')
        self.assertEqual(e['sql_indicators'],[])
        self.assertIn('&amp;',analyze_target('/?q=1&amp;x=2')['decoded_query'])

    def test_missing_fields_and_invalid_values_not_filled_with_zero(self):
        for raw in (b'bad\n',tsv().replace(b'\t2000\t',b'\t-1\t'),tsv().replace(b'\t41000\t',b'\t99999\t')):
            with self.assertRaises(ValueError): apache_tsv(raw)

    def test_combined_log_timezone_and_unknown_latency(self):
        e=apache_combined(combined(),'ubuntu-endpoint','172.20.0.3')
        self.assertEqual(e['event_time'],'2026-10-15T03:18:12.000000Z')
        self.assertIsNone(e['duration_us'])
        self.assertIsNone(e['source_port'])

    def test_wazuh_apache_existing_capture_creates_sql_evidence(self):
        row={'agent':{'id':'001','name':'ubuntu-endpoint'},'rule':{'id':'31103'},'full_log':combined()}
        e=normalize_line('wazuh.jsonl',json.dumps(row).encode(),self.config)
        self.assertEqual(e['kind'],'web.sqli_indicator')
        self.assertFalse(e['success_proven'])

    def test_http_200_does_not_prove_success_or_train_label(self):
        e=normalize_line('apache.tsv',tsv(status=200),self.config)
        e.update(event_id='e',source_refs=[])
        case=build_cases([e],self.config)[0]
        self.assertEqual(case['status'],'possible_web_sqli')
        self.assertFalse(case['confirmed_compromise'])
        self.assertIsNone(case['training_label'])

    def test_normal_http_saved_but_no_sql_case(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        (self.root/'apache.tsv').write_bytes(tsv('/?id=1',200))
        engine.consume()
        self.assertEqual(engine.cases,[])
        self.assertEqual(engine.counts['http_requests'],1)
        self.assertEqual(len(engine.web_log.read_text().splitlines()),1)

    def test_raw_apache_not_parsed_as_json_and_bad_tsv_reported(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        self.assertFalse(engine.process('access.log',combined().encode()))
        engine.process('apache.tsv',b'invalid')
        self.assertEqual(engine.counts['invalid_source_records'],1)

    def test_other_ip_pair_not_filtered(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        (self.root/'apache.tsv').write_bytes(tsv(src='10.1.1.7',dst='10.1.1.8'))
        engine.consume()
        self.assertEqual(engine.cases[0]['source_ip'],'10.1.1.7')
        self.assertEqual(engine.cases[0]['target_host'],'ip:10.1.1.8')

    def test_sensor_and_wazuh_views_deduplicate_without_request_count_claim(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        event={'timestamp':'2026-10-15T03:18:12Z','event_type':'alert','flow_id':1,'src_ip':'172.20.0.4',
            'dest_ip':'172.20.0.3','src_port':41000,'dest_port':80,'alert':{'signature_id':9900101},
            'http':{'url':PAYLOAD,'status':200,'http_method':'GET'}}
        engine.process('eve.jsonl',json.dumps(event).encode())
        wrapper={'agent':{'id':'001','name':'ubuntu-endpoint'},'full_log':json.dumps(event)}
        engine.process('wazuh.jsonl',json.dumps(wrapper).encode())
        self.assertEqual(len(engine.events),1)
        self.assertEqual(engine.counts['duplicate_views'],1)

    def test_late_wazuh_string_status_does_not_interrupt_sql_correlation(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        event={'timestamp':apache_tsv(tsv())['event_time'],'event_type':'alert',
            'flow_id':1,'tx_id':0,'src_ip':'172.20.0.4','dest_ip':'172.20.0.3',
            'src_port':41000,'dest_port':80,'alert':{'signature_id':9900101},
            'http':{'url':PAYLOAD,'status':302,'http_method':'GET'}}
        (self.root/'eve.jsonl').write_text(json.dumps(event)+'\n')
        (self.root/'apache.tsv').write_bytes(tsv(status=302))
        engine.consume()
        self.assertEqual(len(engine.cases),1)
        # Wazuh's decoded view can arrive after the native alert and Apache.
        decoded=json.loads(json.dumps(event))
        for field in ('flow_id','tx_id','src_port','dest_port'):
            decoded[field]=str(decoded[field])
        decoded['alert']['signature_id']='9900101'
        decoded['http']['status']='302'
        wrapper={'agent':{'id':'001','name':'ubuntu-endpoint'},'data':decoded}
        (self.root/'wazuh.jsonl').write_text(json.dumps(wrapper)+'\n')
        engine.consume()
        self.assertEqual(len(engine.events),2)  # native EVE + Apache evidence
        self.assertEqual(engine.counts['duplicate_views'],1)
        self.assertEqual(engine.cases[0]['http_status_counts'],{'302':2})
        self.assertEqual(engine.cases[0]['status'],'possible_web_sqli')
        self.assertFalse(engine.cases[0]['confirmed_compromise'])
        with (self.root/'wazuh.jsonl').open('a') as stream:
            for view in (decoded,event):
                stream.write(json.dumps({'agent':wrapper['agent'],
                    'full_log':json.dumps(view)})+'\n')
        engine.consume()
        self.assertEqual(len(engine.events),2)
        self.assertEqual(engine.counts['duplicate_views'],3)
        self.assertEqual(engine.cases[0]['http_status_counts'],{'302':2})

    def test_http_status_accepts_only_valid_integers_or_ascii_three_digit_strings(self):
        self.assertIsNone(normalize_http_status(None))
        for value in (100,'100',302,'302',599,'599'):
            self.assertEqual(normalize_http_status(value),int(value))
            self.assertIs(type(normalize_http_status(value)),int)
        for value in (True,False,302.0,'302.0',99,600,'099','600',' 302',
                      '0302','\uff13\uff10\uff12','',[],{},'unknown'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                normalize_http_status(value)

    def test_invalid_sensor_http_status_is_recorded_without_stopping_valid_evidence(self):
        engine=Correlator(self.root,self.root/'out',self.config)
        event={'timestamp':apache_tsv(tsv())['event_time'],'event_type':'alert',
            'flow_id':1,'src_ip':'172.20.0.4','dest_ip':'172.20.0.3',
            'src_port':41000,'dest_port':80,'alert':{'signature_id':9900101},
            'http':{'url':PAYLOAD,'http_method':'GET'}}
        values=(True,302.0,'unknown','600',None)
        rows=[{**event,'http':{**event['http'],'status':value}} for value in values]
        (self.root/'eve.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows))
        engine.consume()
        self.assertEqual(engine.counts['invalid_source_records'],4)
        self.assertEqual(len(engine.errors.read_text().splitlines()),4)
        self.assertEqual(len(engine.events),1)
        self.assertIsNone(next(iter(engine.events.values()))['http_status'])
        self.assertEqual(engine.cases[0]['http_status_counts'],{})

    def test_legacy_normalized_views_merge_status_counts_without_mutating_evidence(self):
        event=normalize_line('apache.tsv',tsv(status=302),self.config)
        views=[{**event,'event_id':str(i),'http_status':status,'source_refs':[]}
               for i,status in enumerate((302,'302',None))]
        case=build_cases(views,self.config)[0]
        self.assertEqual(case['http_status_counts'],{'302':2})
        self.assertEqual(case['stages'][0]['evidence_count'],3)
        self.assertEqual(views[1]['http_status'],'302')

    def test_case_id_stable_for_late_views_in_same_window(self):
        a=normalize_line('apache.tsv',tsv(),self.config); a.update(event_id='a',source_refs=[])
        b={**a,'event_id':'b','event_time':'2026-10-15T03:18:00.000000Z'}
        one=build_cases([a],self.config)
        two=build_cases([a,b],self.config)
        self.assertEqual(one[0]['case_id'],two[0]['case_id'])
        self.assertEqual(two,build_cases([b,a],self.config))

    def test_config_sources_append_idempotently_without_asset_changes(self):
        data={'sources':[],'assets':[{'host':'custom','ips':['10.0.0.5']}],'wazuh_manager':'manager-custom'}
        updated=updated_config(data,'ubuntu-endpoint')
        self.assertEqual(updated_config(updated,'ubuntu-endpoint'),updated)
        self.assertEqual(updated['assets'],data['assets'])
        self.assertEqual(updated['wazuh_manager'],'manager-custom')
        self.assertEqual(data['sources'],[])

    def test_rule_merge_preserves_original_rejects_sid_collision(self):
        old='alert tcp any any -> any any (sid:9900001;)\n'
        web=Path(__file__).with_name('soc-web.rules').read_text()
        new=merge_rules(old,web)
        self.assertIn(old.strip(),new)
        self.assertEqual(merge_rules(new,web),new)
        with self.assertRaises(ValueError): merge_rules(old+'alert http any any -> any any (sid:9900101;)',web)

    def test_generated_pcap_has_complete_positive_and_benign_connections(self):
        data=test_pcap(); offset=24; payloads=[]
        while offset<len(data):
            _,_,length,original=struct.unpack_from('<IIII',data,offset); offset+=16
            self.assertEqual(length,original)
            frame=data[offset:offset+length]; offset+=length
            self.assertEqual(frame[12:14],b'\x08\x00')
            payloads.append(frame[54:])
        self.assertEqual(offset,len(data))
        self.assertEqual(len(payloads),30)
        self.assertTrue(any(b'UNION' in p and b'GET' in p for p in payloads))
        self.assertTrue(any(b'POST' in p and b'UNION' in p for p in payloads))
        self.assertTrue(any(b'union+representatives' in p for p in payloads))
        compile(remote_script(),'<remote-suri>','exec')


if __name__=='__main__': unittest.main()
