import json,unittest
from unittest.mock import patch
import dvwa_cli as m

class Reply:
    def __init__(self,body):self.body=body.encode()
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def read(self,*_):return self.body
class Opener:
    def __init__(self,replies):self.replies=iter(replies);self.requests=[]
    def open(self,req,**kwargs):self.requests.append(req);return Reply(next(self.replies))
class DvwaTests(unittest.TestCase):
    def test_fixed_sql_proof_requires_returned_columns_not_reflected_payload(self):
        for valid in (True,False):
            last='<pre>First name: SOCLAB_UNION_PROOF<br />Surname: SOCLAB_SECOND_COLUMN</pre>' if valid else 'ID: SOCLAB_UNION_PROOF SOCLAB_SECOND_COLUMN<br/>First name: admin<br/>Surname: admin'
            op=Opener(['<input name="user_token" value="abc">','login ok','<form/>','baseline',last])
            with self.subTest(valid=valid),patch.object(m.urllib.request,'build_opener',return_value=op):
                if valid:
                    result=m.run('172.20.0.3','sqli','admin','private-test-password')
                    self.assertTrue(result['query_result_proof'])
                    self.assertNotIn('private-test-password',json.dumps(result))
                else:
                    with self.assertRaises(ValueError):m.run('172.20.0.3','sqli','admin','private-test-password')
    def test_upload_probe_has_fixed_code_and_verifies_execution_not_php_source(self):
        op=Opener(['<input name="user_token" value="abc">','login ok','<form/>','uploaded','SOC_LAB_FIXED_EXEC\nuid=33(www-data) gid=33(www-data)'])
        with patch.object(m.urllib.request,'build_opener',return_value=op):result=m.run('172.20.0.3','upload-fixed-probe','admin','secret')
        self.assertTrue(result['fixed_execution_proof']);self.assertFalse(result['confirmed_general_compromise'])
        self.assertNotIn(b'$_GET',m.PHP);self.assertNotIn(b'$_POST',m.PHP)
        self.assertIn(b'/usr/bin/id',m.PHP)
        self.assertIn(b'name="uploaded"',op.requests[3].data)
        self.assertRegex(result['artifact_path'],r'/soc-lab-[a-f0-9]{32}\.php$')
    def test_target_must_be_a_private_single_ipv4(self):
        for ip in ('8.8.8.8','127.0.0.1','::1','172.20.0.3/24'):
            with self.subTest(ip=ip),self.assertRaises(ValueError):m.run(ip,'sqli','admin','secret')

if __name__=='__main__':unittest.main()
