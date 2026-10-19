"""Executed inside ubuntu-endpoint after apt installed the dependencies."""
from html.parser import HTMLParser
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path('/opt/soc-lab/DVWA')
CONF = Path('/etc/apache2/conf-available/soc-lab-web.conf')
STATE = Path('/opt/soc-lab/web-install.json')
REPOSITORY = 'https://github.com/digininja/DVWA.git'


def run(argv, **kwargs):
    print('RUN:', ' '.join(str(a) for a in argv), flush=True)
    return subprocess.run(argv, check=True, **kwargs)


def apache_conf(cidr):
    cidr = str(ipaddress.ip_network(cidr, strict=True))
    return '''# SOC-LAB WEB MANAGED v0.1
ServerName ubuntu-endpoint
Alias /dvwa /opt/soc-lab/DVWA
<Directory /opt/soc-lab/DVWA>
    Options -Indexes
    AllowOverride None
    Require ip 127.0.0.1 ::1 CIDR
</Directory>
Alias /soc-lab-health /var/www/soc-lab/health.txt
<Directory /var/www/soc-lab>
    Options -Indexes
    Require ip 127.0.0.1 ::1 CIDR
</Directory>
# Standard combined log, consumed by Wazuh's Apache decoder.
GlobalLog /var/log/apache2/soc-lab-access.log combined
# Tab-separated telemetry: microsecond start/end, peer endpoints, request,
# status, response body bytes, duration and user agent. This is not JSON.
LogFormat "%{begin:usec}t\\t%{end:usec}t\\t%a\\t%{remote}p\\t%A\\t%{local}p\\t%m\\t%U%q\\t%>s\\t%B\\t%D\\t%{User-Agent}i" soc_lab_metrics
GlobalLog /var/log/apache2/soc-lab-requests.tsv soc_lab_metrics
<IfModule mpm_prefork_module>
    StartServers 2
    MinSpareServers 2
    MaxSpareServers 4
    MaxRequestWorkers 16
    MaxConnectionsPerChild 500
</IfModule>
'''.replace('CIDR', cidr)


def agent_conf(text):
    root = ET.fromstring('<document>'+re.sub(r'<\?xml[^>]*\?>', '', text)+'</document>')
    wanted = ['/var/log/apache2/soc-lab-access.log', '/var/log/apache2/error.log']
    additions = []
    for location in wanted:
        entries = [e for e in root.iter('localfile') if (e.findtext('location') or '').strip() == location]
        if len(entries) > 1:
            raise ValueError('Duplicate Wazuh localfile: '+location)
        if entries:
            if (entries[0].findtext('log_format') or '').strip() != 'apache':
                raise ValueError('Existing web log input has different format: '+location)
        else:
            additions.append('  <localfile>\n    <log_format>apache</log_format>\n    <location>'+location+'</location>\n  </localfile>\n')
    if not additions: return text
    for token in re.finditer(r'<!--.*?-->|</ossec_config>', text, re.DOTALL):
        if token.group() == '</ossec_config>':
            return text[:token.start()]+'\n  <!-- SOC-LAB WEB INPUTS -->\n'+''.join(additions)+text[token.start():]
    raise ValueError('ossec_config closing tag missing')


def startup_conf(text):
    start = '# BEGIN SOC-LAB WEB AUTOSTART'
    end = '# END SOC-LAB WEB AUTOSTART'
    if text.count(start) != text.count(end) or text.count(start) > 1:
        raise ValueError('Ambiguous web autostart block')
    text = re.sub(re.escape(start)+r'.*?'+re.escape(end)+r'\n?', '', text, flags=re.DOTALL)
    return text.rstrip()+'''\n\n# BEGIN SOC-LAB WEB AUTOSTART
if [ "$$" -eq 1 ]; then
    /usr/local/sbin/start-soc-web.sh >>/var/log/soc-lab-web-start.log 2>&1 || echo '[SOC-LAB] Web startup failed; see /var/log/soc-lab-web-start.log'
fi
# END SOC-LAB WEB AUTOSTART
'''


class TokenParser(HTMLParser):
    def __init__(self): super().__init__(); self.value = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name') == 'user_token':
            self.value = attrs.get('value')


def main():
    import grp
    import pwd
    payload = json.load(sys.stdin)
    if os.geteuid() != 0 or not Path('/.dockerenv').exists():
        raise RuntimeError('This installer must run as root inside the lab Docker container')
    cidr = str(ipaddress.ip_network(payload['lab_cidr']))
    ROOT.parent.mkdir(parents=True, exist_ok=True)
    if ROOT.exists():
        if not STATE.exists() or not (ROOT/'.git').exists():
            raise RuntimeError('Existing DVWA directory is not owned by this installer; left untouched')
    else:
        run(['git', 'clone', '--depth', '1', REPOSITORY, str(ROOT)])
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    previous = json.loads(STATE.read_text()) if STATE.exists() else None
    if previous and previous.get('dvwa_commit') != commit:
        raise RuntimeError('DVWA revision changed; review before updating')
    # Record ownership immediately, so a failed installation can be resumed.
    STATE.write_text(json.dumps({'complete': False, 'dvwa_commit': commit, 'lab_cidr': cidr}, indent=2))
    config = ROOT/'config/config.inc.php'
    base_config = (ROOT/'config/config.inc.php.dist').read_text()
    base_config = re.sub(r'\?>\s*$', '', base_config)
    config.write_text(base_config+"""
// SOC-LAB local database and controlled test settings.
$_DVWA['db_server'] = '127.0.0.1';
$_DVWA['db_port'] = '3306';
$_DVWA['db_user'] = 'dvwa';
$_DVWA['db_password'] = 'p@ssw0rd';
$_DVWA['db_database'] = 'dvwa';
$_DVWA['default_security_level'] = 'low';
$_DVWA['disable_authentication'] = false;
""")
    os.chown(config, 0, grp.getgrnam('www-data').gr_gid); os.chmod(config, 0o640)
    uploads = ROOT/'hackable/uploads'
    if uploads.exists(): os.chown(uploads, pwd.getpwnam('www-data').pw_uid, grp.getgrnam('www-data').gr_gid)
    old_conf = CONF.read_bytes() if CONF.exists() else None
    if old_conf and b'SOC-LAB WEB MANAGED' not in old_conf:
        raise RuntimeError('Apache config filename contains unmanaged content')
    CONF.write_text(apache_conf(cidr))
    Path('/var/www/soc-lab').mkdir(exist_ok=True)
    Path('/var/www/soc-lab/health.txt').write_text('SOC_WEB_OK\n')
    run(['a2enmod', 'rewrite'])
    run(['a2enconf', 'soc-lab-web'])
    try:
        run(['apache2ctl', 'configtest'])
    except BaseException:
        if old_conf is None:
            run(['a2disconf', 'soc-lab-web']); CONF.unlink(missing_ok=True)
        else: CONF.write_bytes(old_conf)
        raise
    start = Path('/usr/local/sbin/start-soc-web.sh')
    start.write_text(payload['start_script']); start.chmod(0o755)
    run([str(start)])
    sql = """CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'127.0.0.1';
FLUSH PRIVILEGES;
"""
    run(['mariadb', '--protocol=socket', '-u', 'root'], input=sql.encode())
    tables = subprocess.check_output(['mariadb', '--protocol=socket', '-u', 'root', '-N', '-e', 'SHOW TABLES FROM dvwa'], text=True).splitlines()
    if not tables:
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        page = opener.open('http://127.0.0.1/dvwa/setup.php', timeout=15).read().decode(errors='replace')
        parser = TokenParser(); parser.feed(page)
        if not parser.value: raise RuntimeError('DVWA setup CSRF token not found; inspect /dvwa/setup.php')
        data = urllib.parse.urlencode({'create_db': 'Create / Reset Database', 'user_token': parser.value}).encode()
        opener.open('http://127.0.0.1/dvwa/setup.php', data=data, timeout=30).read()
        tables = subprocess.check_output(['mariadb', '--protocol=socket', '-u', 'root', '-N', '-e', 'SHOW TABLES FROM dvwa'], text=True).splitlines()
        if 'users' not in tables: raise RuntimeError('DVWA did not create its users table; inspect Apache/PHP error log')
    print('DVWA database present; existing non-empty data was not reset.', flush=True)
    wazuh = Path('/var/ossec/etc/ossec.conf')
    original = wazuh.read_bytes()
    updated = agent_conf(original.decode('utf-8-sig')).encode()
    if updated != original:
        stat = wazuh.stat()
        try:
            wazuh.write_bytes(updated); os.chmod(wazuh, stat.st_mode & 0o777); os.chown(wazuh, stat.st_uid, stat.st_gid)
            run(['/var/ossec/bin/wazuh-agentd', '-t'])
            run(['/var/ossec/bin/wazuh-logcollector', '-t'])
            run(['/var/ossec/bin/wazuh-control', 'restart'])
        except BaseException:
            wazuh.write_bytes(original)
            run(['/var/ossec/bin/wazuh-control', 'restart'])
            raise
    bashrc = Path('/root/.bashrc')
    original_bash = bashrc.read_text() if bashrc.exists() else ''
    bashrc.write_text(startup_conf(original_bash))
    try:
        run(['bash', '-n', str(bashrc)])
    except BaseException:
        bashrc.write_text(original_bash)
        raise
    health = urllib.request.urlopen('http://127.0.0.1/soc-lab-health', timeout=10).read().decode().strip()
    if health != 'SOC_WEB_OK': raise RuntimeError('Unexpected health response')
    response = urllib.request.urlopen('http://127.0.0.1/dvwa/login.php', timeout=10)
    if response.status != 200: raise RuntimeError('DVWA login unavailable')
    STATE.write_text(json.dumps({'complete': True, 'dvwa_commit': commit, 'lab_cidr': cidr,
        'urls': ['/soc-lab-health', '/dvwa/login.php'],
        'logs': ['/var/log/apache2/soc-lab-access.log', '/var/log/apache2/soc-lab-requests.tsv', '/var/log/apache2/error.log'],
        'credentials': 'DVWA default lab login: admin / password'}, indent=2))
    print('WEB_LAB_READY', flush=True)
    print(STATE.read_text(), flush=True)


if __name__ == '__main__': main()
