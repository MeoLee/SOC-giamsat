"""Private-lab HTTP load: 100 requests, <=20 starts/s, <=4 concurrent, 2s timeout."""
import concurrent.futures
import ipaddress
import json
import sys
import time
import threading
import urllib.error
import urllib.request


def run(target):
    ip=ipaddress.ip_address(target)
    if ip.version!=4 or not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('RFC1918 lab target required')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    started=time.monotonic(); lock=threading.Lock(); next_start=[started]
    def one():
        with lock:
            delay=max(0,next_start[0]-time.monotonic())
            if time.monotonic()+delay-started>10:return 'not_started_deadline'
            time.sleep(delay);next_start[0]=time.monotonic()+.05
        try:
            with opener.open('http://'+target+'/soc-lab-health',timeout=2) as r:
                r.read(4096);return r.status
        except urllib.error.HTTPError as e:return e.code
        except (OSError,urllib.error.URLError):return 'transport_error'
    futures=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for _ in range(100):
            futures.append(pool.submit(one))
    values=[f.result() for f in futures]
    from collections import Counter
    report={'requested':sum(v!='not_started_deadline' for v in values),'scheduled':len(values),'status_counts':dict(Counter(map(str,values))),
        'max_rate':20,'max_concurrency':4,'elapsed_seconds':round(time.monotonic()-started,3),
        'dos_success_proven':False,'training_label':None}
    print(json.dumps(report));return 2 if 'transport_error' in values or 'not_started_deadline' in values or len(values)!=100 else 0


if __name__=='__main__':raise SystemExit(run(sys.argv[1]))
