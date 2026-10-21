"""Bounded DVWA GET load from Kali: baseline, flood and recovery.

No proxy, redirect, login, exploit payload, form submission or infinite loop.
Results are operator evidence; the detector independently reads Apache logs.
"""
import argparse
from collections import Counter
import concurrent.futures
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import threading
import time

PATHS=('/dvwa/login.php','/dvwa/','/dvwa/index.php')

def target_ip(value):
    ip=ipaddress.IPv4Address(value)
    if not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('Use the RFC1918 IPv4 of the isolated lab endpoint')
    return str(ip)

def validate(phase,requests,rate,concurrency,timeout,path):
    if phase not in ('baseline','flood','recovery') or path not in PATHS:raise ValueError('Invalid phase or fixed DVWA path')
    if type(requests) is not int or not 1<=requests<=1000:raise ValueError('Requests must be 1..1000')
    if type(concurrency) is not int or not 1<=concurrency<=16:raise ValueError('Concurrency must be 1..16')
    if isinstance(rate,bool) or not math.isfinite(rate) or not .5<=rate<=100:raise ValueError('Rate must be .5..100 starts/s')
    if isinstance(timeout,bool) or not math.isfinite(timeout) or not .2<=timeout<=3:raise ValueError('Timeout must be .2..3 seconds')
    if requests/rate>20:raise ValueError('Each phase must fit at most 20 seconds of scheduled starts')
    if phase!='flood' and (rate>2 or concurrency!=1 or requests>30):
        raise ValueError('Baseline/recovery require <=2 starts/s, one connection and <=30 requests')

def request(target,path,timeout):
    start=time.monotonic();conn=http.client.HTTPConnection(target,80,timeout=timeout);timer=None;active=None
    def abort():
        try:active.shutdown(socket.SHUT_RDWR)
        except OSError:pass
    try:
        conn.connect();active=conn.sock
        timer=threading.Timer(max(.01,timeout-(time.monotonic()-start)),abort);timer.daemon=True;timer.start()
        conn.request('GET',path,headers={'Host':target,'Connection':'close','User-Agent':'SOC-Lab-DVWA-Load/0.4.12'})
        response=conn.getresponse();body=response.read(65537)
        outcome=str(response.status) if len(body)<=65536 else 'response_limit'
        return dict(outcome=outcome,latency_ms=round((time.monotonic()-start)*1000,3))
    except (OSError,http.client.HTTPException):
        return dict(outcome='timeout_or_transport_error',latency_ms=round((time.monotonic()-start)*1000,3))
    finally:
        if timer:timer.cancel()
        conn.close()

def run(target,phase,requests,rate,concurrency,timeout,path,worker=request):
    target=target_ip(target);validate(phase,requests,rate,concurrency,timeout,path)
    started=time.monotonic();deadline=started+min(25,requests/rate+timeout+2);next_start=started
    pending=set();values=[];sent=0;last_print=started
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        while sent<requests and time.monotonic()<deadline:
            done={f for f in pending if f.done()}
            values.extend(f.result() for f in done);pending-=done
            if len(pending)>=concurrency:
                done,_=concurrent.futures.wait(pending,timeout=.1,return_when=concurrent.futures.FIRST_COMPLETED)
                values.extend(f.result() for f in done);pending-=done;continue
            time.sleep(max(0,next_start-time.monotonic()))
            if time.monotonic()>=deadline:break
            pending.add(pool.submit(worker,target,path,timeout));sent+=1
            next_start=time.monotonic()+1/rate  # No catch-up burst after a slow response.
            if time.monotonic()-last_print>=1:
                print(f'[{phase.upper()}] sent={sent}/{requests} completed={len(values)} active<={len(pending)}',flush=True);last_print=time.monotonic()
        values.extend(f.result() for f in concurrent.futures.as_completed(pending))
    counts=dict(Counter(v['outcome'] for v in values));latencies=sorted(v['latency_ms'] for v in values)
    report=dict(format='soc-dvwa-web-load/0.1',phase=phase,target_ip=target,http_path=path,http_method='GET',
        requested=requests,started=sent,completed=len(values),configured_max_rate=rate,configured_max_concurrency=concurrency,
        timeout_seconds=timeout,elapsed_seconds=round(time.monotonic()-started,3),outcome_counts=counts,
        client_p50_ms=latencies[max(0,math.ceil(len(latencies)*.5)-1)] if latencies else None,
        client_p95_ms=latencies[max(0,math.ceil(len(latencies)*.95)-1)] if latencies else None,
        phase_completed=sent==requests,credentials_saved=False,cookies_saved=False,followed_redirects=False,
        dos_success_proven=False,training_label=None,
        note='Client metrics are operator evidence, not AI labels or proof of server impact')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('baseline','flood','recovery'))
    p.add_argument('--target',default='172.20.0.3');p.add_argument('--path',choices=PATHS,default='/dvwa/login.php')
    p.add_argument('--requests',type=int);p.add_argument('--rate',type=float);p.add_argument('--concurrency',type=int)
    p.add_argument('--timeout',type=float,default=2);p.add_argument('--output',type=Path);a=p.parse_args()
    if a.output and a.output.exists():p.error('Choose a new local report path')
    try:
        flood=a.phase=='flood'
        r=run(a.target,a.phase,a.requests if a.requests is not None else 400 if flood else 20,
              a.rate if a.rate is not None else 40 if flood else 1,
              a.concurrency if a.concurrency is not None else 8 if flood else 1,a.timeout,a.path)
        if a.output:
            fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:json.dump(r,f,indent=2)
        print(json.dumps(r,indent=2));good=r['phase_completed']
        if not flood:good &= all(k.isdecimal() and 200<=int(k)<400 for k in r['outcome_counts'])
        return 0 if good else 2
    except KeyboardInterrupt:print('DVWA_LOAD_STOPPED: operator interrupted; inspect server logs and last progress counters.');return 130
    except (ValueError,OSError) as e:print('DVWA_LOAD_INCOMPLETE:',e);return 2
if __name__=='__main__':raise SystemExit(main())
