#!/usr/bin/env python3
"""Bounded within-session driver for the isolated kernel-TUN parity tests.

No production service or firewall mutation. Target addresses are supplied at
runtime and never stored in this source. Own process/log files survive a short
MCP command timeout so the operator can collect final results and cleanup.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def save(path: Path, value: dict) -> None:
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['start', 'worker', 'status'])
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--targets', help='JSON mapping label to {host,address,hostname,host_key_alias?}')
    p.add_argument('--pairs', default='')
    p.add_argument('--local-binary', type=Path)
    p.add_argument('--linux-binary', type=Path)
    p.add_argument('--binary-source', default='')
    p.add_argument('--rounds', type=int, default=3)
    p.add_argument('--seconds', type=int, default=10)
    p.add_argument('--flows', default='4')
    p.add_argument('--mbps', type=int, default=500)
    p.add_argument('--variants', default='native,http3-ip-magicsock')
    p.add_argument('--cpu-profile', action='store_true', help='diagnostic sample, not performance acceptance')
    a = p.parse_args()
    out = a.output.resolve()
    if Path.cwd().resolve() == out or Path.cwd().resolve() in out.parents:
        p.error('test output must be outside source checkout')
    statefile = out/'driver.json'
    if a.action == 'status':
        if not statefile.exists():
            p.error('no test driver state')
        print(statefile.read_text())
        return
    if not a.targets or not a.local_binary or not a.linux_binary:
        p.error('targets and both binaries are required')
    targets = json.loads(a.targets)
    pairs = [v.split(':') for v in a.pairs.split(',') if v]
    if not pairs or len(pairs)>6 or any(len(v)!=2 or v[0]==v[1] or any(n not in targets for n in v) for v in pairs):
        p.error('one to six explicit distinct-node pairs are required')
    if not 1<=a.rounds<=3 or not 3<=a.seconds<=30 or not 1<=a.mbps<=500:
        p.error('bounded runtime/rate required')
    for b in (a.local_binary, a.linux_binary):
        if not b.is_file(): p.error('missing test binary')
    out.mkdir(parents=True,exist_ok=True)
    if a.action == 'start':
        if statefile.exists(): p.error('refuse to overlap/overwrite an existing run directory')
        command = [sys.executable, str(Path(__file__).resolve()), 'worker', *sys.argv[2:]]
        with (out/'driver.log').open('w') as log:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        print(json.dumps({'pid':proc.pid,'output':str(out),'state':str(statefile)}))
        return
    state = {'pid':os.getpid(), 'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),
             'binary_source':a.binary_source, 'linux_sha256':hashlib.sha256(a.linux_binary.read_bytes()).hexdigest(),
             'status':'running','runs':[], 'passed':False}
    save(statefile,state)
    current = None
    def stop(signum, frame):
        if current and current.poll() is None:
            current.terminate()
        raise InterruptedError('test driver interrupted')
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    try:
        for i,(left,right) in enumerate(pairs):
            name=left+'-'+right
            result=out/(name+'.json')
            logpath=out/(name+'.log')
            command=[sys.executable,str(Path(__file__).with_name('quicwg-remote.py')),
                '--local-binary',str(a.local_binary.resolve()),'--linux-binary',str(a.linux_binary.resolve()),
                '--variants',a.variants,'--auto-trust','--private-stun','--private-origins','--kernel-iperf',
                '--kernel-seconds',str(a.seconds),'--kernel-flows',a.flows,'--kernel-mbps',str(a.mbps),
                '--rounds',str(a.rounds),'--kernel-idle','2','--latency-samples','3','--ipv6-proof','--output',str(result)]
            if a.cpu_profile: command.append('--kernel-cpu-profile')
            for prefix,node in [('a',left),('b',right)]:
                t=targets[node]
                command += ['--'+prefix+'-host',t['host'],'--'+prefix+'-address',t['address'],
                            '--'+prefix+'-hostname',t['hostname'],'--'+prefix+'-name',node]
                if t.get('host_key_alias'):command += ['--'+prefix+'-host-key-alias',t['host_key_alias']]
            entry={'pair':name,'started':time.time(),'status':'running','result':str(result),'log':str(logpath)}
            state['runs'].append(entry);save(statefile,state)
            with logpath.open('w') as log:
                current=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
                try: code=current.wait(timeout=2400)
                except subprocess.TimeoutExpired:
                    current.terminate()
                    try: code=current.wait(timeout=90)
                    except subprocess.TimeoutExpired:
                        current.kill();code=current.wait(timeout=5)
                    entry['timeout']=True
            entry.update(returncode=code,seconds=round(time.time()-entry['started'],2),status='finished')
            if result.exists():
                d=json.loads(result.read_text());entry['passed']=bool(d.get('passed')) and not d.get('cleanup_errors')
                entry['error']=d.get('error');entry['cleanup_errors']=d.get('cleanup_errors')
                entry['samples']=[{'mode':phase['variant'],'direction':x['direction'],'flows':x['flows'],
                    'round':x['round'],'mbps':x.get('receiver_mbps'),'session_reused':x.get('session_reused')}
                    for phase in d.get('phases',[]) for x in phase.get('kernel_iperf',[])]
            else: entry['passed']=False
            save(statefile,state)
            print('FINISHED',name,entry.get('passed'),entry.get('error'),flush=True)
            # Do not pile new tests on top of a failed cleanup / hanging test.
            if entry.get('timeout') or entry.get('cleanup_errors'):
                raise RuntimeError('cleanup/timeout requires operator inspection')
        state['passed']=all(r.get('passed') for r in state['runs'])
        state['status']='finished'
    except Exception as exc:
        state.update(status='failed',error=str(exc))
    finally:
        if current and current.poll() is None:
            current.terminate()
            try:current.wait(timeout=90)
            except subprocess.TimeoutExpired:current.kill();current.wait()
        state['finished_at']=dt.datetime.now(dt.timezone.utc).isoformat();save(statefile,state)
    print(json.dumps({'status':state['status'],'passed':state['passed'],'output':str(out)}))
    if not state['passed']:raise SystemExit(1)

if __name__=='__main__':main()
