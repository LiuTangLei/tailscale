#!/usr/bin/env python3
"""Compile QUIC-IP and host integration for the upstream platform matrix.

Evidence records compile-only status, never device/runtime compatibility.
Outputs are kept outside source. Split runs with --targets when time is bounded.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CORE = ['./wgengine', './wgengine/quicip', './wgengine/wgtransport/quicbind', './ipn/ipnlocal', './tsnet']
TARGETS = {}
for arch in ('amd64','386','arm64','mips','mipsle','mips64','mips64le','riscv64','loong64','ppc64le','s390x'):
    TARGETS['linux/'+arch] = {'GOOS':'linux','GOARCH':arch}
for arm in ('5','6','7'):
    TARGETS['linux/arm'+arm] = {'GOOS':'linux','GOARCH':'arm','GOARM':arm}
TARGETS['linux/geode'] = {'GOOS':'linux','GOARCH':'386','GO386':'softfloat'}
for system, arches in [('windows',('386','amd64','arm64')),('darwin',('amd64','arm64')),('freebsd',('amd64','arm64')),('openbsd',('amd64','arm64')),('android',('386','amd64','arm','arm64')),('ios',('amd64','arm64'))]:
    for arch in arches: TARGETS[system+'/'+arch] = {'GOOS':system,'GOARCH':arch}
TARGETS['tvos/arm64'] = {'GOOS':'ios','GOARCH':'arm64'}
for system, arch in [('plan9','amd64'),('aix','ppc64'),('solaris','amd64'),('illumos','amd64'),('js','wasm')]:
    TARGETS[system+'/'+arch] = {'GOOS':system,'GOARCH':arch}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--targets',default=','.join(n for n in TARGETS if not n.startswith('tvos/')))
    p.add_argument('--native-sdk',action='store_true',help='link the lab main with Apple/Android SDKs; not app packaging or device verification')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--jobs',type=int,default=2)
    p.add_argument('--timeout',type=int,default=90)
    p.add_argument('--tags',default='')
    p.add_argument('--stock-quic',action='store_true',help='compile upstream queue rather than distribution overlay')
    a=p.parse_args()
    names=a.targets.split(',')
    if any(n not in TARGETS for n in names): p.error('unknown target')
    if not 1 <= a.jobs <= 4: p.error('jobs must be 1..4')
    a.output.mkdir(parents=True,exist_ok=True)
    commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    dirty=bool(subprocess.check_output(['git','status','--porcelain'],text=True).strip())
    overlay = None
    if not a.stock_quic:
        overlay = a.output.resolve() / 'queue-overlay.json'
        subprocess.run(['go','run','./cmd/quic-overlay','-output',str(overlay)],check=True)
    def one(name):
        env=os.environ.copy();env.update(TARGETS[name]);env.update({'CGO_ENABLED':'0','GOMAXPROCS':'3'})
        for k in ('GOARM','GO386','GOAMD64','GOMIPS','GOMIPS64'):
            if k not in TARGETS[name]: env.pop(k,None)
        packages=CORE.copy()
        if name.startswith(('plan9/','aix/','solaris/','illumos/')): packages=['./cmd/tailscale','./cmd/tailscaled']
        if name=='js/wasm': packages=['./cmd/tsconnect/wasm','./cmd/tailscale/cli']
        cmd=['go','build','-mod=readonly','-p=3']
        native_sdk = a.native_sdk and name.startswith(('ios/','tvos/','android/'))
        if name.startswith('tvos/') and not native_sdk:
            raise ValueError('tvOS must be checked with --native-sdk; GOOS=ios alone is not a tvOS link check')
        if native_sdk:
            env['CGO_ENABLED']='1'
            packages=['./cmd/quic-mobilecheck']
            output=a.output.resolve()/('lib-'+name.replace('/','-'))
            if name.startswith(('ios/','tvos/')):
                sdk_name='appletvos' if name.startswith('tvos/') else 'iphonesimulator' if name.endswith('/amd64') else 'iphoneos'
                sdk=subprocess.check_output(['xcrun','--sdk',sdk_name,'--show-sdk-path'],text=True).strip()
                env['CC']=subprocess.check_output(['xcrun','--sdk',sdk_name,'--find','clang'],text=True).strip()
                arch='x86_64' if env['GOARCH']=='amd64' else 'arm64'
                target=arch+'-apple-'+('tvos17.0' if sdk_name=='appletvos' else 'ios17.0-simulator' if sdk_name=='iphonesimulator' else 'ios17.0')
                env.update({'SDKROOT':sdk,'CGO_CFLAGS':'-isysroot '+sdk+' -target '+target,'CGO_LDFLAGS':'-isysroot '+sdk+' -target '+target})
                cmd+=['-buildmode=c-archive','-o',str(output)+'.a']
            else:
                ndk=Path.home()/'Library/Android/sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/darwin-x86_64/bin'
                triples={'arm64':'aarch64-linux-android','arm':'armv7a-linux-androideabi','amd64':'x86_64-linux-android','386':'i686-linux-android'}
                env['CC']=str(ndk/(triples[env['GOARCH']]+'26-clang'))
                cmd+=['-buildmode=c-shared','-o',str(output)+'.so']
        tags = a.tags
        if overlay:
            cmd += ['-modfile',str(overlay)+'.mod','-overlay',str(overlay)]
            tags = ','.join(x for x in (tags,'ts_http3_queue_overlay') if x)
        if tags: cmd += ['-tags',tags]
        cmd+=packages
        start=time.monotonic()
        proc=subprocess.Popen(cmd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            out,_=proc.communicate(timeout=a.timeout)
            status='PASS' if proc.returncode==0 else 'FAIL'
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGTERM)
            try: out,_=proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);out,_=proc.communicate()
            status='TIMEOUT'
        item={'target':name,'status':status,'runtime_verified':False,'kind':('native SDK link smoke via mobile ABI fixture (not app packaging/runtime)' if native_sdk else 'upstream auxiliary target regression' if name.startswith(('plan9/','aix/','solaris/','illumos/','js/')) else 'VPN Go core/package compile (no app signing/link/runtime)'),
              'env':{k:env[k] for k in ('GOOS','GOARCH','GOARM','GO386','CGO_ENABLED','CC','SDKROOT','CGO_CFLAGS','CGO_LDFLAGS') if k in env},
              'command':cmd,'seconds':round(time.monotonic()-start,3),'exit':proc.returncode,'log':name.replace('/','-')+'.log'}
        (a.output/item['log']).write_text(out)
        print(name,status,item['seconds'],out[-600:] if status!='PASS' else '',flush=True)
        return item
    results=[]
    def save():
        evidence={'commit':commit,'dirty':dirty,'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'all_compile_passed':bool(results) and all(x['status']=='PASS' for x in results),'results':results}
        (a.output/'matrix.json').write_text(json.dumps(evidence,indent=2)+'\n')
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for f in concurrent.futures.as_completed([ex.submit(one,n) for n in names]): results.append(f.result());save()
    save()
    if any(x['status']!='PASS' for x in results): raise SystemExit(1)

if __name__=='__main__': main()
