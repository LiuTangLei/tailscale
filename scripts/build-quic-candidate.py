#!/usr/bin/env python3
"""Build a test-only local QUIC dependency without editing go.mod or module cache.
Release builds must use the published module instead of this helper.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shlex, shutil, subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--quic-root',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--platforms',default='darwin/arm64,linux/amd64')
    a=p.parse_args()
    root=pathlib.Path.cwd();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    quic=a.quic_root.resolve()
    if not (quic/'go.mod').is_file():raise SystemExit('missing QUIC module')
    mod=out/'candidate.mod'
    shutil.copyfile(root/'go.mod',mod);shutil.copyfile(root/'go.sum',out/'candidate.sum')
    subprocess.run(['go','mod','edit','-modfile='+str(mod),'-replace=github.com/quic-go/quic-go='+str(quic)],check=True)
    env=os.environ.copy();env.update(CGO_ENABLED='0')
    host=subprocess.check_output(['go','env','GOHOSTOS','GOHOSTARCH'],text=True).splitlines()
    vars_text=subprocess.check_output(['go','run','./cmd/mkversion'],env={**env,'GOOS':host[0],'GOARCH':host[1]},text=True)
    vals={}
    for line in vars_text.splitlines():
        if '=' in line:
            key,val=line.split('=',1);parts=shlex.split(val);vals[key]=parts[0] if parts else ''
    flags='-X tailscale.com/version.longStamp='+vals['VERSION_LONG']+' -X tailscale.com/version.shortStamp='+vals['VERSION_SHORT']
    results={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
             'quic_source':subprocess.check_output(['git','-C',str(quic),'rev-parse','HEAD'],text=True).strip(),
             'quic_dirty':bool(subprocess.check_output(['git','-C',str(quic),'status','--porcelain'],text=True).strip()),'files':{}}
    for platform in a.platforms.split(','):
        goos,arch=platform.split('/')
        for name in ('tailscale','wgcompat-lab'):
            target=out/(name+'-'+goos+'-'+arch)
            cmd=['go','build','-mod=readonly','-modfile='+str(mod),'-tags=ts_http3_queue_overlay','-trimpath','-ldflags',flags,'-o',str(target),'./cmd/'+name]
            subprocess.run(cmd,check=True,env={**env,'GOOS':goos,'GOARCH':arch})
            results['files'][target.name]=hashlib.sha256(target.read_bytes()).hexdigest()
            print('BUILT',target.name,flush=True)
    (out/'build.json').write_text(json.dumps(results,indent=2)+'\n')
if __name__=='__main__':main()
