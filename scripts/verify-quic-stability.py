#!/usr/bin/env python3
"""Validate explicit final WAN runs, not the success flag of a partial benchmark.
This writes evidence outside the source tree; it does not publish a release.
"""
from __future__ import annotations
import argparse,json,pathlib,statistics


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=pathlib.Path,required=True)
    p.add_argument('--reports',type=pathlib.Path,nargs='+',required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--minimum-mbps',type=float,default=200)
    a=p.parse_args();build=json.loads(a.build.read_text())
    failures=[];rows=[]
    if build.get('quic_dirty'):failures.append('QUIC library build was dirty')
    for path in a.reports:
        d=json.loads(path.read_text())
        if d.get('passed') is not True or d.get('cleanup_errors') or not d.get('hosts'):
            failures.append(str(path)+': incomplete/failed run or cleanup')
        if d.get('source_dirty') or d.get('source_commit')!=build.get('source'):
            failures.append(str(path)+': unverified Tailscale source')
        if d.get('linux_sha256')!=build['files'].get('wgcompat-lab-linux-amd64'):
            failures.append(str(path)+': binary SHA mismatch')
        for h in d.get('hosts',[]):
            if h.get('baseline')!=h.get('after'):failures.append(str(path)+': production service changed')
        for phase in d.get('phases',[]):
            samples=phase.get('kernel_iperf',[])
            if len(samples)<4:failures.append(str(path)+': insufficient repeat samples')
            for s in samples:
                if s.get('failed') or not s.get('session_reused') or s.get('omitted_seconds')!=0:
                    failures.append(str(path)+': failed/reconnected/omitted benchmark')
                if s.get('receiver_mbps',0)<a.minimum_mbps:
                    failures.append(str(path)+': throughput below gate')
                rows.append({'report':path.name,'mode':phase['variant'],'direction':s['direction'],'round':s['round'],
                    'flows':s['flows'],'idle_seconds':s['idle_before_seconds'],'receiver_mbps':s['receiver_mbps'],
                    'wall_lower_bound_mbps':s['receiver_wall_lower_bound_mbps'],'session_reused':s['session_reused']})
            for host,stats in phase.get('final_transport',{}).items():
                if stats.get('connection_stats',{}).get('CongestionControl')!='bbr-v1' or stats.get('wireguard_encryption') is not False:
                    failures.append(str(path)+': actual carrier/controller mismatch')
                if stats.get('connections')!=phase['transport'][host].get('connections'):
                    failures.append(str(path)+': session recreated during repeated test')
    summary={'scope':'isolated SG/J kernel-TUN WAN gate, not all-platform runtime or production QUIC deployment',
             'passed':not failures and bool(rows),'failures':failures,'build':build,
             'sample_count':len(rows),'minimum_receiver_mbps':min((r['receiver_mbps'] for r in rows),default=0),
             'median_receiver_mbps':statistics.median([r['receiver_mbps'] for r in rows]) if rows else 0,
             'minimum_wall_lower_bound_mbps':min((r['wall_lower_bound_mbps'] for r in rows),default=0),'samples':rows}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('build','samples')},indent=2))
    for r in rows:print(r['mode'],r['direction'],r['round'],round(r['receiver_mbps'],2),'wall',round(r['wall_lower_bound_mbps'],2))
    if not summary['passed']:raise SystemExit(1)
if __name__=='__main__':main()
