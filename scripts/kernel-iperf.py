#!/usr/bin/env python3
"""Kernel TCP/UDP benchmark helpers for the isolated QUIC lab.

Each host already has a private qbench-* network namespace and a real TUN FD
owned by the test engine in the host namespace. No veth/NAT/default-route or
production firewall change is needed. iperf traffic has exactly one path: TUN.
"""
from __future__ import annotations
import json
import shlex
import time


def configure(nodes, remote):
    for i, node in enumerate(nodes):
        ns = node['kernel_ns']
        commands = [
            ['ip', '-n', ns, 'address', 'replace', node['test_ip'] + '/32', 'dev', 'qbench0'],
            ['ip', '-n', ns, 'link', 'set', 'qbench0', 'mtu', '1280', 'up'],
            ['ip', '-n', ns, 'route', 'replace', nodes[i ^ 1]['test_ip'] + '/32', 'dev', 'qbench0'],
        ]
        if node.get('test_ipv6') and nodes[i ^ 1].get('test_ipv6'):
            commands += [
                ['ip', '-n', ns, '-6', 'address', 'replace', node['test_ipv6'] + '/128', 'dev', 'qbench0', 'nodad'],
                ['ip', '-n', ns, '-6', 'route', 'replace', nodes[i ^ 1]['test_ipv6'] + '/128', 'dev', 'qbench0'],
            ]
        for command in commands:
            remote(node, shlex.join(command))
        # Namespace must have NO physical default route or inherited production
        # Tailscale device. A passing transfer cannot have bypassed the test TUN.
        route = remote(node, shlex.join(['ip', '-n', ns, 'route', 'get', nodes[i ^ 1]['test_ip']])).stdout
        links = json.loads(remote(node, shlex.join(['ip', '-n', ns, '-j', 'link', 'show'])).stdout)
        if 'dev qbench0' not in route or {x['ifname'] for x in links} != {'lo', 'qbench0'}:
            raise RuntimeError('kernel benchmark namespace has unexpected network paths')
        node['kernel_path'] = {'route': route.strip(), 'interfaces': [x['ifname'] for x in links]}


def benchmark(nodes, args, phase, checkpoint, remote, api, ident, index):
    def state():
        return {n['name']: {'process': api(n, '/metrics'), 'quic': api(n, '/quic'),
                 'tun': json.loads(remote(n, shlex.join(['ip', '-n', n['kernel_ns'], '-s', '-j', 'link', 'show', 'dev', 'qbench0'])).stdout)} for n in nodes}
    server = nodes[0]
    client = nodes[1]
    unit = f'qbench-iperf-{ident}-{index}'
    command = ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
               '--property=RuntimeMaxSec=600', '--property=TimeoutStopSec=5',
               'ip', 'netns', 'exec', server['kernel_ns'], 'iperf3', '-s', '-B', server['test_ip'], '-p', '18530']
    remote(server, shlex.join(command))
    server.setdefault('aux_units', []).append(unit)
    try:
        for _ in range(30):
            listening = remote(server, shlex.join(['ip','netns','exec',server['kernel_ns'],'ss','-H','-lnt','sport = :18530'])).stdout
            if listening.strip(): break
            time.sleep(0.1)
        else: raise RuntimeError('isolated iperf listener did not start')
        phase['kernel_paths'] = {n['name']:n['kernel_path'] for n in nodes}
        phase['kernel_iperf'] = []
        directions = (True, False) if args.kernel_reverse_first else (False, True)
        for round_no in range(1, args.rounds + 1):
            for reverse in directions:
                direction = f"{server['name']} -> {client['name']}" if reverse else f"{client['name']} -> {server['name']}"
                for flows in args.kernel_flows:
                    if args.kernel_idle:
                        time.sleep(args.kernel_idle)
                    before = state()
                    cmd = ['ip','netns','exec',client['kernel_ns'],'iperf3','-c',server['test_ip'],'-p','18530',
                           '-P',str(flows),'-t',str(args.kernel_seconds),'-O',str(args.kernel_omit),'-J','--get-server-output',
                           '-b',str(int(args.kernel_mbps*1_000_000/flows))]
                    if reverse: cmd.append('-R')
                    if args.kernel_udp: cmd += ['-u','-l','1100']
                    started = time.monotonic()
                    p = remote(client, shlex.join(cmd), check=False, timeout=args.kernel_seconds + 25)
                    elapsed = time.monotonic() - started
                    try: doc = json.loads(p.stdout)
                    except ValueError: raise RuntimeError('iperf returned invalid JSON: '+p.stderr[-500:])
                    if p.returncode or doc.get('error'):
                        phase['kernel_iperf'].append({'direction':direction,'round':round_no,'flows':flows,'failed':True,'iperf':doc})
                        checkpoint()
                        raise RuntimeError('kernel iperf failed: '+str(doc.get('error',p.stderr[-500:])))
                    after = state()
                    receiver = doc.get('end',{}).get('sum_received') or doc.get('end',{}).get('sum')
                    if args.kernel_udp:
                        streams = doc.get('end',{}).get('streams',[])
                        udp = [s['udp'] for s in streams if 'udp' in s]
                        if udp:
                            receiver = dict(receiver or {})
                            receiver.update(lost_packets=sum(s.get('lost_packets',0) for s in udp),packets=sum(s.get('packets',0) for s in udp))
                    if not receiver or receiver.get('bytes',0)<=0: raise RuntimeError('no received payload in iperf output')
                    mbps = receiver['bits_per_second']/1_000_000
                    item = {'direction':direction,'round':round_no,'flows':flows,'receiver_mbps':mbps,
                            'offered_total_mbps':args.kernel_mbps,'protocol':'udp' if args.kernel_udp else 'tcp',
                            'omitted_seconds':args.kernel_omit, 'idle_before_seconds':args.kernel_idle,
                            'receiver_wall_lower_bound_mbps':receiver['bytes']*8/elapsed/1_000_000,
                            'wall_seconds':elapsed,'before':before,'after':after,'iperf':doc}
                    if phase['variant'] != 'native':
                        item['session_reused'] = all(
                            before[n['name']]['quic'].get('connections') == after[n['name']]['quic'].get('connections')
                            and before[n['name']]['quic'].get('handshake_errors') == after[n['name']]['quic'].get('handshake_errors')
                            for n in nodes)
                    phase['kernel_iperf'].append(item)
                    checkpoint()
                    cpu = {n['name']: round(after[n['name']]['process']['cpu_total_seconds'] - before[n['name']]['process']['cpu_total_seconds'],3) for n in nodes}
                    print(f"KERNEL {phase['variant']} {direction} P={flows} round={round_no}: receiver={mbps:.2f} Mbps CPU={cpu}",flush=True)
    finally:
        # Preserve the original benchmark exception; outer cleanup also owns
        # this exact unit if management is temporarily slow under CPU load.
        try:
            remote(server, 'systemctl stop '+shlex.quote(unit),check=False,timeout=45)
        except Exception as exc:
            phase.setdefault('cleanup_warnings', []).append(str(exc))
        # The namespace owns the listening address; never a public iperf server.
