#!/usr/bin/env python3
"""Isolated two-host native-vs-QUIC WG tests. Does not replace production tailscaled.
All generated TLS keys stay on their host; only public SPKI pins are exchanged.
"""
from __future__ import annotations
import argparse
import base64
import os
import signal
import fcntl
import re
from urllib.parse import urlsplit
import urllib.request
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("compat", Path(__file__).with_name("wgcompat-remote.py"))
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)
run, remote = compat.run, compat.remote


def api(node, path, *, method='GET', check=True, timeout=10):
    # A localhost SSH forward avoids spawning a remote curl/session for every
    # metric sample. It never exposes the admin API on a public interface.
    if not node.get('admin_local'):
        return compat.api(node, path, method=method, check=check, timeout=timeout)
    req = urllib.request.Request(f"http://127.0.0.1:{node['admin_local']}{path}", method=method, headers={'X-WG-Lab':'1'})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as response:
            return json.load(response)
    except Exception as exc:
        if check: raise RuntimeError(f"{node['name']} {path}: {exc}") from exc
        return None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def browser_smoke(node, temp):
    browser = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    if not browser.is_file(): raise RuntimeError('Chrome binary not available for browser smoke')
    origin = urlsplit(node['h3url'])
    profile = temp / ('chrome-' + node['name'])
    netlog = temp / ('chrome-' + node['name'] + '-netlog.json')
    pin = base64.b64encode(bytes.fromhex(node['identity']['spki_sha256'])).decode()
    before = api(node, '/quic')
    command = [str(browser), '--headless=new', '--disable-gpu', '--disable-extensions', '--disable-background-networking',
               '--no-first-run', '--no-default-browser-check', '--no-proxy-server', '--enable-quic', '--use-mock-keychain',
               '--user-data-dir=' + str(profile), '--log-net-log=' + str(netlog),
               '--ignore-certificate-errors-spki-list=' + pin,
               '--origin-to-force-quic-on=' + origin.netloc,
               '--host-resolver-rules=MAP ' + origin.hostname + ' ' + node['address'],
               '--timeout=15000', '--dump-dom', 'https://' + origin.netloc + '/']
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=35)
    except subprocess.TimeoutExpired:
        timed_out = True
        # macOS may deny group signals when Chrome's sandboxed helpers have
        # different credentials. Terminate only the exact browser child that
        # this invocation created; Chrome tears down its own helper processes.
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=5)
    after = api(node, '/quic')
    passed = not timed_out and proc.returncode == 0 and 'Welcome' in stdout and after.get('http3_public_pages', 0) > before.get('http3_public_pages', 0)
    types, errors = {}, []
    if netlog.is_file():
        try:
            log = json.loads(netlog.read_text())
            names = {value: name for name, value in log.get('constants', {}).get('logEventTypes', {}).items()}
            for event in log.get('events', []):
                name = names.get(event.get('type'), '')
                if 'HTTP3' in name or 'QUIC_SESSION' in name: types[name] = types.get(name, 0) + 1
                params = event.get('params', {})
                if params.get('net_error') or params.get('quic_error'):
                    errors.append({'event': name, 'net_error': params.get('net_error'), 'quic_error': params.get('quic_error')})
        except (ValueError, OSError):
            errors.append({'event': 'incomplete netlog after browser termination'})
    return {'host': node['name'], 'passed': passed, 'timeout': timed_out, 'exit': proc.returncode,
            'page_sha256': hashlib.sha256(stdout.encode()).hexdigest(), 'stderr_tail': stderr[-1500:] if not passed else '',
            'server_http3_requests_delta': after['http3_requests'] - before['http3_requests'],
            'server_http3_public_pages_delta': after.get('http3_public_pages', 0) - before.get('http3_public_pages', 0), 'network_events': types, 'network_errors': errors[-15:],
            'scope': 'isolated Chrome profile; explicit QUIC origin and trust only this temporary test SPKI; not a browser fingerprint equivalence test'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--local-binary", type=Path, required=True)
    p.add_argument("--linux-binary", type=Path, required=True)
    p.add_argument("--managed-cli", type=Path, help="test actual CLI identity/trust/staging and restart, without transport environment overrides")
    p.add_argument("--sg", "--a-host", dest="sg", default="root@sg.yesican.top")
    p.add_argument("--zjg", "--b-host", dest="zjg", default="root@173.249.215.87")
    p.add_argument("--sg-address", "--a-address", dest="sg_address", default="96.9.212.12")
    p.add_argument("--zjg-address", "--b-address", dest="zjg_address", default="173.249.215.87")
    p.add_argument("--a-name", default="sg", help="report label and test-only HTTP authority")
    p.add_argument("--b-name", default="zjg", help="report label and test-only HTTP authority")
    p.add_argument("--a-hostname", default="sg2222", help="expected SSH hostname; mismatch aborts")
    p.add_argument("--a-via", help="optional SSH jump host for host A management only; data-path addresses stay unchanged")
    p.add_argument("--a-host-key-alias", help="existing trusted SSH known_hosts name for host A; does not disable host-key checking")
    p.add_argument("--b-host-key-alias", help="existing trusted SSH known_hosts name for host B; does not disable host-key checking")
    p.add_argument("--b-hostname", default="zjg", help="expected SSH hostname; mismatch aborts")
    p.add_argument("--latency-samples", type=int, default=10, help="encrypted idle RTT samples per direction, 0 disables")
    p.add_argument("--variants", default="native,quic-ip-udp,http3-ip-udp,http3-ip-magicsock")
    p.add_argument("--dev-wg-over-quic", action="store_true", help="requires a ts_dev_wg_over_quic binary")
    p.add_argument("--browser-smoke", action="store_true", help="isolated headless Chrome visit to the HTTP/3 public site (UDP mode)")
    p.add_argument("--profile", choices=["standard", "awg2", "awg3", "awg31"], default="standard")
    p.add_argument("--declared-servers", default="", help="comma-separated test node labels declaring server; empty keeps both ordinary mesh")
    p.add_argument("--private-origins", action="store_true", help="use private .invalid origins and verify they are not sent as TLS SNI")
    p.add_argument("--auto-trust", action="store_true", help="test current H3 Noise node authentication without provisioned peer pins")
    p.add_argument("--mib", type=int, default=8)
    p.add_argument("--parallel", type=int, default=1)
    p.add_argument("--rounds", type=int, default=1)
    p.add_argument("--force-derp", action="store_true")
    p.add_argument("--private-stun", action="store_true", help="run a bounded test STUN responder on host A UDP 42643; no external STUN list needed")
    p.add_argument("--proof-only", action="store_true", help="run encrypted integrity checks without throughput benchmarks")
    p.add_argument("--kernel-iperf", action="store_true", help="Linux-only isolated network namespace + real TUN + kernel iperf; no production routes/firewall changes")
    p.add_argument("--kernel-seconds", type=int, default=15)
    p.add_argument("--kernel-omit", type=int, default=0, help="iperf omitted warmup seconds; zero measures the full transfer without catch-up artifacts")
    p.add_argument("--kernel-idle", type=int, default=0, help="idle the same QUIC session between directions, at most 20 seconds")
    p.add_argument("--kernel-reverse-first", action="store_true", help="start with server-to-client data to detect direction/order bias")
    p.add_argument("--kernel-flows", default="1,4")
    p.add_argument("--kernel-mbps", type=int, default=500, help="bounded aggregate offered load, at most 500 Mbps")
    p.add_argument("--kernel-udp", action="store_true", help="inner UDP offered-load test instead of kernel TCP")
    p.add_argument("--kernel-cpu-profile", action="store_true", help="diagnostic-only bounded CPU profiles; throughput is profiling-affected")
    p.add_argument("--ipv6-proof", action="store_true", help="also verify inner IPv6 TSMP and file transfer")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not 0 <= args.kernel_omit <= 5 or not 0 <= args.kernel_idle <= 20:
        p.error("kernel-omit must be 0..5 and kernel-idle 0..20")
    if args.a_name == args.b_name or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", x) for x in (args.a_name, args.b_name)):
        p.error("node labels must be distinct lowercase DNS labels")
    declared_servers = set(filter(None, args.declared_servers.split(',')))
    if not declared_servers.issubset({args.a_name, args.b_name}):
        p.error("declared-servers contains an unknown test node")
    if declared_servers and args.managed_cli:
        p.error("declaration matrix currently uses isolated environment profiles, not managed CLI setup")
    if not 0 <= args.latency_samples <= 30:
        p.error("latency-samples must be 0..30")
    # Lock canonical test hosts rather than all WAN tests globally. Disjoint
    # pairs may run concurrently; any shared host is serialized, with sorted
    # lock acquisition preventing deadlocks. No remote resources exist yet.
    host_locks = []
    if args.sg_address == args.zjg_address:
        p.error('test endpoints must identify distinct machines')
    for address in sorted((args.sg_address, args.zjg_address)):
        lock_id = hashlib.sha256(address.encode()).hexdigest()[:20]
        lock = open(Path(tempfile.gettempdir()) / ('tailscale-transport-' + lock_id + '.lock'), 'a+')
        deadline = time.monotonic() + 600
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                host_locks.append(lock)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    p.error('another test still owns this host; no remote changes made')
                time.sleep(0.5)
    def interrupted(signum, frame):
        raise RuntimeError(f"test interrupted by signal {signum}; cleaning owned resources")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    variants = args.variants.split(",")
    if not variants or any(v not in ("native", "quic-udp", "quic-magicsock", "quic-ip-udp", "quic-ip-magicsock", "http3-ip-udp", "http3-ip-magicsock") for v in variants):
        p.error("invalid variants")
    if not args.dev_wg_over_quic and any(v in ("quic-udp", "quic-magicsock") for v in variants):
        p.error("WG-over-QUIC is development-only; use native or --dev-wg-over-quic with the build tag")
    if not 1 <= args.mib <= 64 or not 1 <= args.parallel <= 4 or not 1 <= args.rounds <= 3:
        p.error("invalid benchmark limits")
    if args.auto_trust and (args.managed_cli or any(v not in ('native', 'http3-ip-magicsock') for v in variants)):
        p.error('auto-trust fixture supports native/http3-ip-magicsock without managed-cli')
    if args.force_derp and any(v.endswith("-udp") for v in variants):
        p.error("independent UDP mode does not use DERP; test magicsock instead")
    if args.profile != "standard" and any(v.startswith(("quic-ip-", "http3-ip-")) for v in variants):
        p.error("native QUIC IP rejects AWG profiles; use --profile=standard")
    if args.managed_cli and (not args.managed_cli.is_file() or args.profile != "standard" or any(v not in ("native", "quic-ip-magicsock", "http3-ip-magicsock") for v in variants)):
        p.error("managed CLI tests require a real CLI binary, standard profile and native/magicsock modes")
    if args.kernel_iperf:
        try: args.kernel_flows = [int(v) for v in args.kernel_flows.split(',')]
        except ValueError: p.error('kernel-flows must be comma-separated integers')
        if not args.kernel_flows or any(v not in (1,2,4,8) for v in args.kernel_flows) or not 3 <= args.kernel_seconds <= 30 or not 1 <= args.kernel_mbps <= 500:
            p.error('invalid bounded kernel benchmark settings')
        if args.proof_only: p.error('kernel-iperf conflicts with proof-only')
        if args.kernel_seconds * len(args.kernel_flows) * args.rounds * 2 > 360:
            p.error('kernel benchmark exceeds per-mode bounded runtime')
    ident = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    result = {"run": ident, "linux_sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
              "profile": args.profile, "force_derp": args.force_derp, "auto_trust": args.auto_trust,
              "declared_servers": sorted(declared_servers), "private_origins": args.private_origins,
              "nodes": [{"name": args.a_name, "address": args.sg_address}, {"name": args.b_name, "address": args.zjg_address}],
              "source_commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
              "source_dirty": bool(run(["git", "status", "--porcelain"]).stdout.strip()),
              "settings": {"mib_per_stream": args.mib, "parallel": args.parallel, "rounds": args.rounds},
              "phases": [], "passed": False, "cleanup_errors": []}
    nodes, units, processes = [], [], []
    def checkpoint():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.kernel_iperf:
        result['kernel_benchmark'] = {'seconds':args.kernel_seconds,'flows':args.kernel_flows,'aggregate_limit_mbps':args.kernel_mbps,'inner_protocol':'udp' if args.kernel_udp else 'tcp','scope':'same engine and isolated kernel TUN for every mode; no HTTP payload benchmark'}
        kernel_spec = importlib.util.spec_from_file_location('kernel_iperf', Path(__file__).with_name('kernel-iperf.py'))
        kernel = importlib.util.module_from_spec(kernel_spec)
        kernel_spec.loader.exec_module(kernel)
    checkpoint()
    with tempfile.TemporaryDirectory(prefix="quicwg-") as tmp:
        temp = Path(tmp)
        control_port, derp_port = free_port(), free_port()
        log = (temp / "control.log").open("w+")
        cmd = [str(args.local_binary.resolve()), "control", "--listen", f"127.0.0.1:{control_port}",
               "--derp-listen", f"127.0.0.1:{derp_port}"]
        if not args.force_derp:
            cmd += ["--stun-server", f"{args.sg_address}:42643"] if args.private_stun else ["--public-stun"]
        processes.append(subprocess.Popen(cmd, stdout=log, stderr=log))
        try:
            for _ in range(300):
                if processes[0].poll() is not None:
                    log.seek(0)
                    raise RuntimeError("control failed: " + log.read()[-2000:])
                try:
                    with socket.create_connection(("127.0.0.1", control_port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("control startup timeout")
            for name, host, expected, address in [(args.a_name, args.sg, args.a_hostname, args.sg_address), (args.b_name, args.zjg, args.b_hostname, args.zjg_address)]:
                node = {"name": name, "host": host, "address": address, "dir": f"/var/tmp/quicwg-lab-{ident}-{name}",
                        "socket": str(temp / name), "admin": 18441, "admin_local": free_port()}
                ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
                if args.a_via and name == args.a_name:
                    ssh += ["-J", args.a_via]
                host_key_alias = args.a_host_key_alias if name == args.a_name else args.b_host_key_alias
                if host_key_alias:
                    ssh += ["-o", "HostKeyAlias=" + host_key_alias, "-o", "StrictHostKeyChecking=yes"]
                actual = run(ssh + [host, "hostname"]).stdout.strip()
                if actual != expected:
                    raise RuntimeError(f"wrong host: {actual}, expected {expected}")
                tunnel = subprocess.Popen(ssh + ["-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=10", "-M", "-S", node["socket"], "-N",
                    "-R", f"127.0.0.1:{control_port}:127.0.0.1:{control_port}",
                    "-R", f"127.0.0.1:{derp_port}:127.0.0.1:{derp_port}",
                    "-L", f"127.0.0.1:{node['admin_local']}:127.0.0.1:18441", host], stdout=subprocess.DEVNULL, stderr=log)
                processes.append(tunnel)
                # SSH may finish key exchange after ConnectTimeout's TCP phase;
                # a six-second socket wait falsely failed on this real WAN.
                for _ in range(300):
                    if tunnel.poll() is not None:
                        raise RuntimeError(f"SSH tunnel failed: {name}")
                    if Path(node["socket"]).exists():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f"SSH startup timeout: {name}")
                node["ssh"] = ssh + ["-S", node["socket"], host]
                nodes.append(node)
                busy = remote(node, "ss -H -lnt 'sport = :18441'; ss -H -lnu 'sport = :42641'; ss -H -lnu 'sport = :42642'; ss -H -lnt 'sport = :42642'").stdout.strip()
                if args.private_stun and name == args.a_name:
                    busy += remote(node, "ss -H -lnu 'sport = :42643'").stdout.strip()
                if busy:
                    raise RuntimeError(f"test ports are occupied: {name}: {busy}")
                node["baseline"] = remote(node, "systemctl show tailscaled -p MainPID -p ActiveState; tailscale version | head -1", check=False).stdout.strip()
                remote(node, "install -d -m 700 " + shlex.quote(node["dir"]))
                if args.kernel_iperf:
                    remote(node, 'command -v iperf3; test -c /dev/net/tun')
                    ns = f"qbench-{ident}-{name}"
                    remote(node, shlex.join(['ip','netns','add',ns]))
                    node['kernel_ns'] = ns
                    remote(node, shlex.join(['ip','-n',ns,'link','set','lo','up']))
                run(["scp", "-C", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}",
                     str(args.linux_binary.resolve()), f"{host}:{node['dir']}/lab"], timeout=120)
                remote(node, f"chmod 700 {node['dir']}/lab")
                if args.managed_cli:
                    run(["scp", "-C", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}", str(args.managed_cli.resolve()), f"{host}:{node['dir']}/cli"], timeout=120)
                    remote(node, f"chmod 700 {node['dir']}/cli")
                node["identity"] = json.loads(remote(node, shlex.join([node["dir"] + "/lab", "identity", "--dir", node["dir"] + "/tls"])).stdout)

            def stop_current():
                for node in nodes:
                    if node.get("unit"):
                        remote(node, "systemctl stop " + shlex.quote(node["unit"]), check=False, timeout=20)
                        node["unit"] = None

            def start(variant, index, profile):
                for i, node in enumerate(nodes):
                    env = ["TS_NO_LOGS_NO_SUPPORT=true", f"TS_DEBUG_ALWAYS_USE_DERP={'true' if args.force_derp else 'false'}"]
                    if args.managed_cli:
                        pass  # mode and pinned identity come from the daemon-owned profile
                    elif variant == "native":
                        env += ["TS_EXPERIMENTAL_WG_TRANSPORT=native"]
                    else:
                        h3 = variant.startswith("http3-ip-")
                        native_ip = h3 or variant.startswith("quic-ip-")
                        io_mode = variant.removeprefix("http3-ip-" if h3 else "quic-ip-" if native_ip else "quic-")
                        peer = nodes[i ^ 1]
                        peer_cfg = {"public_key": peer["public_key"], "spki_sha256": peer["identity"]["spki_sha256"]}
                        config = {"version": 1, "io": io_mode, "local_public_key": node["public_key"],
                                  "certificate": node["identity"]["certificate"], "private_key": node["identity"]["private_key"],
                                  "initial_packet_size": 1400, "queue_packets": 2048, "peers": [peer_cfg]}
                        if native_ip:
                            config.update({"version": 2, "payload": "ip"})
                        if io_mode == "udp":
                            config["listen"] = "0.0.0.0:42642"
                            peer_cfg["endpoint"] = f"{peer['address']}:42642"
                        if h3:
                            origin_port = 42642 if io_mode == "udp" else 42641
                            config["http3"] = True
                            config["server"] = node['name'] in declared_servers
                            peer_cfg["server"] = peer['name'] in declared_servers
                            suffix = 'invalid' if args.private_origins else 'test'
                            config["http3_url"] = f"https://{node['name']}.{suffix}:{origin_port}/.well-known/masque/ip/*/*/"
                            peer_cfg["http3_url"] = f"https://{peer['name']}.{suffix}:{origin_port}/.well-known/masque/ip/*/*/"
                            node["h3url"] = config["http3_url"]
                            if args.browser_smoke and io_mode == "udp": config["http3_tcp_listen"] = "0.0.0.0:42642"
                        if h3 and args.auto_trust:
                            config['auto_trust'] = True
                            config['peers'] = []
                            config['http3_url'] = f"https://peer-{node['public_key'].removeprefix('nodekey:')[:12]}.invalid/.well-known/masque/ip/*/*/"
                            node['h3url'] = config['http3_url']
                        local_config = temp / f"{node['name']}-config.json"
                        local_config.write_text(json.dumps(config))
                        run(["scp", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}",
                             str(local_config), f"{node['host']}:{node['dir']}/quic.json"])
                        env += [f"TS_EXPERIMENTAL_WG_TRANSPORT={'http3-ip' if h3 else 'quic-ip' if native_ip else 'quic'}", f"TS_EXPERIMENTAL_QUIC_CONFIG={node['dir']}/quic.json"]
                    unit = f"quicwg-{ident}-{node['name']}-{index}"
                    command = ["systemd-run", "--quiet", "--collect", "--unit=" + unit, "--property=RuntimeMaxSec=600", "--property=TimeoutStopSec=15", "--property=Restart=no",
                               "env"] + env + [node["dir"] + "/lab", "node", "--dir", node["dir"] + "/state", "--hostname", "quicwg-" + node["name"],
                                "--control", f"http://127.0.0.1:{control_port}", "--listen", "127.0.0.1:18441", "--port", "42641", "--profile", profile]
                    if args.kernel_iperf:
                        command += ['--kernel-netns', node['kernel_ns']]
                    if args.managed_cli:
                        command += ["--localapi-socket", node["dir"] + "/state/localapi.sock"]
                    if args.private_stun and node["name"] == args.a_name and not args.force_derp:
                        command += ["--stun-listen", "0.0.0.0:42643"]
                    remote(node, shlex.join(command))
                    node["unit"] = unit
                    units.append((node, unit))
                statuses = []
                for _ in range(75):
                    statuses = [api(n, "/status", check=False, timeout=3) for n in nodes]
                    if all(s and s.get("state") == "Running" and s.get("peers") and s.get("public_key") for s in statuses):
                        return statuses
                    time.sleep(1)
                raise RuntimeError(f"nodes not ready for {variant}: {statuses}")

            def cli(node, *arguments, json_result=False):
                command = [node["dir"] + "/cli", "--socket", node["dir"] + "/state/localapi.sock", "awg"] + list(arguments)
                value = remote(node, shlex.join(command), timeout=25).stdout
                return json.loads(value) if json_result else value

            def stage_managed(variant):
                desired = "native" if variant == "native" else "http3-ip" if variant.startswith("http3") else "quic-ip"
                evidence = {}
                for node in nodes:
                    before = cli(node, "status", "--json", json_result=True)
                    cli(node, "transport", "--yes", desired)
                    after = cli(node, "status", "--json", json_result=True)
                    if after["active_mode"] != before["active_mode"] or after["desired_mode"] != desired:
                        raise RuntimeError("CLI staging incorrectly claimed a live mode switch")
                    evidence[node["name"]] = after
                return evidence

            print("BOOTSTRAP isolated identities", flush=True)
            statuses = start("native", "bootstrap", "standard")
            for i, node in enumerate(nodes):
                node["public_key"] = statuses[i]["public_key"]
                node["test_ip"] = next(x for x in statuses[i]["ips"] if ":" not in x)
                node["test_ipv6"] = next((x for x in statuses[i]["ips"] if ":" in x), None)
            if args.managed_cli:
                cards = [cli(n, "identity", "--init", json_result=True) for n in nodes]
                for i, node in enumerate(nodes):
                    cli(node, "peer", "add", "--yes", json.dumps(cards[i ^ 1], separators=(",", ":")))
                    cli(node, "doctor")
                result["cli_setup"] = stage_managed(variants[0])
                checkpoint()
            stop_current()
            for index, variant in enumerate(variants):
                print(f"START {variant}/{args.profile}", flush=True)
                phase = {"variant": variant, "probes": [], "benchmarks": [], "passed": False}
                result["phases"].append(phase)
                statuses = start(variant, index, args.profile)
                if args.kernel_iperf:
                    kernel.configure(nodes, remote)
                if args.managed_cli:
                    phase["cli_status"] = {n["name"]: cli(n, "status", "--json", json_result=True) for n in nodes}
                    for value in phase["cli_status"].values():
                        expected = "native" if variant == "native" else "http3-ip" if variant.startswith("http3") else "quic-ip"
                        if value["active_mode"] != expected or value["pending_restart"] or value["source"] != "managed":
                            raise RuntimeError("managed profile did not activate on actual restart: " + json.dumps(value))
                    print("CLI mode applied after restart:", variant, flush=True)
                # A declared server can send application data first over an
                # existing connection, but only the nonserver TLS initiator
                # exercises the browser handshake. Establish that connection
                # first, then test both inner data directions independently.
                proof_order = sorted(range(len(nodes)), key=lambda i: nodes[i]['name'] in declared_servers)
                for i in proof_order:
                    node = nodes[i]
                    if statuses[i]["public_key"] != node["public_key"]:
                        raise RuntimeError("persisted test node identity changed")
                    target = nodes[i ^ 1]["test_ip"]
                    proof = api(node, f"/probe?target={target}&size=1048576", method="POST", timeout=65)
                    proof["from"] = node["name"]
                    if proof.get("download", {}).get("bytes") != 1048576 or proof.get("upload", {}).get("bytes") != 1048576:
                        raise RuntimeError("payload proof missing")
                    phase["probes"].append(proof)
                    checkpoint()
                    print(f"PASS {variant} {node['name']} TSMP + verified 1MiB each way", flush=True)
                    if args.ipv6_proof:
                        target6 = nodes[i ^ 1]["test_ipv6"]
                        if not target6:
                            raise RuntimeError("test peer has no IPv6 address")
                        proof6 = api(node, f"/probe?target={target6}&size=1048576", method="POST", timeout=65)
                        if proof6.get("download", {}).get("bytes") != 1048576 or proof6.get("upload", {}).get("bytes") != 1048576:
                            raise RuntimeError("IPv6 payload proof missing")
                        proof6.update({"from": node["name"], "family": "ipv6"})
                        phase["probes"].append(proof6)
                        checkpoint()
                        print(f"PASS {variant} {node['name']} inner IPv6 TSMP + verified 1MiB each way", flush=True)
                if variant.startswith('http3-ip-') and not args.managed_cli:
                    # A cold engine can discard stale startup hints while the
                    # control map is installed. First establish authenticated
                    # metadata, then explicitly test a host-rebind lifecycle.
                    # Production never reconnects solely to change appearance.
                    phase['initial_transport'] = {n['name']:api(n,'/quic') for n in nodes}
                    initiator = nodes[proof_order[0]]
                    other = nodes[1-proof_order[0]]
                    phase['rebind'] = api(initiator,'/reconnect',method='POST',timeout=15)
                    recovered = api(initiator,f"/probe?target={other['test_ip']}&size=1048576",method='POST',timeout=65)
                    if recovered.get('download',{}).get('bytes')!=1048576 or recovered.get('upload',{}).get('bytes')!=1048576:
                        raise RuntimeError('rebind did not recover verified bidirectional traffic')
                    phase['rebind_proof'] = recovered
                    print('REBIND',variant,initiator['name'],'verified bidirectional data',flush=True)
                for node in nodes:
                    phase.setdefault("transport", {})[node["name"]] = api(node, "/quic")
                    if variant != "native":
                        stats = phase["transport"][node["name"]]
                        if not stats.get("identity_ok") or not stats.get("datagrams") or stats.get("tls_version") != 772 or not stats.get("sent_packets") or not stats.get("received_packets"):
                            raise RuntimeError("QUIC/TLS/data counters did not prove real QUIC transit")
                        if variant.startswith("http3-ip-"):
                            expected_profile = "chromium-h3" if len(declared_servers) == 1 and node['name'] not in declared_servers else "none"
                            if stats.get('browser_fingerprint') != expected_profile:
                                raise RuntimeError(f"{node['name']} profile mismatch: expected {expected_profile}, got {stats.get('browser_fingerprint')}")
                            phase.setdefault('verified_profiles', {})[node['name']] = expected_profile
                        if variant.startswith(("quic-ip-", "http3-ip-")):
                            expected_alpn = "h3" if variant.startswith("http3-ip-") else "quic-ip/1"
                            if stats.get("payload") != "ip" or stats.get("alpn") != expected_alpn or stats.get("wireguard_encryption") is not False:
                                raise RuntimeError("native-IP mode fell back to a WireGuard carrier")
                            current = api(node, "/status")
                            for peer_status in current.get("peers", []):
                                if peer_status.get("session_protocol") != ("http3-ip" if variant.startswith("http3-ip-") else "quic-ip") or peer_status.get("session_state") != 2 or not peer_status.get("lastHandshake", "").startswith("0001-"):
                                    raise RuntimeError("native-IP peer missing truthful TLS session status: " + json.dumps(peer_status))
                if args.latency_samples:
                    for i, node in enumerate(nodes):
                        latency = api(node, f"/latency?target={nodes[i ^ 1]['test_ip']}&samples={args.latency_samples}", method="POST", timeout=45)
                        latency["from"] = node["name"]
                        phase.setdefault("latency", []).append(latency)
                        if latency.get("failed"):
                            raise RuntimeError("encrypted idle latency probe lost responses: " + json.dumps(latency))
                        print(f"RTT {variant} {node['name']}: median={latency['median_ms']:.2f}ms p95={latency['p95_ms']:.2f}ms", flush=True)
                if args.kernel_iperf:
                    kernel.benchmark(nodes, args, phase, checkpoint, remote, api, ident, index)
                for i, node in enumerate(nodes if not args.proof_only and not args.kernel_iperf else []):
                    target = nodes[i ^ 1]["test_ip"]
                    before = {n["name"]: {"process": api(n, "/metrics"), "quic": api(n, "/quic")} for n in nodes}
                    bench = api(node, f"/bench?target={target}&bytes={args.mib << 20}&parallel={args.parallel}&rounds={args.rounds}&direction=download", method="POST", timeout=100)
                    after = {n["name"]: {"process": api(n, "/metrics"), "quic": api(n, "/quic")} for n in nodes}
                    bench.update({"from": node["name"], "before": before, "after": after})
                    phase["benchmarks"].append(bench)
                    checkpoint()
                    if not bench.get("mbps") or any(s.get("error") for s in bench.get("streams", [])):
                        raise RuntimeError("benchmark failed: " + json.dumps(bench.get("streams")))
                    cpu = {n["name"]: after[n["name"]]["process"]["cpu_total_seconds"] - before[n["name"]]["process"]["cpu_total_seconds"] for n in nodes}
                    print(f"BENCH {variant} download at {node['name']}: {bench['mbps']:.2f} Mbps; CPU seconds {cpu}", flush=True)
                if args.browser_smoke and variant == "http3-ip-udp":
                    phase["browser"] = []
                    for n in nodes:
                        evidence = browser_smoke(n, temp)
                        phase["browser"].append(evidence)
                        print('BROWSER', n['name'], 'PASS' if evidence['passed'] else 'FAIL', flush=True)
                        checkpoint()
                phase["final_transport"] = {n["name"]: api(n, "/quic") for n in nodes}
                if variant.startswith('http3-ip-'):
                    for node in nodes:
                        actual = phase['final_transport'][node['name']].get('browser_fingerprint')
                        if actual != phase['verified_profiles'][node['name']]:
                            raise RuntimeError('actual client handshake profile changed during benchmark')
                phase["data_plane_passed"] = True
                phase["passed"] = all(e["passed"] for e in phase.get("browser", []))
                if args.managed_cli:
                    phase["next_start"] = stage_managed(variants[index + 1] if index + 1 < len(variants) else "native")
                checkpoint()
                stop_current()
            result["data_plane_passed"] = all(p.get("data_plane_passed", False) for p in result["phases"])
            result["passed"] = all(p["passed"] for p in result["phases"])
        except Exception as exc:
            result["error"] = str(exc)
            print("FAILED:", exc, flush=True)
            for node, unit in units:
                if node.get("unit") == unit:
                    result.setdefault("failure_stats", {})[node["name"]] = {"quic": api(node, "/quic", check=False), "process": api(node, "/metrics", check=False)}
                    result.setdefault("failure_logs", {})[node["name"]] = remote(node, "journalctl -u " + shlex.quote(unit) + " -n 100 --no-pager", check=False).stdout
        finally:
            for node in nodes:
                for unit in node.get('aux_units', []):
                    try:
                        remote(node, 'systemctl stop ' + shlex.quote(unit), check=False, timeout=45)
                    except Exception as exc:
                        result['cleanup_errors'].append(str(exc))
            for node, unit in units:
                try:
                    remote(node, "systemctl stop " + shlex.quote(unit), check=False, timeout=20)
                except Exception as exc:
                    result["cleanup_errors"].append(str(exc))
            for node in nodes:
                try:
                    result.setdefault("hosts", []).append({"name": node["name"], "address": node["address"], "baseline": node.get("baseline"),
                         "after": remote(node, "systemctl show tailscaled -p MainPID -p ActiveState; tailscale version | head -1", check=False).stdout.strip()})
                    if node.get('kernel_ns'):
                        pids = remote(node, shlex.join(['ip','netns','pids',node['kernel_ns']])).stdout.strip()
                        if pids: raise RuntimeError('test namespace still has processes; refusing untracked cleanup: '+pids)
                        remote(node, shlex.join(['ip','netns','delete',node['kernel_ns']]))
                    if node["dir"].startswith(f"/var/tmp/quicwg-lab-{ident}-"):
                        remote(node, "rm -rf -- " + shlex.quote(node["dir"]), check=False)
                except Exception as exc:
                    result["cleanup_errors"].append(str(exc))
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
            log.close()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
    if result['cleanup_errors']:
        result['passed'] = False
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    if not result["passed"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
