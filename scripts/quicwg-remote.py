#!/usr/bin/env python3
"""Isolated two-host native-vs-QUIC WG tests. Does not replace production tailscaled.
All generated TLS keys stay on their host; only public SPKI pins are exchanged.
"""
from __future__ import annotations
import argparse
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
run, remote, api = compat.run, compat.remote, compat.api


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--local-binary", type=Path, required=True)
    p.add_argument("--linux-binary", type=Path, required=True)
    p.add_argument("--sg", default="root@sg.yesican.top")
    p.add_argument("--zjg", default="root@173.249.215.87")
    p.add_argument("--sg-address", default="96.9.212.12")
    p.add_argument("--zjg-address", default="173.249.215.87")
    p.add_argument("--variants", default="native,quic-udp,quic-ip-udp,quic-ip-magicsock")
    p.add_argument("--profile", choices=["standard", "awg2", "awg3", "awg31"], default="standard")
    p.add_argument("--mib", type=int, default=8)
    p.add_argument("--parallel", type=int, default=1)
    p.add_argument("--rounds", type=int, default=1)
    p.add_argument("--force-derp", action="store_true")
    p.add_argument("--proof-only", action="store_true", help="run encrypted integrity checks without throughput benchmarks")
    p.add_argument("--ipv6-proof", action="store_true", help="also verify inner IPv6 TSMP and file transfer")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    variants = args.variants.split(",")
    if not variants or any(v not in ("native", "quic-udp", "quic-magicsock", "quic-ip-udp", "quic-ip-magicsock") for v in variants):
        p.error("invalid variants")
    if not 1 <= args.mib <= 64 or not 1 <= args.parallel <= 4 or not 1 <= args.rounds <= 3:
        p.error("invalid benchmark limits")
    if args.force_derp and any(v.endswith("-udp") for v in variants):
        p.error("independent UDP mode does not use DERP; test magicsock instead")
    if args.profile != "standard" and any(v.startswith("quic-ip-") for v in variants):
        p.error("native QUIC IP rejects AWG profiles; use --profile=standard")
    ident = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    result = {"run": ident, "linux_sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
              "profile": args.profile, "force_derp": args.force_derp,
              "settings": {"mib_per_stream": args.mib, "parallel": args.parallel, "rounds": args.rounds},
              "phases": [], "passed": False, "cleanup_errors": []}
    nodes, units, processes = [], [], []
    def checkpoint():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    checkpoint()
    with tempfile.TemporaryDirectory(prefix="quicwg-") as tmp:
        temp = Path(tmp)
        control_port, derp_port = free_port(), free_port()
        log = (temp / "control.log").open("w+")
        cmd = [str(args.local_binary.resolve()), "control", "--listen", f"127.0.0.1:{control_port}",
               "--derp-listen", f"127.0.0.1:{derp_port}"]
        if not args.force_derp:
            cmd += ["--public-stun"]
        processes.append(subprocess.Popen(cmd, stdout=log, stderr=log))
        try:
            for _ in range(60):
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
            for name, host, expected, address in [("sg", args.sg, "sg2222", args.sg_address), ("zjg", args.zjg, "zjg", args.zjg_address)]:
                node = {"name": name, "host": host, "address": address, "dir": f"/var/tmp/quicwg-lab-{ident}-{name}",
                        "socket": str(temp / name), "admin": 18441}
                ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12"]
                actual = run(ssh + [host, "hostname"]).stdout.strip()
                if actual != expected:
                    raise RuntimeError(f"wrong host: {actual}, expected {expected}")
                tunnel = subprocess.Popen(ssh + ["-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=10", "-M", "-S", node["socket"], "-N",
                    "-R", f"127.0.0.1:{control_port}:127.0.0.1:{control_port}",
                    "-R", f"127.0.0.1:{derp_port}:127.0.0.1:{derp_port}", host], stdout=subprocess.DEVNULL, stderr=log)
                processes.append(tunnel)
                for _ in range(60):
                    if tunnel.poll() is not None:
                        raise RuntimeError(f"SSH tunnel failed: {name}")
                    if Path(node["socket"]).exists():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f"SSH startup timeout: {name}")
                node["ssh"] = ssh + ["-S", node["socket"], host]
                nodes.append(node)
                busy = remote(node, "ss -H -lnt 'sport = :18441'; ss -H -lnu 'sport = :42641'; ss -H -lnu 'sport = :42642'").stdout.strip()
                if busy:
                    raise RuntimeError(f"test ports are occupied: {name}: {busy}")
                node["baseline"] = remote(node, "systemctl show tailscaled -p MainPID -p ActiveState; tailscale version | head -1", check=False).stdout.strip()
                remote(node, "install -d -m 700 " + shlex.quote(node["dir"]))
                run(["scp", "-C", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}",
                     str(args.linux_binary.resolve()), f"{host}:{node['dir']}/lab"], timeout=120)
                remote(node, f"chmod 700 {node['dir']}/lab")
                node["identity"] = json.loads(remote(node, shlex.join([node["dir"] + "/lab", "identity", "--dir", node["dir"] + "/tls"])).stdout)

            def stop_current():
                for node in nodes:
                    if node.get("unit"):
                        remote(node, "systemctl stop " + shlex.quote(node["unit"]), check=False, timeout=20)
                        node["unit"] = None

            def start(variant, index, profile):
                for i, node in enumerate(nodes):
                    env = ["TS_NO_LOGS_NO_SUPPORT=true", f"TS_DEBUG_ALWAYS_USE_DERP={'true' if args.force_derp else 'false'}"]
                    if variant == "native":
                        env += ["TS_EXPERIMENTAL_WG_TRANSPORT=native"]
                    else:
                        native_ip = variant.startswith("quic-ip-")
                        io_mode = variant.removeprefix("quic-ip-" if native_ip else "quic-")
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
                        local_config = temp / f"{node['name']}-config.json"
                        local_config.write_text(json.dumps(config))
                        run(["scp", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}",
                             str(local_config), f"{node['host']}:{node['dir']}/quic.json"])
                        env += [f"TS_EXPERIMENTAL_WG_TRANSPORT={'quic-ip' if native_ip else 'quic'}", f"TS_EXPERIMENTAL_QUIC_CONFIG={node['dir']}/quic.json"]
                    unit = f"quicwg-{ident}-{node['name']}-{index}"
                    command = ["systemd-run", "--quiet", "--collect", "--unit=" + unit, "--property=RuntimeMaxSec=600", "--property=TimeoutStopSec=15", "--property=Restart=no",
                               "env"] + env + [node["dir"] + "/lab", "node", "--dir", node["dir"] + "/state", "--hostname", "quicwg-" + node["name"],
                                "--control", f"http://127.0.0.1:{control_port}", "--listen", "127.0.0.1:18441", "--port", "42641", "--profile", profile]
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

            print("BOOTSTRAP isolated identities", flush=True)
            statuses = start("native", "bootstrap", "standard")
            for i, node in enumerate(nodes):
                node["public_key"] = statuses[i]["public_key"]
                node["test_ip"] = next(x for x in statuses[i]["ips"] if ":" not in x)
                node["test_ipv6"] = next((x for x in statuses[i]["ips"] if ":" in x), None)
            stop_current()
            for index, variant in enumerate(variants):
                print(f"START {variant}/{args.profile}", flush=True)
                phase = {"variant": variant, "probes": [], "benchmarks": [], "passed": False}
                result["phases"].append(phase)
                statuses = start(variant, index, args.profile)
                for i, node in enumerate(nodes):
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
                for node in nodes:
                    phase.setdefault("transport", {})[node["name"]] = api(node, "/quic")
                    if variant != "native":
                        stats = phase["transport"][node["name"]]
                        if not stats.get("identity_ok") or not stats.get("datagrams") or stats.get("tls_version") != 772 or not stats.get("sent_packets") or not stats.get("received_packets"):
                            raise RuntimeError("QUIC/TLS/data counters did not prove real QUIC transit")
                        if variant.startswith("quic-ip-"):
                            if stats.get("payload") != "ip" or stats.get("alpn") != "quic-ip/1" or stats.get("wireguard_encryption") is not False:
                                raise RuntimeError("native-IP mode fell back to a WireGuard carrier")
                            current = api(node, "/status")
                            for peer_status in current.get("peers", []):
                                if peer_status.get("session_protocol") != "quic-ip" or peer_status.get("session_state") != 2 or not peer_status.get("lastHandshake", "").startswith("0001-"):
                                    raise RuntimeError("native-IP peer missing truthful TLS session status: " + json.dumps(peer_status))
                for i, node in enumerate(nodes if not args.proof_only else []):
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
                phase["final_transport"] = {n["name"]: api(n, "/quic") for n in nodes}
                phase["passed"] = True
                checkpoint()
                stop_current()
            result["passed"] = True
        except Exception as exc:
            result["error"] = str(exc)
            print("FAILED:", exc, flush=True)
            for node, unit in units:
                if node.get("unit") == unit:
                    result.setdefault("failure_stats", {})[node["name"]] = {"quic": api(node, "/quic", check=False), "process": api(node, "/metrics", check=False)}
                    result.setdefault("failure_logs", {})[node["name"]] = remote(node, "journalctl -u " + shlex.quote(unit) + " -n 100 --no-pager", check=False).stdout
        finally:
            for node, unit in units:
                try:
                    remote(node, "systemctl stop " + shlex.quote(unit), check=False, timeout=20)
                except Exception as exc:
                    result["cleanup_errors"].append(str(exc))
            for node in nodes:
                try:
                    result.setdefault("hosts", []).append({"name": node["name"], "address": node["address"], "baseline": node.get("baseline"),
                         "after": remote(node, "systemctl show tailscaled -p MainPID -p ActiveState; tailscale version | head -1", check=False).stdout.strip()})
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
    if not result["passed"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
