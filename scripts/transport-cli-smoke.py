#!/usr/bin/env python3
"""Local real-binary CLI acceptance using two isolated tsnet processes.
No production socket, service manager, remote host or firewall is accessed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab", type=Path, required=True)
    ap.add_argument("--cli", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--auto-trust", action="store_true", help="test fresh H3 profiles without identity preparation or card import")
    args = ap.parse_args()
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("TS_EXPERIMENTAL_"):
            del env[name]
    env["TS_NO_LOGS_NO_SUPPORT"] = "true"
    result = {"passed": False, "phases": [], "scope": "local CLI binaries + actual two-node tsnet data plane", "cleanup_errors": [],
              "lab_sha256": hashlib.sha256(args.lab.read_bytes()).hexdigest(),
              "cli_sha256": hashlib.sha256(args.cli.read_bytes()).hexdigest(),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()),
              "automatic_trust": args.auto_trust}
    with tempfile.TemporaryDirectory(prefix="transport-cli-") as tmp:
        root = Path(tmp)
        control_port, derp_port, stun_port = free_port(), free_port(), free_port(socket.SOCK_DGRAM)
        log = (root / "lab.log").open("w+")
        ctrl = subprocess.Popen([str(args.lab), "control", "--listen", f"127.0.0.1:{control_port}", "--derp-listen", f"127.0.0.1:{derp_port}", "--stun-server", f"127.0.0.1:{stun_port}"], env=env, stdout=log, stderr=log)
        nodes = []
        for i in range(2):
            state = root / f"node{i}"
            state.mkdir(mode=0o700)
            nodes.append({"state": state, "admin": free_port(), "udp": free_port(socket.SOCK_DGRAM), "process": None})

        def http(node, path, method="GET"):
            req = urllib.request.Request(f"http://127.0.0.1:{node['admin']}{path}", method=method, headers={"X-WG-Lab": "1"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)

        def cli(node, *commands, checked=True, json_result=False, stdin=""):
            cp = subprocess.run([str(args.cli), "--socket", str(node["state"] / "localapi.sock"), "awg", *commands], input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, env=env)
            if checked and cp.returncode:
                raise RuntimeError(f"CLI {' '.join(commands[:2])}: {cp.stderr} {cp.stdout}")
            return json.loads(cp.stdout) if json_result else cp

        def stop(proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)

        def stop_nodes():
            for node in nodes:
                stop(node["process"])
                node["process"] = None

        def start_nodes():
            for i, node in enumerate(nodes):
                cmd = [str(args.lab), "node", "--profile", "keep", "--dir", str(node["state"]), "--hostname", f"cli-smoke-{i}", "--listen", f"127.0.0.1:{node['admin']}", "--control", f"http://127.0.0.1:{control_port}", "--port", str(node["udp"]), "--localapi-socket", str(node["state"] / "localapi.sock")]
                if i == 0:
                    cmd += ["--stun-listen", f"127.0.0.1:{stun_port}"]
                node["process"] = subprocess.Popen(cmd, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                try:
                    statuses = [http(n, "/status") for n in nodes]
                    if all(s.get("state") == "Running" and s.get("peers") for s in statuses):
                        for n, s in zip(nodes, statuses):
                            n["ip"] = next(v for v in s["ips"] if ":" not in v)
                        return
                except (OSError, ValueError):
                    pass
                if any(n["process"].poll() is not None for n in nodes):
                    raise RuntimeError("isolated node exited")
                time.sleep(0.1)
            raise RuntimeError("local nodes not ready")

        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", control_port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("local control did not listen")
                    time.sleep(0.1)
            start_nodes()
            if not args.auto_trust:
                cards = [cli(n, "identity", "--init", json_result=True) for n in nodes]
                for i, n in enumerate(nodes):
                    cli(n, "peer", "add", "--yes", json.dumps(cards[i ^ 1]))
                    cli(n, "doctor")
            else:
                cli(nodes[1], "server", "--yes", "--no-restart", "on")
            for i, n in enumerate(nodes):
                no_tty = cli(n)
                if "Usage: tailscale awg" not in no_tty.stdout:
                    raise RuntimeError("non-TTY root did not print usage")
                before = cli(n, "status", "--json", json_result=True)
                cli(n, "transport", "--no-restart", "http3-ip" if args.auto_trust else "quic-ip", stdin="")
                if cli(n, "status", "--json", json_result=True)["revision"] != before["revision"]:
                    raise RuntimeError("EOF unexpectedly changed profile")
                if cli(n, "transport", "--yes", "--no-restart", "wg-over-quic", checked=False).returncode == 0:
                    raise RuntimeError("production CLI accepted WG-over-QUIC")
            awg_profile = json.dumps({"jc": 4, "jmin": 700, "jmax": 899, "s1": 19, "s2": 29, "s3": 15, "s4": 20,
                                      "h1": 773603178, "h2": 1713856760, "h3": 2188170348, "h4": 3015010040})
            if args.auto_trust:
                for n in nodes:
                    cli(n, "set", "--yes", "--no-restart", awg_profile)
            modes = ("http3-ip", "native", "http3-ip", "native") if args.auto_trust else ("quic-ip", "http3-ip", "native")
            for mode in modes:
                for n in nodes:
                    before = cli(n, "status", "--json", json_result=True)
                    pid = n["process"].pid
                    if args.auto_trust:
                        cli(n, "set", "--yes", "--no-restart", "quic" if mode == "http3-ip" else awg_profile)
                    else:
                        cli(n, "transport", "--yes", "--no-restart", mode)
                    after = cli(n, "status", "--json", json_result=True)
                    if after["active_mode"] != before["active_mode"] or after["desired_mode"] != mode or not after["pending_restart"] or n["process"].pid != pid:
                        raise RuntimeError("staging mislabeled running mode or restarted the daemon")
                    if args.auto_trust and after['awg_configured'] != (mode == 'native'):
                        raise RuntimeError('AWG was not automatically cleared or saved with the selected mode')
                pending_probes = []
                if args.auto_trust and mode == 'native':
                    for i, n in enumerate(nodes):
                        proof = http(n, f"/probe?target={nodes[i ^ 1]['ip']}&size=262144", "POST")
                        if proof['upload']['bytes'] != 262144 or proof['download']['bytes'] != 262144:
                            raise RuntimeError('saving AWG broke the still-running QUIC connection')
                        pending_probes.append(proof)
                stop_nodes()
                start_nodes()
                phase = {"mode": mode, "status": [], "probes": [], "before_restart_probes": pending_probes}
                for i, n in enumerate(nodes):
                    status = cli(n, "status", "--json", json_result=True)
                    if status["active_mode"] != mode or status["pending_restart"] or status["source"] != "managed":
                        raise RuntimeError("CLI profile did not activate after restart")
                    if args.auto_trust and status['awg_configured'] != (mode == 'native'):
                        raise RuntimeError('restart did not preserve the selected AWG configuration')
                    if args.auto_trust and mode == "http3-ip":
                        if status.get("authentication") != "node-key" or status.get("peers") or not status.get("identity"):
                            raise RuntimeError("fresh H3 still depends on manual identity cards")
                        cli(n, "doctor")
                    phase["status"].append(status)
                    proof = http(n, f"/probe?target={nodes[i ^ 1]['ip']}&size=262144", "POST")
                    if proof["upload"]["bytes"] != 262144 or proof["download"]["bytes"] != 262144:
                        raise RuntimeError("incomplete payload proof")
                    phase["probes"].append(proof)
                result["phases"].append(phase)
                print("PASS real CLI + restart + bidirectional data:", mode, flush=True)
            if args.auto_trust:
                # Sync uses the shared set/apply path while the receiver is
                # still QUIC and the source has already restarted into AWG.
                for n in nodes:
                    cli(n, 'set', '--yes', 'quic')
                stop_nodes()
                start_nodes()
                cli(nodes[0], 'set', '--yes', awg_profile)
                stop_nodes()
                start_nodes()
                sync_result = cli(nodes[1], 'sync', stdin='1\ny\nn\n')
                result['sync_output'] = sync_result.stdout + sync_result.stderr
                staged = cli(nodes[1], 'status', '--json', json_result=True)
                result['sync_staged_status'] = staged
                if staged['active_mode'] != 'http3-ip' or staged['desired_mode'] != 'native' or not staged['awg_configured']:
                    raise RuntimeError('sync did not save AWG with a native selection')
                stop_nodes()
                start_nodes()
                phase = {'mode': 'sync-quic-to-awg', 'status': [], 'probes': []}
                for i, n in enumerate(nodes):
                    phase['status'].append(cli(n, 'status', '--json', json_result=True))
                    proof = http(n, f"/probe?target={nodes[i ^ 1]['ip']}&size=262144", 'POST')
                    if proof['upload']['bytes'] != 262144 or proof['download']['bytes'] != 262144:
                        raise RuntimeError('synced AWG did not carry application data after restart')
                    phase['probes'].append(proof)
                result['phases'].append(phase)
                print('PASS real CLI sync from QUIC to AWG + restart + bidirectional data', flush=True)
            result["passed"] = True
        except Exception as exc:
            result["error"] = str(exc)
            log.flush()
            log.seek(0)
            result["log_tail"] = log.read()[-14000:]
            print("FAILED:", exc, flush=True)
        finally:
            try:
                stop_nodes()
                stop(ctrl)
            except Exception as exc:
                result["cleanup_errors"].append(str(exc))
            log.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
