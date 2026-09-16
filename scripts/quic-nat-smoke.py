#!/usr/bin/env python3
"""Local QUIC regression: forced DERP, simultaneous traffic, idle and rebind.

Only fresh tsnet processes and an isolated loopback test control/DERP server
are used. No production sockets, node state, service managers, remote servers
or firewall rules are accessed. The lab itself verifies application payloads.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
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


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force-derp", action="store_true")
    parser.add_argument("--application-only", action="store_true", help="independent TCP payload check without a single TSMP packet prerequisite")
    parser.add_argument("--require-direct", action="store_true", help="reject a direct-path test if it stayed on DERP")
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--idle-seconds", type=float, default=65)
    parser.add_argument("--bytes", type=int, default=262144)
    args = parser.parse_args()
    if args.require_direct and args.force_derp:
        parser.error("require-direct and force-derp are mutually exclusive")
    if not 1 <= args.rounds <= 30 or not 0 <= args.idle_seconds <= 90:
        parser.error("rounds must be 1..30 and idle-seconds 0..90")
    if not 1 <= args.bytes <= 4 * 1024 * 1024:
        parser.error("bytes must be 1..4194304")
    args.lab = args.lab.resolve(strict=True)
    args.cli = args.cli.resolve(strict=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("TS_")}
    env.update(TS_NO_LOGS_NO_SUPPORT="true", TS_DISABLE_PORTMAPPER="true",
               TS_DEBUG_ALWAYS_USE_DERP=str(args.force_derp).lower())
    report = {"passed": False, "force_derp": args.force_derp, "application_only": args.application_only, "require_direct": args.require_direct, "rounds": args.rounds,
              "idle_seconds": args.idle_seconds, "payload_bytes": args.bytes,
              "scope": "fresh loopback test control + DERP and two isolated tsnet processes",
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()),
              "lab_sha256": hashlib.sha256(args.lab.read_bytes()).hexdigest(),
              "cli_sha256": hashlib.sha256(args.cli.read_bytes()).hexdigest(),
              "phases": [], "cleanup_errors": []}
    processes: list[subprocess.Popen] = []
    with tempfile.TemporaryDirectory(prefix="quic-nat-smoke-") as temporary:
        root = Path(temporary)
        control_port, derp_port, stun_port = free_port(), free_port(), free_port(socket.SOCK_DGRAM)
        log = (root / "test.log").open("w+")
        ctrl = subprocess.Popen([str(args.lab), "control", "--listen", f"127.0.0.1:{control_port}",
                                 "--derp-listen", f"127.0.0.1:{derp_port}",
                                 "--stun-server", f"127.0.0.1:{stun_port}"], env=env, stdout=log, stderr=log)
        processes.append(ctrl)
        nodes = []
        for index in range(2):
            state = root / str(index)
            state.mkdir(mode=0o700)
            nodes.append({"state": state, "admin": free_port(), "udp": free_port(socket.SOCK_DGRAM), "process": None})
        # Do not inherit browser/system HTTP proxies for private test listeners.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def http(node: dict, path: str, method: str = "GET") -> dict:
            req = urllib.request.Request(f"http://127.0.0.1:{node['admin']}{path}", method=method,
                                         headers={"X-WG-Lab": "1"})
            try:
                with opener.open(req, timeout=60) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                raise RuntimeError(f"{path.split('?')[0]}: HTTP {error.code}: {error.read(1000).decode(errors='replace')}") from error

        def cli(node: dict, *commands: str) -> str:
            result = subprocess.run([str(args.cli), "--socket", str(node["state"] / "localapi.sock"), *commands],
                                    input="", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, env=env)
            if result.returncode:
                raise RuntimeError(f"CLI {commands[:2]}: {result.stderr} {result.stdout}")
            return result.stdout

        def stop(proc: subprocess.Popen | None) -> None:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)

        def start(index: int) -> None:
            node = nodes[index]
            cmd = [str(args.lab), "node", "--dir", str(node["state"]), "--hostname", f"quic-nat-test-{index}",
                   "--listen", f"127.0.0.1:{node['admin']}", "--control", f"http://127.0.0.1:{control_port}",
                   "--port", str(node["udp"]), "--localapi-socket", str(node["state"] / "localapi.sock")]
            if index == 0:
                cmd += ["--stun-listen", f"127.0.0.1:{stun_port}"]
            proc = subprocess.Popen(cmd, env=env, stdout=log, stderr=log)
            node["process"] = proc
            processes.append(proc)

        def ready() -> None:
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                try:
                    status = [http(node, "/status") for node in nodes]
                    if all(s.get("state") == "Running" and s.get("peers") for s in status):
                        for node, s in zip(nodes, status):
                            node["ip"] = next(ip for ip in s["ips"] if ":" not in ip)
                        return
                except (OSError, ValueError):
                    pass
                if any(node["process"].poll() is not None for node in nodes):
                    raise RuntimeError("isolated node exited before readiness")
                time.sleep(0.1)
            raise RuntimeError("isolated nodes failed to become ready")

        def probe_phase(name: str) -> None:
            started = time.monotonic()
            phase = {"name": name, "passed": False}
            report["phases"].append(phase)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(http, node, f"/probe?target={nodes[index ^ 1]['ip']}&size={args.bytes}&application-only={str(args.application_only).lower()}", "POST")
                           for index, node in enumerate(nodes)]
                proofs = [future.result() for future in futures]
            for proof in proofs:
                for direction in ("upload", "download"):
                    if proof[direction]["bytes"] != args.bytes or not proof[direction].get("sha256"):
                        raise RuntimeError(f"{name}: incomplete application-data proof")
                if args.force_derp:
                    peers = proof["status"]["peers"]
                    if not peers or any(peer.get("direct") for peer in peers):
                        raise RuntimeError(f"{name}: forced-DERP test escaped onto a direct path")
                if args.require_direct:
                    peers = proof["status"]["peers"]
                    if not peers or any(not peer.get("direct") for peer in peers):
                        raise RuntimeError(f"{name}: direct-path test stayed on DERP")
            phase.update(passed=True, seconds=round(time.monotonic() - started, 3), proofs=proofs,
                         diagnostics=[http(node, "/quic") for node in nodes])
            print("PASS", name, phase["seconds"], flush=True)

        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", control_port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("test control did not start")
                    time.sleep(0.1)
            for i in range(2):
                start(i)
            ready()
            for node in nodes:
                cli(node, "awg", "transport", "--yes", "http3-ip")
            for node in nodes:
                stop(node["process"])
            for i in range(2):
                start(i)
            ready()
            for node in nodes:
                status = json.loads(cli(node, "awg", "status", "--json"))
                if status["active_mode"] != "http3-ip" or status["authentication"] != "node-key":
                    raise RuntimeError("QUIC automatic authentication did not activate")
            for i in range(args.rounds):
                probe_phase(f"simultaneous-{i+1}")
            if args.idle_seconds:
                time.sleep(args.idle_seconds)
                probe_phase("after-idle")
            for i in range(2):
                cli(nodes[i], "debug", "rebind")
                probe_phase(f"after-rebind-{i}")
            stop(nodes[1]["process"])
            start(1)
            ready()
            probe_phase("after-peer-restart")
            # A power loss or NAT path loss cannot deliver CONNECTION_CLOSE.
            # Exercise both key-order roles rather than only graceful restart.
            for index in range(2):
                nodes[index]["process"].kill()
                nodes[index]["process"].wait(timeout=4)
                # The lab's optional Unix CLI listener has no daemon-style
                # stale-socket cleanup after SIGKILL; remove only our own path.
                (nodes[index]["state"] / "localapi.sock").unlink(missing_ok=True)
                start(index)
                ready()
                probe_phase(f"after-peer-crash-{index}")
            for node in nodes:
                stop(node["process"])
            for i in range(2):
                start(i)
            ready()
            probe_phase("after-simultaneous-restart")
            report["passed"] = True
        except Exception as error:
            report["error"] = str(error)
            report["failure_diagnostics"] = []
            for node in nodes:
                try:
                    report["failure_diagnostics"].append(http(node, "/quic"))
                except Exception as diagnostic_error:
                    report["failure_diagnostics"].append({"error": str(diagnostic_error)})
            log.flush()
            log.seek(0)
            report["log_tail"] = log.read()[-16000:]
            print("FAIL", error, flush=True)
            # Public numerical diagnostics are useful even if log inspection is
            # unavailable. Never print private identities or authentication data.
            for index, diagnostic in enumerate(report["failure_diagnostics"]):
                keys = ("active_connections", "connections", "handshake_errors", "sent_packets", "received_packets", "send_errors", "send_drops", "receive_drops", "raw_drops", "http3_tunnels", "http3_rejected")
                print("FAILURE_COUNTERS", index, json.dumps({key: diagnostic.get(key) for key in keys}), flush=True)
        finally:
            for proc in reversed(processes):
                try:
                    stop(proc)
                except Exception as error:
                    report["cleanup_errors"].append(str(error))
            log.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"] or report["cleanup_errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
