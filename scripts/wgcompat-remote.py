#!/usr/bin/env python3
"""Run isolated tsnet data-plane tests on two authorized SSH hosts.

Does not replace tailscaled, use production keys, edit firewall/routes/DNS, or
join the production control plane. Temporary units have hard runtime limits.
Only files/units created by this invocation are removed during cleanup.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import shutil
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time


def run(argv: list[str], *, check: bool = True, timeout: int = 25) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {shlex.join(argv[:3])}: {result.stderr.strip()} {result.stdout.strip()}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-binary", type=Path, required=True)
    parser.add_argument("--linux-binary", type=Path, required=True)
    parser.add_argument("--sg", required=True)
    parser.add_argument("--zjg", required=True)
    parser.add_argument("--profiles", default="standard,awg2,awg3,awg31")
    parser.add_argument("--force-derp", action="store_true", help="force the isolated SSH-forwarded DERP relay instead of direct UDP")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profiles = args.profiles.split(",")
    if not all(p in {"standard", "awg2", "awg3", "awg31"} for p in profiles):
        raise ValueError("invalid profile list")
    for binary in (args.local_binary, args.linux_binary):
        if not binary.is_file():
            raise ValueError(f"missing binary: {binary}")
    ident = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    results: dict = {"run": ident, "linux_sha256": hashlib.sha256(args.linux_binary.read_bytes()).hexdigest(),
                     "isolation": "tsnet; temporary control/DERP via SSH; production services unchanged",
                     "force_derp": args.force_derp, "phases": [], "passed": False}
    processes: list[subprocess.Popen] = []
    nodes: list[dict] = []
    units: list[tuple[dict, str]] = []
    with tempfile.TemporaryDirectory(prefix="wgcompat-") as temp:
        tempdir = Path(temp)
        archive = tempdir / "lab.gz"
        with args.linux_binary.open("rb") as src, gzip.open(archive, "wb", compresslevel=1) as dst:
            shutil.copyfileobj(src, dst)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            control_port = sock.getsockname()[1]
            with socket.socket() as derp_sock:
                derp_sock.bind(("127.0.0.1", 0))
                derp_port = derp_sock.getsockname()[1]
        control_log = (tempdir / "control.log").open("w+")
        control = subprocess.Popen([str(args.local_binary.resolve()), "control", "--listen", f"127.0.0.1:{control_port}",
                                    "--derp-listen", f"127.0.0.1:{derp_port}", "--public-stun"],
                                   stdout=control_log, stderr=control_log)
        processes.append(control)
        try:
            for _ in range(200):
                if control.poll() is not None:
                    control_log.seek(0)
                    raise RuntimeError("control exited: " + control_log.read()[-2000:])
                try:
                    with socket.create_connection(("127.0.0.1", control_port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("control did not listen")
            for name, host, expected in (("sg", args.sg, "sg2222"), ("zjg", args.zjg, "zjg")):
                node = {"name": name, "host": host, "dir": f"/var/tmp/wgcompat-lab-{ident}-{name}",
                        "socket": str(tempdir / f"ssh-{name}"), "admin": 18441, "udp": 42641}
                ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12"]
                actual = run(ssh_base + [host, "hostname"]).stdout.strip()
                if actual != expected:
                    raise RuntimeError(f"refusing wrong host {name}: got {actual!r}, expected {expected!r}")
                node["hostname"] = actual
                # A dedicated SSH connection forwards the local-only control plane.
                tunnel = subprocess.Popen(ssh_base + ["-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=10",
                                            "-M", "-S", node["socket"], "-N", "-R",
                                            f"127.0.0.1:{control_port}:127.0.0.1:{control_port}",
                                            "-R", f"127.0.0.1:{derp_port}:127.0.0.1:{derp_port}", host],
                                           stdout=subprocess.DEVNULL, stderr=control_log)
                processes.append(tunnel)
                for _ in range(40):
                    if tunnel.poll() is not None:
                        raise RuntimeError(f"SSH forwarding failed for {name}")
                    if Path(node["socket"]).exists():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f"SSH forwarding did not start for {name}")
                node["ssh"] = ssh_base + ["-S", node["socket"], host]
                nodes.append(node)
                busy = remote(node, "ss -H -lnt 'sport = :18441'; ss -H -lnu 'sport = :42641'").stdout.strip()
                if busy:
                    raise RuntimeError(f"test ports already used on {name}: {busy}")
                remote(node, f"install -d -m 700 {shlex.quote(node['dir'])}")
                run(["scp", "-q", "-o", "BatchMode=yes", "-o", f"ControlPath={node['socket']}",
                     str(archive), f"{host}:{node['dir']}/lab.gz"], timeout=90)
                remote(node, f"gzip -d {shlex.quote(node['dir'] + '/lab.gz')} && chmod 700 {shlex.quote(node['dir'] + '/lab')}")
                baseline = remote(node, "systemctl show tailscaled -p ActiveState -p SubState -p MainPID; tailscale version | head -1", check=False).stdout.strip()
                node["baseline"] = baseline
            for index, profile in enumerate(profiles):
                phase = {"profile": profile, "probes": [], "ready": [], "passed": False}
                results["phases"].append(phase)
                print(f"START profile={profile}", flush=True)
                current_units = []
                for node in nodes:
                    unit = f"wgcompat-{ident}-{node['name']}-{index}"
                    command = ["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--property=RuntimeMaxSec=240",
                               "--property=TimeoutStopSec=10", "--property=Restart=no",
                               "env", "TS_EXPERIMENTAL_WG_TRANSPORT=native", "TS_NO_LOGS_NO_SUPPORT=true",
                               f"TS_DEBUG_ALWAYS_USE_DERP={'true' if args.force_derp else 'false'}",
                               node["dir"] + "/lab", "node", "--dir", node["dir"] + "/state",
                               "--hostname", f"wgcompat-{node['name']}", "--control", f"http://127.0.0.1:{control_port}",
                               "--listen", f"127.0.0.1:{node['admin']}", "--port", str(node["udp"]), "--profile", profile]
                    remote(node, shlex.join(command))
                    units.append((node, unit))
                    current_units.append((node, unit))
                deadline = time.monotonic() + 75
                statuses = []
                while time.monotonic() < deadline:
                    statuses = [api(node, "/status", check=False) for node in nodes]
                    if all(isinstance(s, dict) and s.get("state") == "Running" and s.get("ips") and s.get("peers") for s in statuses):
                        break
                    time.sleep(1)
                else:
                    for node, unit in current_units:
                        phase.setdefault("logs", {})[node["name"]] = remote(node, f"journalctl -u {unit} --no-pager -n 25", check=False).stdout
                    raise RuntimeError(f"profile {profile}: nodes did not become ready: {statuses}")
                phase["ready"] = statuses
                for i, node in enumerate(nodes):
                    target = next(ip for ip in statuses[i ^ 1]["ips"] if ":" not in ip)
                    data = api(node, f"/probe?target={target}&size=1048576", method="POST", timeout=65)
                    if not isinstance(data, dict) or data.get("download", {}).get("bytes") != 1048576 or data.get("upload", {}).get("bytes") != 1048576:
                        raise RuntimeError(f"invalid probe result on {node['name']}: {data}")
                    if data["download"]["sha256"] != data["upload"]["sha256"]:
                        raise RuntimeError("upload/download SHA256 mismatch")
                    if data.get("tsmp", {}).get("Err"):
                        raise RuntimeError("TSMP reported an error")
                    discovery = data.get("discovery") or {}
                    data["from"] = node["name"]
                    data["path"] = "direct" if discovery.get("Endpoint") else "relay"
                    if args.force_derp and (data["path"] != "relay" or not discovery.get("DERPRegionID")):
                        raise RuntimeError("forced DERP probe unexpectedly bypassed relay")
                    if not args.force_derp and data["path"] != "direct":
                        raise RuntimeError("direct-UDP gate did not establish a direct peer path")
                    matching = [p for p in data["status"].get("peers", []) if target in p.get("ips", [])]
                    if not matching or matching[0].get("Tx", 0) <= 0 or matching[0].get("Rx", 0) <= 0:
                        raise RuntimeError("missing encrypted WireGuard peer traffic counters")
                    phase["probes"].append(data)
                    print(f"PASS {profile} {node['name']} -> {target}: encrypted TSMP, download+upload 1MiB, path={data['path']}, seconds={data['seconds']:.3f}", flush=True)
                # Exercise a live profile reset in addition to startup configuration.
                for node in nodes:
                    api(node, "/profile?name=standard", method="POST")
                for node, unit in current_units:
                    remote(node, f"systemctl stop {shlex.quote(unit)}", check=False, timeout=20)
                phase["passed"] = True
            results["passed"] = True
        except Exception as exc:
            results["error"] = str(exc)
            control_log.flush()
            control_log.seek(0)
            results["control_log_tail"] = control_log.read()[-12000:]
            print(f"FAILED: {exc}", flush=True)
        finally:
            cleanup_errors = []
            for node, unit in units:
                try:
                    if not results["passed"]:
                        results.setdefault("failure_logs", {})[unit] = remote(node, f"journalctl -u {shlex.quote(unit)} --no-pager -n 60", check=False).stdout
                    remote(node, f"systemctl stop {shlex.quote(unit)}", check=False, timeout=20)
                except Exception as exc:
                    cleanup_errors.append(f"{node['name']} stop {unit}: {exc}")
            for node in nodes:
                try:
                    after = remote(node, "systemctl show tailscaled -p ActiveState -p SubState -p MainPID; tailscale version | head -1", check=False).stdout.strip()
                    results.setdefault("hosts", []).append({"name": node["name"], "hostname": node.get("hostname"),
                        "baseline": node.get("baseline"), "after": after})
                    # Strict prefix guards: delete only this invocation's test directory.
                    directory = node["dir"]
                    if directory.startswith(f"/var/tmp/wgcompat-lab-{ident}-"):
                        remote(node, "rm -rf -- " + shlex.quote(directory), check=False)
                except Exception as exc:
                    cleanup_errors.append(f"{node['name']} cleanup: {exc}")
            results["cleanup_errors"] = cleanup_errors
            if cleanup_errors:
                results["passed"] = False
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            control_log.close()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    if not results["passed"]:
        raise SystemExit(1)


def remote(node: dict, command: str, *, check: bool = True, timeout: int = 25):
    return run(node["ssh"] + [command], check=check, timeout=timeout)


def api(node: dict, path: str, *, method: str = "GET", check: bool = True, timeout: int = 10):
    argv = ["curl", "--silent", "--show-error", "--fail-with-body", "--max-time", str(timeout), "-X", method,
            "-H", "X-WG-Lab: 1", f"http://127.0.0.1:{node['admin']}{path}"]
    result = remote(node, shlex.join(argv), check=False, timeout=timeout + 5)
    if result.returncode:
        if check:
            raise RuntimeError(f"{node['name']} {path}: {result.stderr.strip()} {result.stdout.strip()}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        if check:
            raise RuntimeError(f"invalid JSON from {node['name']}: {result.stdout[:500]}")
        return None


if __name__ == "__main__":
    main()
