#!/usr/bin/env python3
"""Exercise real containerboot env login, AWG disk state and restart persistence.

Uses a test control server in an internal-only Docker network namespace.
No published ports, real credentials, production state or host VPN are used.
The supplied Linux lab binary must match the Docker engine architecture.
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def run(*args: str, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed ({p.returncode}): {p.stderr[-2000:]}")
    return p


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--h3', action='store_true')
    parser.add_argument('--kernel', action='store_true')
    args = parser.parse_args()
    lab = args.lab.resolve(strict=True)
    token = 'ts-issue18-' + uuid.uuid4().hex[:10]
    control, node = token + '-control', token + '-node'
    network = token + '-net'
    sock = '/tmp/issue18-custom.sock'
    url = 'http://127.0.0.1:18440'
    report = {'passed': False, 'image': args.image, 'kernel': args.kernel,
              'scope': 'real containerboot, isolated test control, no external network',
              'phases': [], 'cleanup_errors': []}
    containers: list[str] = []

    def cli(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
        return run('docker', 'exec', node, 'tailscale', '--socket=' + sock, *cmd, check=check)

    def ready() -> dict:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            p = cli('status', '--json', check=False)
            try:
                status = json.loads(p.stdout)
                if status.get('BackendState') == 'Running':
                    return status
            except (ValueError, TypeError):
                pass
            time.sleep(0.2)
        raise RuntimeError('container did not reach Running through TS_* environment login')

    def prefs() -> dict:
        return json.loads(cli('debug', 'prefs').stdout)

    def restart() -> None:
        run('docker', 'restart', '-t', '10', node)
        ready()

    def disk_profiles(state: Path) -> list[dict]:
        data = json.loads((state / 'tailscaled.state').read_text())
        values = []
        for value in data.values():
            try:
                decoded = json.loads(base64.b64decode(value))
                if isinstance(decoded, dict) and 'AmneziaWG' in decoded:
                    values.append(decoded)
            except (ValueError, TypeError):
                continue
        return values

    try:
        with tempfile.TemporaryDirectory(prefix=token + '-') as temp:
            state = Path(temp)
            # An internal bridge has an up Ethernet interface (needed by the
            # daemon's connectivity monitor), but no route to the Internet.
            run('docker', 'network', 'create', '--internal', network)
            containers.append(control)
            run('docker', 'run', '-d', '--name', control, '--network', network,
                '--mount', f'type=bind,src={lab},dst=/lab,readonly',
                '--entrypoint', '/lab', args.image, 'control',
                '--listen', '127.0.0.1:18440', '--derp-listen', '127.0.0.1:18442',
                '--stun-server', '127.0.0.1:18443')
            time.sleep(0.5)
            containers.append(node)
            cmd = ['docker', 'run', '-d', '--name', node, '--network', 'container:' + control,
                   '--mount', f'type=bind,src={state},dst=/state',
                   '-e', 'TS_STATE_DIR=/state', '-e', 'TS_SOCKET=' + sock,
                   '-e', 'TS_USERSPACE=' + ('false' if args.kernel else 'true'),
                   '-e', 'TS_AUTH_ONCE=false', '-e', 'TS_NO_LOGS_NO_SUPPORT=true',
                   '-e', 'TS_AUTHKEY=isolated-test-placeholder-not-a-credential',
                   '-e', 'TS_HOSTNAME=issue18-env-test',
                   '-e', 'TS_EXTRA_ARGS=--login-server=' + url + ' --accept-routes']
            if args.kernel:
                cmd += ['--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun']
            cmd.append(args.image)
            run(*cmd)
            ready()
            initial = prefs()
            if initial.get('ControlURL') != url or not initial.get('RouteAll'):
                raise RuntimeError('TS_EXTRA_ARGS did not reach the daemon preferences')
            report['version'] = cli('version').stdout.strip()
            report['phases'].append('TS_AUTHKEY/TS_HOSTNAME/TS_EXTRA_ARGS/custom TS_SOCKET login')
            configs = [
                {'jc': 4, 'jmin': 700, 'jmax': 899},
                {'jc': 4, 'jmin': 700, 'jmax': 899, 's1': 19, 's2': 29, 's3': 15, 's4': 20,
                 'h1': {'min': 773603178, 'max': 773603214},
                 'h2': {'min': 1713856760, 'max': 1713856814},
                 'h3': {'min': 2188170348, 'max': 2188170388},
                 'h4': {'min': 3015010040, 'max': 3015010084},
                 'header_protection_key': secrets.token_hex(32),
                 'content_padding_addition': {'min': 5, 'max': 31}}
            ]
            for index, config in enumerate(configs):
                cli('awg', 'set', '--no-restart', json.dumps(config))
                active = prefs().get('AmneziaWG')
                if not active or active.get('JC') != 4:
                    raise RuntimeError('AWG set reported success but immediate preferences did not change')
                profiles = disk_profiles(state)
                if not any(p.get('AmneziaWG') == active for p in profiles):
                    raise RuntimeError('AWG preferences were not written into tailscaled.state')
                restart()
                if prefs().get('AmneziaWG') != active:
                    raise RuntimeError('AWG preferences changed across containerboot restart')
                report['phases'].append(f'AWG v{index + 2} immediate read, disk write and restart')
            cli('awg', 'reset', '--no-restart')
            restart()
            if prefs().get('AmneziaWG', {}).get('JC', 0):
                raise RuntimeError('AWG reset did not survive restart')
            report['phases'].append('AWG reset persisted')
            if args.h3:
                cli('awg', 'transport', '--yes', '--no-restart', 'http3-ip')
                staged = json.loads(cli('awg', 'status', '--json').stdout)
                if staged['desired_mode'] != 'http3-ip' or not staged['pending_restart']:
                    raise RuntimeError('H3 mode was not staged')
                restart()
                active = json.loads(cli('awg', 'status', '--json').stdout)
                if active['active_mode'] != 'http3-ip' or active['pending_restart'] or not active.get('identity'):
                    raise RuntimeError('H3 mode/identity did not activate after restart')
                identity = active['identity']
                restart()
                again = json.loads(cli('awg', 'status', '--json').stdout)
                if again['active_mode'] != 'http3-ip' or again['identity'] != identity:
                    raise RuntimeError('H3 identity changed across restart')
                report['phases'].append('QUIC staged activation and identity persisted across two restarts')
                for config in configs:
                    cli('awg', 'set', '--yes', '--no-restart', json.dumps(config))
                    pending = json.loads(cli('awg', 'status', '--json').stdout)
                    saved_awg = prefs().get('AmneziaWG')
                    if pending['active_mode'] != 'http3-ip' or pending['desired_mode'] != 'native' or not pending['awg_configured']:
                        raise RuntimeError('selecting AWG did not stage native with saved parameters')
                    if not any(p.get('AmneziaWG') == saved_awg for p in disk_profiles(state)):
                        raise RuntimeError('staged AWG did not reach disk')
                    restart()
                    active = json.loads(cli('awg', 'status', '--json').stdout)
                    if active['active_mode'] != 'native' or prefs().get('AmneziaWG') != saved_awg:
                        raise RuntimeError('AWG did not activate after one restart')
                    cli('awg', 'set', '--yes', '--no-restart', 'quic')
                    if prefs().get('AmneziaWG', {}).get('JC', 0):
                        raise RuntimeError('selecting QUIC did not clear AWG automatically')
                    restart()
                    if json.loads(cli('awg', 'status', '--json').stdout)['active_mode'] != 'http3-ip':
                        raise RuntimeError('QUIC did not activate after automatic AWG clearing')
                report['phases'].append('QUIC to AWG v2/v3 to QUIC without manual reset or repeated configuration')
            report['passed'] = True
    except Exception as exc:
        report['error'] = str(exc)
        report['test_logs'] = {}
        for name in containers:
            logs = run('docker', 'logs', '--tail', '45', name, check=False)
            report['test_logs'][name] = (logs.stdout + logs.stderr)[-6000:]
    finally:
        for name in reversed(containers):
            p = run('docker', 'rm', '-f', name, check=False)
            if p.returncode and 'No such container' not in p.stderr:
                report['cleanup_errors'].append(p.stderr[-500:])
        p = run('docker', 'network', 'rm', network, check=False)
        if p.returncode and 'not found' not in p.stderr:
            report['cleanup_errors'].append(p.stderr[-500:])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    if not report['passed'] or report['cleanup_errors']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
