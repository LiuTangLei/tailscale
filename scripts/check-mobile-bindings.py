#!/usr/bin/env python3
"""Compile the existing mobile binding packages against a selected Go workspace.
No apps are signed/installed. Reads pre-existing validation .work files only.
"""
from __future__ import annotations
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import time


def output(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--android-root', type=Path, required=True)
    p.add_argument('--ios-root', type=Path, required=True)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--timeout', type=int, default=90)
    a = p.parse_args()
    compiler = a.ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin'
    jobs = []
    for arch, triple in [('arm64', 'aarch64-linux-android'), ('arm', 'armv7a-linux-androideabi'), ('386', 'i686-linux-android'), ('amd64', 'x86_64-linux-android')]:
        env = {'GOOS': 'android', 'GOARCH': arch, 'CGO_ENABLED': '1', 'CC': str(compiler / (triple + '26-clang'))}
        if arch == 'arm': env['GOARM'] = '7'
        jobs.append(('android-' + arch, a.android_root, env, 'Android NDK API 26 package compilation'))
    for name, sdk, triple, minimum in [
        ('ios-device', 'iphoneos', 'arm64-apple-ios15.0', '-miphoneos-version-min=15.0'),
        ('ios-simulator', 'iphonesimulator', 'arm64-apple-ios15.0-simulator', '-mios-simulator-version-min=15.0'),
        ('tvos-sdk-library', 'appletvos', 'arm64-apple-tvos17.0', '-mtvos-version-min=17.0')]:
        path = output(['xcrun', '--sdk', sdk, '--show-sdk-path'])
        env = {'GOOS': 'ios', 'GOARCH': 'arm64', 'CGO_ENABLED': '1', 'CC': 'clang -target ' + triple,
               'CGO_CFLAGS': '-isysroot ' + path + ' ' + minimum, 'CGO_LDFLAGS': '-isysroot ' + path + ' ' + minimum}
        jobs.append((name, a.ios_root, env, 'Package/archive compilation only; no app target, signing or runtime proof'))
    result = {'core_commit': output(['git', 'rev-parse', 'HEAD']),
              'core_dirty': bool(output(['git', 'status', '--porcelain'])),
              'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'results': [], 'passed': False}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    for name, root, settings, scope in jobs:
        work = root / 'http3-validation.work'
        if not work.is_file(): raise ValueError('Missing explicitly prepared validation workspace: ' + str(work))
        env = os.environ.copy()
        for key in ('GOOS', 'GOARCH', 'GOARM', 'GO386', 'GOFLAGS', 'CGO_ENABLED', 'CGO_CFLAGS', 'CGO_LDFLAGS', 'CC'):
            env.pop(key, None)
        env.update(settings)
        env['GOWORK'] = str(work)
        cmd = ['go', 'build', '-mod=readonly', '-p=3', './libtailscale']
        started = time.monotonic()
        proc = subprocess.Popen(cmd, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            log, _ = proc.communicate(timeout=a.timeout)
            status = 'PASS' if proc.returncode == 0 else 'FAIL'
        except subprocess.TimeoutExpired:
            proc.terminate()
            try: log, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); log, _ = proc.communicate()
            status = 'TIMEOUT'
        logpath = a.output.with_name(name + '.log')
        logpath.write_text(log)
        row = {'target': name, 'status': status, 'env': settings, 'command': cmd, 'workspace': str(work),
               'app_commit': output(['git', 'rev-parse', 'HEAD'], root),
               'tracked_source_clean': subprocess.run(['git', 'diff', '--quiet'], cwd=root).returncode == 0,
               'seconds': round(time.monotonic()-started, 3), 'scope': scope, 'runtime_verified': False,
               'log': str(logpath), 'exit': proc.returncode}
        result['results'].append(row)
        a.output.write_text(json.dumps(result, indent=2) + '\n')
        print(name, status, row['seconds'], log[-600:] if status != 'PASS' else '', flush=True)
    result['passed'] = len(result['results']) == len(jobs) and all(r['status'] == 'PASS' for r in result['results'])
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    if not result['passed']: raise SystemExit(1)


if __name__ == '__main__': main()
