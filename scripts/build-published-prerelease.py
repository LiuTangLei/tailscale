#!/usr/bin/env python3
"""Build prerelease assets using only the published dependency graph.

No local replace, source overlay, credentials, production state or server
access. Outputs must be outside this checkout. GitHub publication is separate.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

WG = 'github.com/LiuTangLei/wireguard-go'
WG_VERSION = 'v0.0.31'
QUIC = 'github.com/quic-go/quic-go'
QUIC_FORK = 'github.com/LiuTangLei/quic-go'
QUIC_VERSION = 'v0.62.0-tailscale.1'
PLATFORMS = ('linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64', 'windows/amd64', 'windows/arm64')


def command(argv: list[str], env: dict[str, str], timeout: int = 240) -> str:
    p = subprocess.run(argv, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{argv[0]} failed ({p.returncode}): {p.stderr[-4000:]}')
    return p.stdout


def decode_many(text: str) -> list[dict]:
    result, decoder = [], json.JSONDecoder()
    while text.strip():
        obj, end = decoder.raw_decode(text.lstrip())
        result.append(obj)
        text = text.lstrip()[end:]
    return result


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--tag', default='v1.102.3-quic.1')
    p.add_argument('--jobs', type=int, default=2)
    a = p.parse_args()
    if not 1 <= a.jobs <= 4:
        p.error('jobs must be 1..4')
    root = Path.cwd().resolve()
    out = a.output.resolve()
    if out == root or root in out.parents:
        p.error('output must be outside the checkout')
    env = os.environ.copy()
    env.update(GOWORK='off', GOFLAGS='', GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org', GONOSUMDB='', GOPRIVATE='', CGO_ENABLED='0', GOMAXPROCS='3')
    for k in ('GOOS', 'GOARCH', 'GOARM', 'GO386', 'GOAMD64', 'GOMIPS', 'GOMIPS64', 'TAGS', 'TS_USE_TOOLCHAIN'):
        env.pop(k, None)
    if command(['git', 'status', '--porcelain'], env).strip():
        raise RuntimeError('release source must have a clean working tree')
    commit = command(['git', 'rev-parse', 'HEAD'], env).strip()
    if command(['git', 'rev-parse', a.tag + '^{commit}'], env).strip() != commit:
        raise RuntimeError('release tag does not identify the current commit')
    version_vars = {}
    for line in command(['sh', './build_dist.sh', 'shellvars'], env).splitlines():
        if '=' in line:
            k, value = line.split('=', 1)
            parts = shlex.split(value)
            version_vars[k] = parts[0] if parts else ''
    long_version = version_vars.get('VERSION_LONG', '')
    if commit[:9] not in long_version or 'dirty' in long_version:
        raise RuntimeError('Tailscale linker version does not identify the clean source commit')
    modules = decode_many(command(['go', 'list', '-mod=readonly', '-m', '-json', WG, QUIC], env))
    selected = {m['Path']: m for m in modules}
    if selected.get(WG, {}).get('Version') != WG_VERSION or selected[WG].get('Replace'):
        raise RuntimeError('WG version is not the published release')
    replacement = selected.get(QUIC, {}).get('Replace') or {}
    if replacement.get('Path') != QUIC_FORK or replacement.get('Version') != QUIC_VERSION or not replacement.get('Sum'):
        raise RuntimeError('QUIC is not the checksum-verified published fork')
    command(['go', 'mod', 'verify'], env)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        'release_tag': a.tag, 'source_commit': commit, 'source_dirty': False, 'long_version': long_version,
        'go_version': command(['go', 'version'], env).strip(),
        'dependency_mode': 'published Go modules; no local paths or overlays',
        'dependencies': {
            WG: {'version': WG_VERSION, 'sum': selected[WG].get('Sum'), 'commit': '8835972ec5d8acec8e028af84261fc5be3be6648'},
            QUIC_FORK: {'version': QUIC_VERSION, 'sum': replacement['Sum'], 'commit': '7f38a9286424f7d979bde30dc92ebdef161a6266'},
        },
        'assets': [],
        'runtime_scope': 'standalone CLI/daemon binaries; not signed application installers, APKs or IPAs',
    }

    def build(platform: str, name: str) -> dict:
        goos, arch = platform.split('/')
        filename = f'{name}-{goos}-{arch}' + ('.exe' if goos == 'windows' else '')
        path = out / filename
        started = time.monotonic()
        command(['sh', './build_dist.sh', '-o', str(path), './cmd/' + name], {**env, 'GOOS': goos, 'GOARCH': arch})
        info = command(['go', 'version', '-m', str(path)], env)
        # The CLI is an API client and need not link either crypto engine.
        # Every daemon must link both exact published modules.
        if name == 'tailscaled':
            for line in (f'\tdep\t{WG}\t{WG_VERSION}\t', f'\t=>\t{QUIC_FORK}\t{QUIC_VERSION}\t'):
                if line not in info:
                    raise RuntimeError(f'{filename}: missing expected build metadata {line!r}')
        # Tailscale uses explicit linker stamps; generic Go VCS fields are not
        # emitted by every toolchain/worktree combination. Validate them when
        # present, and always check the actual linked Tailscale version bytes.
        if ('vcs.revision=' in info and f'vcs.revision={commit}' not in info) or 'vcs.modified=true' in info:
            raise RuntimeError(f'{filename}: incorrect VCS build metadata')
        if long_version.encode() not in path.read_bytes():
            raise RuntimeError(f'{filename}: missing linked Tailscale source version')
        if 'ts_dev_wg_over_quic' in info or '/Users/lei/code/tailscale-all/quic-go' in info:
            raise RuntimeError('development-only code or local dependency leaked into release')
        if goos == 'darwin':
            # Standalone test binaries use an ad-hoc signature, not a Developer
            # ID / notarized application signature. Intel cross-builds may not
            # get an automatic linker signature, so sign both architectures.
            command(['/usr/bin/codesign', '--force', '--sign', '-', str(path)], env)
            command(['/usr/bin/codesign', '--verify', '--strict', str(path)], env)
        result = {'name': filename, 'bytes': path.stat().st_size, 'sha256': digest(path), 'platform': platform, 'links_packet_engines': name == 'tailscaled', 'linked_long_version': long_version, 'seconds': round(time.monotonic() - started, 2)}
        print('BUILT', filename, result['sha256'], flush=True)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futures = [ex.submit(build, platform, name) for platform in PLATFORMS for name in ('tailscale', 'tailscaled')]
        for f in concurrent.futures.as_completed(futures):
            manifest['assets'].append(f.result())
    manifest['assets'].sort(key=lambda x: x['name'])
    if command(['git', 'rev-parse', 'HEAD'], env).strip() != commit or command(['git', 'status', '--porcelain'], env).strip():
        raise RuntimeError('source changed during build; do not publish')
    (out / 'BUILD-MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    checksums = [f"{x['sha256']}  {x['name']}" for x in manifest['assets']]
    checksums.append(f"{digest(out / 'BUILD-MANIFEST.json')}  BUILD-MANIFEST.json")
    (out / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
    print('ALL 12 RELEASE BINARIES VERIFIED', commit, flush=True)


if __name__ == '__main__':
    main()
