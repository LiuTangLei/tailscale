#!/usr/bin/env python3
"""Keep transport correctness separate from the user's 95% WG throughput gate.

Consumes one same-topology kernel-iperf report. Does not run commands, contact
servers or modify configuration. Three complete samples per direction/flow are
required; profiling samples and bandwidth-capped baselines are not acceptance.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import statistics


def evaluate(document: dict, threshold: float = 0.95) -> dict:
    issues = []
    rows = []
    if not 0.95 <= threshold <= 1:
        raise ValueError('threshold must be at least 0.95 and at most 1')
    if document.get('passed') is not True or document.get('cleanup_errors'):
        issues.append('transport run or cleanup did not complete successfully')
    if document.get('profile') != 'standard':
        issues.append('WG baseline must use the standard, non-AWG profile')
    kernel = document.get('kernel_benchmark', {})
    if kernel.get('inner_protocol') != 'tcp':
        issues.append('requires the same kernel TCP benchmark for both modes')
    groups = {}
    baseline = {}
    for phase in document.get('phases', []):
        variant = phase.get('variant')
        if variant not in ('native', 'http3-ip-magicsock'):
            continue
        if phase.get('passed') is not True:
            issues.append(f'{variant} phase did not finish')
        controller = phase.get('controller', 'bbr-v1')
        for sample in phase.get('kernel_iperf', []):
            speed = sample.get('receiver_mbps')
            if sample.get('failed') or not isinstance(speed, (int, float)) or not math.isfinite(speed) or speed <= 0:
                issues.append('invalid receiver throughput sample')
                continue
            if sample.get('profiling_affected'):
                issues.append('profiling-affected sample is not a performance acceptance sample')
            if sample.get('protocol') != 'tcp' or sample.get('omitted_seconds', 0) != 0:
                issues.append('requires non-omitted TCP transfer measurements')
            key = (sample.get('direction'), sample.get('flows'))
            target = baseline if variant == 'native' else groups.setdefault(controller, {})
            target.setdefault(key, []).append(sample)
    if not baseline or not groups:
        issues.append('missing WG or H3 comparison')
    for controller, tests in groups.items():
        if set(tests) != set(baseline):
            issues.append(f'{controller}: directions/flow counts do not match WG baseline')
        directions = {key[0] for key in tests}
        if len(directions) < 2:
            issues.append(f'{controller}: both directions are required')
        for key, samples in sorted(tests.items()):
            original = baseline.get(key, [])
            rounds = {x.get('round') for x in samples}
            native_rounds = {x.get('round') for x in original}
            if len(rounds) < 3 or len(native_rounds) < 3 or len(rounds) != len(samples) or len(native_rounds) != len(original):
                issues.append(f'{key}: requires three distinct complete rounds, without duplicate or missing samples')
            if not original:
                continue
            limits = {x.get('offered_total_mbps') for x in original + samples}
            if len(limits) != 1 or not isinstance(next(iter(limits)), (int, float)):
                issues.append(f'{key}: offered rate limits differ or are unknown')
            wg = statistics.median(x['receiver_mbps'] for x in original)
            h3 = statistics.median(x['receiver_mbps'] for x in samples)
            limit = original[0].get('offered_total_mbps')
            if isinstance(limit, (int, float)) and wg >= limit * 0.97:
                issues.append(f'{key}: WG hit the offered-rate ceiling; this cannot prove uncapped WG parity')
            row = {'direction': key[0], 'flows': key[1], 'controller': controller,
                   'wg_median_mbps': wg, 'h3_median_mbps': h3, 'ratio': h3 / wg,
                   'required_mbps': threshold * wg, 'meets_ratio': h3 >= threshold * wg,
                   'wg_rounds': len(original), 'h3_rounds': len(samples)}
            rows.append(row)
            if not row['meets_ratio']:
                issues.append(f'{key}: H3 is below {threshold:.0%} of WG')
    return {'passed': not issues and bool(rows), 'threshold': threshold,
            'baseline_scope': 'same fork, standard native WireGuard; not an untouched official executable',
            'rows': rows, 'issues': issues}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.report.read_text()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
