#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('parity_gate', Path(__file__).with_name('verify-h3-wg-parity.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(ratio=1.0):
    phases = []
    for variant in ('native', 'http3-ip-magicsock'):
        samples = []
        for direction in ('A -> B', 'B -> A'):
            for round_number in (1, 2, 3):
                samples.append({'direction': direction, 'round': round_number, 'flows': 4,
                                'receiver_mbps': 300 * (ratio if variant != 'native' else 1),
                                'offered_total_mbps': 500, 'protocol': 'tcp', 'omitted_seconds': 0})
        phases.append({'variant': variant, 'passed': True, 'controller': 'bbr-v1', 'kernel_iperf': samples})
    return {'passed': True, 'cleanup_errors': [], 'profile': 'standard',
            'kernel_benchmark': {'inner_protocol': 'tcp'}, 'phases': phases}


class ParityGateTests(unittest.TestCase):
    def test_exact_threshold(self):
        self.assertTrue(module.evaluate(fixture(0.95))['passed'])
        self.assertFalse(module.evaluate(fixture(0.949))['passed'])

    def test_a_fast_direction_cannot_hide_a_slow_one(self):
        d = fixture(1.2)
        for s in d['phases'][1]['kernel_iperf'][:3]:
            s['receiver_mbps'] = 200
        self.assertFalse(module.evaluate(d)['passed'])

    def test_incomplete_failed_profiled_or_capped_run_rejected(self):
        cases = []
        d = fixture(); d['phases'][1]['kernel_iperf'].pop(); cases.append(d)
        d = fixture(); d['cleanup_errors'] = ['leftover service']; cases.append(d)
        d = fixture(); d['profile'] = 'awg2'; cases.append(d)
        d = fixture(); d['phases'][0]['kernel_iperf'][0]['profiling_affected'] = True; cases.append(d)
        d = fixture(); d['phases'][1]['kernel_iperf'][0]['offered_total_mbps'] = 250; cases.append(d)
        d = fixture()
        for phase in d['phases']:
            for s in phase['kernel_iperf']:
                s['receiver_mbps'] = 500
        cases.append(d)
        for d in cases:
            with self.subTest(report=d):
                self.assertFalse(module.evaluate(copy.deepcopy(d))['passed'])


if __name__ == '__main__':
    unittest.main()
