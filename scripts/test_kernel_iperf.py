import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('kernel_iperf', Path(__file__).with_name('kernel-iperf.py'))
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)

class ReceiverSummaryTest(unittest.TestCase):
    def fixture(self):
        return {'start': {'test_start': {'reverse': 0}}, 'end': {'sum_received':
                {'sender': False, 'lost_packets': 0, 'packets': 100, 'bytes': 96000, 'bits_per_second': 768000}},
                'server_output_text': '[  5]   0.00-10.03 sec  93.8 KBytes  76.6 Kbits/sec  0.002 ms  4/100 (4%)  receiver\n'}

    def test_forward_client_zero_is_not_receiver_loss(self):
        result, source = kernel.receiver_summary(self.fixture(), True)
        self.assertEqual((result['lost_packets'], result['packets'], result['lost_percent']), (4, 100, 4))
        self.assertEqual(result['bits_per_second'], 768000)
        self.assertEqual(source, 'server.text.receiver')

    def test_exact_server_json_takes_precedence(self):
        doc = self.fixture()
        actual = {'sender': False, 'lost_packets': 9, 'packets': 100, 'bits_per_second': 700001, 'bytes': 90000}
        doc['server_output_json'] = {'end': {'sum': actual}}
        self.assertEqual(kernel.receiver_summary(doc, True), (actual, 'server.end.receiver'))

    def test_reverse_uses_client_receiver(self):
        doc = self.fixture()
        doc['start']['test_start']['reverse'] = 1
        self.assertEqual(kernel.receiver_summary(doc, True)[0]['lost_packets'], 0)

    def test_missing_or_ambiguous_forward_receiver_fails(self):
        doc = self.fixture()
        for text in ('', doc['server_output_text'] + doc['server_output_text'].replace('[  5]', '[  6]')):
            doc['server_output_text'] = text
            with self.assertRaises(RuntimeError):
                kernel.receiver_summary(doc, True)

if __name__ == '__main__':
    unittest.main()
