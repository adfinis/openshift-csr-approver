import unittest
import unittest.mock as mock

from collections import namedtuple

from openshift_csr_approver import approver as oca


VALID_SPEC = '''
---
master-01:
  names:
    - master-01
    - master-01.os.example.com
  ips:
    - 10.42.0.1
    - 192.168.42.1
worker-01:
  names: [worker-01, worker-01.os.example.com]
  ips: [10.42.0.11, 192.168.42.11]
'''


class ParseConfigmapTest(unittest.TestCase):

    def test_parse_valid(self):
        with mock.patch('builtins.open', mock.mock_open(read_data=VALID_SPEC)):
            parsed_spec = oca.parse_node_csr_spec('foo')

        self.assertIsInstance(parsed_spec, dict)
        self.assertEqual(len(parsed_spec), 2)
        self.assertIn('master-01', parsed_spec)
        self.assertIn('worker-01', parsed_spec)

        self.assertIsInstance(parsed_spec['master-01'], dict)
        self.assertIsInstance(parsed_spec['worker-01'], dict)
        self.assertIn('names', parsed_spec['master-01'])
        self.assertIn('ips', parsed_spec['master-01'])
        self.assertIn('names', parsed_spec['worker-01'])
        self.assertIn('ips', parsed_spec['worker-01'])

        self.assertIsInstance(parsed_spec['master-01']['names'], list)
        self.assertIsInstance(parsed_spec['master-01']['ips'], list)
        self.assertIsInstance(parsed_spec['worker-01']['names'], list)
        self.assertIsInstance(parsed_spec['worker-01']['ips'], list)
        self.assertEqual(len(parsed_spec['master-01']['names']), 2)
        self.assertEqual(len(parsed_spec['master-01']['ips']), 2)
        self.assertEqual(len(parsed_spec['worker-01']['names']), 2)
        self.assertEqual(len(parsed_spec['worker-01']['ips']), 2)

        self.assertIn('master-01', parsed_spec['master-01']['names'])
        self.assertIn('master-01.os.example.com',
                      parsed_spec['master-01']['names'])
        self.assertIn('10.42.0.1', parsed_spec['master-01']['ips'])
        self.assertIn('192.168.42.1', parsed_spec['master-01']['ips'])

        self.assertIn('worker-01', parsed_spec['worker-01']['names'])
        self.assertIn('worker-01.os.example.com',
                      parsed_spec['worker-01']['names'])
        self.assertIn('10.42.0.11', parsed_spec['worker-01']['ips'])
        self.assertIn('192.168.42.11', parsed_spec['worker-01']['ips'])
