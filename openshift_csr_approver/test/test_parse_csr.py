import unittest
import unittest.mock as mock

import yaml
import kubernetes.client as k8s
import OpenSSL

from openshift_csr_approver import approver as oca


CSR_VALID = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-valid',
        uid='c6c9be5a-e66a-4d35-be99-9a59f766539b'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='c6c9be5a-e66a-4d35-be99-9a59f766539b',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRQ2xjcHM5CnhyL3hFaFdEbG4xR3lRanU0WW1pQTZkaVVkdzh6LzQ1WXZPODh0L2w1bmVlZUtMd1ZpZysrRk9zeXpSZ1p4elIKTHVLT0JzRDRGU0FKZGFQdkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFvZFRzSWRXUExmbkR1TE9GTWJSZCtkc3Q5WjlLY3dTQ043eWMKdU14YzRXVmhvRGZpTUtOUllPcEZ6YUZPZVF2SFJ1RVJWQXY0c3BnL21LOFQrN01JN1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus()
)


CSR_INVALID = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-valid',
        uid='c6c9be5a-e66a-4d35-be99-9a59f766539b'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='c6c9be5a-e66a-4d35-be99-9a59f766539b',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRQ2xjcHM5CnhyL3hFaFdEbG4xR3lRanU0WW1pQTZkaVVkTHISISDELIBERATELYBROKENdzh6LzQ1WXZPODh0L2w1bmVlZUtMd1ZpZysrRk9zeXpSZ1p4elIKTHVLT0JzRDRGU0FKZGFQdkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFvZFRzSWRXUExmbkR1TE9GTWJSZCtkc3Q5WjlLY3dTQ043eWMKdU14YzRXVmhvRGZpTUtOUllPcEZ6YUZPZVF2SFJ1RVJWQXY0c3BnL21LOFQrN01JN1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus()
)


class ParseCsrTest(unittest.TestCase):

    def test_parse_valid_csr(self):
        csr = CSR_VALID
        parsed = oca.parse_csr(csr)
        self.assertEqual(parsed.get_subject().O, 'system:nodes')
        self.assertEqual(parsed.get_subject().CN, 'system:node:master-01')
        ext = str(parsed.get_extensions()[0])
        sans = ext.split(', ')
        self.assertEqual(len(sans), 4)
        self.assertIn('DNS:master-01', sans)
        self.assertIn('DNS:master-01.os.example.com', sans)
        self.assertIn('IP Address:10.42.0.1', sans)
        self.assertIn('IP Address:192.168.42.1', sans)

    def test_parse_invalid_csr(self):
        csr = CSR_INVALID
        with self.assertRaises(OpenSSL.crypto.Error):
            oca.parse_csr(csr)
