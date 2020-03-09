import unittest

import yaml
import kubernetes.client as k8s

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


CSR_WRONG_CN = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-wrong-cn',
        uid='bb66a03e-ae06-4e0c-bf5e-6b8382ec2d8c'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='bb66a03e-ae06-4e0c-bf5e-6b8382ec2d8c',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNakJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRRGpOVmlECi9VaEV3TkYyUlpGOTUwejVLeEw5SFBNT1AvNkNsYmxuUmJFOUFUUHhEVzR4amZzdFVBTHNleU43NVI4YkpwUWgKU212NkMreGR6TE5PdWdKZkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFCeXBQSWV4Uyt6N1kzQmVWY1UwRy8vUXIzZDNPOWxtYzFPMk4KSHI1QXFhak1QQzNMUU9ncTdhdFhPVDFGaU9ZbEo0YmUwNFdaOGFuV2doaVhuYjNzUlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus()
)


CSR_WRONG_SAN = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-wrong-san',
        uid='8d0d8924-7afb-417a-bb1f-00a4b50b536e'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='8d0d8924-7afb-417a-bb1f-00a4b50b536e',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRRFg5UGl6CkhRNkQxRUhqUms0NCttT3RSU21wTG9Bd0lCRS9PUHZaR1pKOVdING5NZHBHWWNDd3g1T3RsMjlodW5OeE5tZGwKc3c0T2RkckNvUU9GMzdOM0FnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TW9JWWJXRnpkR1Z5TFRBeUxtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUNod1RBCnFDb0NNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUExeU5BMFdPSkFFQy9SOFZkSWpxMkpYL0hLb25rUUo5c0FST1cKdmgzbGZxd0hvNDQ5VVZwWUJtYW5aQ2NVcHBIMWRUY0hLc0Y3T1FvMjkyUjJ5OE9DcXc9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus()
)


CSR_WRONG_USAGES = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-wrong-usages',
        uid='f7e4e7a5-f278-4796-9e5e-01e8fb210d20'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='f7e4e7a5-f278-4796-9e5e-01e8fb210d20',
        usages=[
            'digital signature',
            'key encipherment',
            'client auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRQ2xjcHM5CnhyL3hFaFdEbG4xR3lRanU0WW1pQTZkaVVkdzh6LzQ1WXZPODh0L2w1bmVlZUtMd1ZpZysrRk9zeXpSZ1p4elIKTHVLT0JzRDRGU0FKZGFQdkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFvZFRzSWRXUExmbkR1TE9GTWJSZCtkc3Q5WjlLY3dTQ043eWMKdU14YzRXVmhvRGZpTUtOUllPcEZ6YUZPZVF2SFJ1RVJWQXY0c3BnL21LOFQrN01JN1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus()
)


CSR_APPROVED = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-approved',
        uid='3585ad87-19d4-4729-b99a-a422cae24713'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='3585ad87-19d4-4729-b99a-a422cae24713',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRQ2xjcHM5CnhyL3hFaFdEbG4xR3lRanU0WW1pQTZkaVVkdzh6LzQ1WXZPODh0L2w1bmVlZUtMd1ZpZysrRk9zeXpSZ1p4elIKTHVLT0JzRDRGU0FKZGFQdkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFvZFRzSWRXUExmbkR1TE9GTWJSZCtkc3Q5WjlLY3dTQ043eWMKdU14YzRXVmhvRGZpTUtOUllPcEZ6YUZPZVF2SFJ1RVJWQXY0c3BnL21LOFQrN01JN1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus(
        conditions=[
            k8s.V1beta1CertificateSigningRequestCondition(
                last_update_time='2020-03-06T17:45:00+01:00',
                type='Approved',
                reason='Testing',
                message='Approved for testing purposes'
            )
        ]
    )
)


CSR_DENIED = k8s.V1beta1CertificateSigningRequest(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequest',
    metadata=k8s.V1ObjectMeta(
        name='csr-denied',
        uid='bbfebbed-c71d-4eb4-87e8-8ba05fc29198'
    ),
    spec=k8s.V1beta1CertificateSigningRequestSpec(
        groups=[
            'system:nodes',
            'system:authenticated'
        ],
        uid='bbfebbed-c71d-4eb4-87e8-8ba05fc29198',
        usages=[
            'digital signature',
            'key encipherment',
            'server auth'
        ],
        username='system:node:master-01',
        request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbTFoYzNSbGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRQ2xjcHM5CnhyL3hFaFdEbG4xR3lRanU0WW1pQTZkaVVkdzh6LzQ1WXZPODh0L2w1bmVlZUtMd1ZpZysrRk9zeXpSZ1p4elIKTHVLT0JzRDRGU0FKZGFQdkFnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1cxaGMzUmxjaTB3TVlJWWJXRnpkR1Z5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUJod1RBCnFDb0JNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFvZFRzSWRXUExmbkR1TE9GTWJSZCtkc3Q5WjlLY3dTQ043eWMKdU14YzRXVmhvRGZpTUtOUllPcEZ6YUZPZVF2SFJ1RVJWQXY0c3BnL21LOFQrN01JN1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
    ),
    status=k8s.V1beta1CertificateSigningRequestStatus(
        conditions=[
            k8s.V1beta1CertificateSigningRequestCondition(
                last_update_time='2020-03-06T17:45:00+01:00',
                type='Denied',
                reason='Testing',
                message='Denied for testing purposes'
            )
        ]
    )
)


NODE_CSR_SPEC = '''
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


class CheckApproveValidCsr(unittest.TestCase):

    def setUp(self):
        self.spec = yaml.safe_load(NODE_CSR_SPEC)

    def test_check_valid_csr(self):
        csr = CSR_VALID
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertTrue(ok)

    def test_check_wrong_cn(self):
        csr = CSR_WRONG_CN
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertRegex(msg, '.*subject CN (.*) does not match.*')
        self.assertFalse(ok)

    def test_check_wrong_san(self):
        csr = CSR_WRONG_SAN
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertRegex(msg, '.*SAN (.*) not allowed for node.*')
        self.assertFalse(ok)

    def test_check_wrong_usages(self):
        csr = CSR_WRONG_USAGES
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertRegex(msg, '.*required usage (.*) absent.*')
        self.assertFalse(ok)

    def test_check_approved(self):
        csr = CSR_APPROVED
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertRegex(msg, '.*Already processed.*Approved.*')
        self.assertFalse(ok)

    def test_check_denied(self):
        csr = CSR_DENIED
        csrinfo = oca.parse_csr(csr)
        ok, msg = oca.check_approve_csr(csr, csrinfo, self.spec)
        self.assertRegex(msg, '.*Already processed.*Denied.*')
        self.assertFalse(ok)
