import unittest

import yaml
import kubernetes.client as k8s

from openshift_csr_approver import approver as oca


REQUESTS = k8s.V1beta1CertificateSigningRequestList(
    api_version='certificates.k8s.io/v1beta1',
    kind='CertificateSigningRequestList',
    items=[
        # VALID CSR
        k8s.V1beta1CertificateSigningRequest(
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
        ),
        # ALREADY APPROVED CSR
        k8s.V1beta1CertificateSigningRequest(
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
        ),
        # ALREADY DENIED CSR
        k8s.V1beta1CertificateSigningRequest(
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
        ),
        # CSR WITH WRONG CN
        k8s.V1beta1CertificateSigningRequest(
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
        ),
        # CSR WITH WRONG USAGES
        k8s.V1beta1CertificateSigningRequest(
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
        ),
        # OTHER OK CSR
        k8s.V1beta1CertificateSigningRequest(
            api_version='certificates.k8s.io/v1beta1',
            kind='CertificateSigningRequest',
            metadata=k8s.V1ObjectMeta(
                name='csr-valid-worker',
                uid='7f73912a-cd87-4fad-bdc7-44a82607b897'
            ),
            spec=k8s.V1beta1CertificateSigningRequestSpec(
                groups=[
                    'system:nodes',
                    'system:authenticated'
                ],
                uid='7f73912a-cd87-4fad-bdc7-44a82607b897',
                usages=[
                    'digital signature',
                    'key encipherment',
                    'server auth'
                ],
                username='system:node:worker-01',
                request='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQlFUQ0I3QUlCQURBM01SVXdFd1lEVlFRS0RBeHplWE4wWlcwNmJtOWtaWE14SGpBY0JnTlZCQU1NRlhONQpjM1JsYlRwdWIyUmxPbmR2Y210bGNpMHdNVEJjTUEwR0NTcUdTSWIzRFFFQkFRVUFBMHNBTUVnQ1FRRG5yN0c4ClZqK3Q0aFQ2S1Zka0lyZ2lWTGcweUlRUXpQM1drN1FYTDczN0ZQQWowYTEvTkh2OW9RUGlsbGlWaC9oVEJ1eGgKaTAvU2FzeTJ0TkhIbGVGN0FnTUJBQUdnVURCT0Jna3Foa2lHOXcwQkNRNHhRVEEvTUQwR0ExVWRFUUVCL3dRegpNREdDQ1hkdmNtdGxjaTB3TVlJWWQyOXlhMlZ5TFRBeExtOXpMbVY0WVcxd2JHVXVZMjl0aHdRS0tnQUxod1RBCnFDb0xNQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFkRHBzenAyQjdNZnJMZk51aXRuTndsU09hckl4OXdrZzUxcG8KNkxFMXdaQ1psMXRibm5ZSU4zOXlCSnpSamorZ2RFNy9BSGM4QTlkUjFOSXZ0NUJPZHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K'  # noqa E501
            ),
            status=k8s.V1beta1CertificateSigningRequestStatus()
        )
    ]
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


class TestIterateCsrs(unittest.TestCase):

    def setUp(self):
        self.spec = yaml.safe_load(NODE_CSR_SPEC)

    def test_iterate_csrs(self):
        csrs_to_approve = oca.iterate_csrs(REQUESTS, self.spec)
        # make sure only the correct CSRs are approved
        self.assertEqual(len(csrs_to_approve), 2)
        master = csrs_to_approve[0]
        worker = csrs_to_approve[1]
        self.assertEqual(master.metadata.name, 'csr-valid')
        self.assertEqual(worker.metadata.name, 'csr-valid-worker')
