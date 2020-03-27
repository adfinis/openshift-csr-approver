#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# openshift-csr-approver - Automatically approve some OpenShift CSRs.
#
# Copyright (C) 2020 Adfinis SyGroup AG
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-FileCopyrightText: 2020 Adfinis SyGroup AG
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, Dict, List, Tuple

import os
import sys
import argparse
import json
import base64
from datetime import datetime

import yaml
import kubernetes.client as k8s
import OpenSSL

from openshift_csr_approver.logging import logger, PrettyFormatter


def create_approval_patch(csr: k8s.V1beta1CertificateSigningRequest,
                          date: datetime) -> None:
    # Approving CSRs works by appending a condition of type
    # "Approved" to the status.
    message = f'This CSR for node {csr.metadata.name} was approved by openshift-csr-approver'  # noqa E501
    condition = k8s.V1beta1CertificateSigningRequestCondition(
        type='Approved',
        reason='openshift-csr-approver',
        message=message,
        # Ugly "+ Z" hack to make the kubernetes API accept the UTC timestamp
        last_update_time=date.isoformat(timespec='seconds') + 'Z'
    )
    if csr.status.conditions is None:
        csr.status.conditions = []
    csr.status.conditions.append(condition)


def build_k8s_client(args: argparse.Namespace) -> k8s.ApiClient:
    sa_path = args.sa_path
    token_path = os.path.join(sa_path, 'token')
    ca_path = os.path.join(sa_path, 'ca.crt')

    config = k8s.Configuration()
    config.logger_formatter = PrettyFormatter()
    config.debug = False
    config.host = args.endpoint

    if os.path.exists(token_path):
        with open(token_path, 'r') as tf:
            token = tf.read()
        config.api_key['authorization'] = token
        config.api_key_prefix['authorization'] = 'Bearer'
    if os.path.exists(ca_path):
        config.ssl_ca_cert = ca_path

    client = k8s.ApiClient(config)
    return client


def parse_node_csr_spec(filepath: str) -> Dict[str, Any]:
    filename: str = os.path.basename(filepath)
    with open(filepath, 'r') as cm:
        spec = yaml.safe_load(cm)
    node_csr_spec = {}
    if not isinstance(spec, dict):
        raise TypeError(f'{filename}: . is not of type dict')
    for nodename, node_spec in spec.items():
        if not isinstance(nodename, str):
            raise TypeError(f'{filename}: key {nodename} of . is not of type str')  # noqa E501
        if not isinstance(node_spec, dict):
            raise TypeError(f'{filename}: .{nodename} is not of type dict')
        if 'names' not in node_spec:
            raise KeyError(f'{filename}: .{nodename}.names is missing')
        if 'ips' not in node_spec:
            raise KeyError(f'{filename}: .{nodename}.ips is missing')
        if not isinstance(node_spec['names'], list):
            raise TypeError(f'{filename}: .{nodename}.names is not of type list')  # noqa E501
        if not isinstance(node_spec['ips'], list):
            raise TypeError(f'{filename}: .{nodename}.ips is not of type list')
        names = []
        ips = []
        for i, name in enumerate(node_spec['names']):
            if not isinstance(name, str):
                raise TypeError(f'{filename}: .{nodename}.names[{i}] is not of type str')  # noqa E501
            names.append(name)
        for i, ip in enumerate(node_spec['ips']):
            if not isinstance(ip, str):
                raise TypeError(f'{filename}: .{nodename}.ips[{i}] is not of type str')  # noqa E501
            ips.append(ip)
        node_csr_spec[nodename] = {
            'names': names,
            'ips': ips
        }
    return node_csr_spec


def parse_csr(csr: k8s.V1beta1CertificateSigningRequest) \
        -> OpenSSL.crypto.X509Req:
    b64 = csr.spec.request
    decoded = base64.b64decode(b64)
    parsed = OpenSSL.crypto.load_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, decoded)
    return parsed


def check_approve_csr(csr: k8s.V1beta1CertificateSigningRequest,
                      csr_info: OpenSSL.crypto.X509Req,
                      node_csr_spec: Dict[str, Any]) \
        -> Tuple[bool, str]:
    # Skip CSRs that are already approved or denied
    if csr.status.conditions is not None:
        for condition in csr.status.conditions:
            if condition.type in ['Approved', 'Denied']:
                update_time = condition.last_update_time
                ctype = condition.type
                reason = condition.reason
                return False, f'Already processed at {update_time} ({ctype}, {reason}), skipping'  # noqa E501

    # The logic implemented here is based on the checks in
    # https://github.com/openshift/cluster-machine-approver/blob/master/csr_check.go

    csr_username = csr.spec.username
    if not csr_username.startswith('system:node:'):
        return False, f'Not approving, username {csr_username} does not match system:node:<nodename>'  # noqa E501
    nodename = csr_username[len('system:node:'):]
    if len(nodename) == 0:
        return False, 'Not approving, node name is empty'
    if nodename not in node_csr_spec:
        return False, f'Not approving, node {nodename} not present in spec'
    node_spec = node_csr_spec[nodename]

    groups = csr.spec.groups
    for group in ['system:nodes', 'system:authenticated']:
        if group not in groups:
            return False, f'Not approving, required group {group} absent from CSR'  # noqa E501

    usages = csr.spec.usages
    if len(usages) != 3:
        return False, f'Not approving, wrong usages: {", ".join(usages)}'
    for usage in ['digital signature', 'key encipherment', 'server auth']:
        if usage not in usages:
            return False, f'Not approving, required usage {usage} absent from CSR'  # noqa E501

    subject = csr_info.get_subject()
    if subject.CN != csr_username:
        return False, f'Not approving, subject CN ({subject.CN}) does not match username {csr_username}'  # noqa E501
    if subject.O != 'system:nodes':
        return False, f'Not approving, subject O ({subject.O}) does not match system:nodes'  # noqa E501

    # Find SAN exstension
    csr_san = None
    for extension in csr_info.get_extensions():
        if extension.get_short_name() == b'subjectAltName':
            csr_san = extension
    if not csr_san:
        return False, f'Not approving, X509v3 extension Subject Alternative Name absent from CSR'  # noqa E501

    # Match each SAN against the allowed values from the CM
    # Only approve if ALL SANs are present in the node CSR spec
    parsed_san = str(csr_san)
    sans = parsed_san.split(', ')
    for name in sans:
        if name.startswith('DNS:'):
            dns_name = name[len('DNS:'):]
            if dns_name not in node_spec['names']:
                return False, f'Not approving, SAN {name} not allowed for node {nodename}'  # noqa E501
        elif name.startswith('IP Address:'):
            ip_name = name[len('IP Address:'):]
            if ip_name not in node_spec['ips']:
                return False, f'Not approving, SAN {name} not allowed for node {nodename}'  # noqa E501
        else:
            return False, f'Not approving, unexpected SAN {name}'

    # Approve CSR
    prettyname = ', '.join([
        f'{x[0].decode()} = {x[1].decode()}'
        for x in subject.get_components()
    ])
    return True, f'Marking CSR for approval: {prettyname}'


def iterate_csrs(csrs: k8s.V1beta1CertificateSigningRequestList,
                 node_csr_spec: Dict[str, Any]) \
        -> List[k8s.V1beta1CertificateSigningRequest]:
    if len(csrs.items) == 0:
        logger.info('No CSRs to process')
    csrs_to_approve = []
    for csr in csrs.items:
        # Broad error handling around each single CSR processing
        # prevents denial of service if a (maliciously crafted)
        # malformed CSR causes an unexpected error.
        try:
            csrinfo = parse_csr(csr)
            ok, msg = check_approve_csr(csr, csrinfo, node_csr_spec)
            name = csr.metadata.name
            logger.info(f'{name}: {msg}')
            if ok:
                csrs_to_approve.append(csr)
        except BaseException as e:
            # Log, but don't quit -> continue processing other CSRs
            logger.error(e, exc_info=True)
    return csrs_to_approve


def run_csr_approval(client: k8s.ApiClient,
                     node_csr_spec: Dict[str, Any]) -> None:
    api = k8s.CertificatesV1beta1Api(client)
    csrs: k8s.V1beta1CertificateSigningRequestList \
        = api.list_certificate_signing_request()
    now = datetime.utcnow()
    csrs_to_approve = iterate_csrs(csrs, node_csr_spec)
    for csr in csrs_to_approve:
        try:
            create_approval_patch(csr, now)
            api.replace_certificate_signing_request_approval(
                csr.metadata.name, body=csr)
        except BaseException as e:
            # Log, but don't quit -> continue processing other CSRs
            logger.error(e, exc_info=True)


def parse_arguments(args: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Auto-approve allowed cluster node CSRs')
    parser.add_argument('--api-endpoint', metavar='endpoint',
                        type=str, action='store', dest='endpoint',
                        default='https://kubernetes.default',
                        help='Base URL of the kubernetes API, e.g. https://api.openshift.example.com')  # noqa E501
    parser.add_argument('--config-file', metavar='/path/to/cm/mount/spec.yaml',
                        type=str, action='store', dest='cm_path',
                        default='/var/run/config/node-csr-spec/spec.yaml',
                        help='Path to the config file from the config map, e.g. /var/run/config/node-csr-spec/spec.yaml')  # noqa E501
    parser.add_argument('--service-account', metavar='/path/to/sa/mount',
                        type=str, action='store', dest='sa_path',
                        default='/var/run/secrets/service-account',
                        help='Path to the service account secret mount point, e.g. /var/run/secrets/service-account')  # noqa E501
    return parser.parse_args(args)


def main() -> None:
    args = parse_arguments(sys.argv[1:])
    try:
        client = build_k8s_client(args)
        node_csr_spec = parse_node_csr_spec(args.cm_path)
        run_csr_approval(client, node_csr_spec)
    except BaseException as e:
        logger.critical(e, exc_info=True)
        sys.exit(1)
