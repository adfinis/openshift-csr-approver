# openshift-csr-approver

[![License](https://img.shields.io/github/license/adfinis-sygroup/openshift-csr-approver.svg?style=plastic)](LICENSE)
[![Build Status](https://travis-ci.com/adfinis-sygroup/openshift-csr-approver.svg?branch=master)](https://travis-ci.com/adfinis-sygroup/openshift-csr-approver)
[![Test Coverage](https://codecov.io/gh/adfinis-sygroup/openshift-csr-approver/branch/master/graph/badge.svg)](https://codecov.io/gh/adfinis-sygroup/openshift-csr-approver)

A tool for automatically approving kubelet CSRs in OpenShift 4
clusters set up on user-provisioned infrastructure.

When installed on user-provisioned infrastructure, the OpenShift
`machine-approver` does not automatically approve new kubelet CSRs.
On installer-provisioned infrastructure, the information from
`Machine` resources is used to decide which CSRs to approve and which
to deny.  On user-provisioned infrastructure, this information is not
available.  Instead, this tool relies on information provided by the
user in form of a ConfigMap resource.

The tool is installed as a Kubernetes `Cronjob` resource which starts
the CSR approval process every half hour.

## Installation

### Create a Project

We recommend to install this tool in an independent project/namespace.
Installation in an existing, shared namespace is possible as well.

Create a project to deploy this tool in:

```bash
$ oc new-project csr-approver
```

When deploying in an existing project, switch to it:

```bash
$ oc project existing-project
```

### Configure the Node CSR Spec

Open the file `deployment.yaml` in your preferred text editor.  The
first resource in this file is a Config Map named
`openshift-csr-approver`.  In this CM, configure the file `spec.yaml`
as follows:

```yaml
master-01:  # Name of a node, as it appears in "oc get node"
  # All DNS names expected to appear in the node's CSR
  names: [ master-01, master-01.os.example.com ]
  # All IP addresses expected to appear in the node's CSR
  ips: [ "10.42.0.10", "2001:db8::10" ]

# Another node
worker-01:
  names: [ worker-01, worker-01.os.example.com ]
  ips: [ "10.42.0.20", "2001:db8::20" ]

# Add all allowed nodes to the file
# ...
```

### Set Namespace

In the file `deployment.yaml`, you also need to set the ServiceAccount
namespace in the ClusterRoleBinding resource.

### Create the Resources

When you're done configuring the Node CSR Spec, create the resources
with

```bash
$ oc apply -f deployment.yaml
```

This creates the following resource:

- The `ConfigMap` you configured earlier
- A `ServiceAccount` used by the tool
- A `Secret` for the service account
- A `ClusterRole` with the permissions required for managing CSRs
- A `ClusterRoleBinding` binding the service account to the role
- A `CronJob` running the tool in a 30 minute interval

Since you're configuring a `ClusterRole` and `ClusterRoleBinding`,
corresponding administrative privileges are required for creating the
resources.


## Maintenance

### Managing Node Changes

Whenever a node is removed from or added to the cluster, the
`ConfigMap` should be adapted accordingly.  To do this, first
switch to the project the tool is deployed in:

```bash
$ oc project csr-approver
```

Then edit the configmap with

```bash
$ oc edit cm openshift-csr-approver
```

and apply your changes.

Alternatively, edit the `deployment.yaml` file and reapply it:

```bash
$ oc apply -f deployment.yaml
```
