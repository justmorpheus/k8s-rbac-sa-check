# k8s-rbac-security-check

This script audits Kubernetes Role-Based Access Control (RBAC) configurations to identify risky ClusterRoles and Roles in your cluster. It also checks which pods can be exec-ed into using different shells and whether they run as root or a non-root user.

## Features

- Identify Risky ClusterRoles and Roles: The script analyzes ClusterRoles and Roles to determine if they have potentially risky permissions such as reading secrets, executing on pods, impersonating users, etc.
- Check Pod Exec Permissions: The script attempts to exec into pods using different shells (/bin/bash, /bin/sh, sh, bash) and identifies if they run as root or a non-root user.
- Service Account Analysis: It checks which pods are using specific ServiceAccounts and provides detailed output regarding their exec permissions.

## Requirements

- Python 3.x
- Kubernetes Python client library
- colorama Python library

## Usage

### To run full scan to detailed output for each risky ClusterRole and Role.

```
python3 rbac-scan-full.py
```

- To use the script, simply run _python3 rbac_check.py

By default, service accounts, users and groups are checked.


## Thanks
- Original author: https://github.com/edurra
- Modified via chatgpt4o
