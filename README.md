# k8s-rbac-security-check

## Usage
This script checks several RBAC configurations that can lead to security issues, such as privilege escalation. In order to run the script, it is necessary to have python 3 installed as well as a Kubeconfig file with read permissions on the cluster.

By default, service accounts, users and groups are checked. However, it is possible to not scan for any of those subjects by using the options --no-service-accounts, --no-users and --no-groups respectively.

To use the script, simply run _python3 rbac_check.py_

## Sample report
The following image shows a sample output of the script.

![Alt text]([https://github.com/edurra/k8s-rbac-security-check/blob/main/rbac_check.PNG] "Output")

