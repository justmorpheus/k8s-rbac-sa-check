# k8s-rbac-security-check

This script checks several Kubernetes RBAC configurations that can lead to security issues, such as privilege escalation. So far, the script checks for ClusterRoles and Roles that have permissions considered as risky due to security reasons.

In addition, the script is able to recognize if the Role/ClusterRole has been assigned to any subject (service account, user, group). Moreover, if it has been assigned to a service account, the script will report if the service account is in use by any pod.

## Usage
To use the script, simply run _python3 rbac_check.py_

By default, service accounts, users and groups are checked. However, it is possible to not scan for any of those subjects by using the options --no-service-accounts, --no-users and --no-groups respectively.

It is also possible to export the results in CSV format by using the --output [FILENAME] option

## Sample report
The following image shows a sample output of the script.

![image alt text](https://github.com/edurra/k8s-rbac-security-check/blob/main/rbac_check.PNG)

## Thanks
- Original author: https://github.com/edurra
- Modified via chatgpt4o
