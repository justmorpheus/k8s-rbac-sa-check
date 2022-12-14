from kubernetes import client, config
from colorama import Fore, Style
import argparse

parser = argparse.ArgumentParser(description='Audit Kubernetes RBAC configurations')
parser.add_argument('--service-accounts', action=argparse.BooleanOptionalAction, default=True,
                    help="By default set to --service-accounts. If --no-service-accounts used, service accounts will not be evaluated")
parser.add_argument('--users', action=argparse.BooleanOptionalAction, default=True,
                    help="By default set to --users. If --no-users used, users will not be evaluated")
parser.add_argument('--groups', action=argparse.BooleanOptionalAction, default=True,
                    help="By default set to --groups. If --no-groups used, groups will not be evaluated")
args = parser.parse_args()

USE_SERVICE_ACCOUNTS = vars(args)['service_accounts']
USE_USERS = vars(args)['users']
USE_GROUPS = vars(args)['groups']

config.load_kube_config()
r1 = client.RbacAuthorizationV1Api()
v1 = client.CoreV1Api()


def get_cluster_role_bindings():
    cluster_role_bindings = r1.list_cluster_role_binding()
    cluster_role_bindings_dict = {}
    for crb in cluster_role_bindings.items:
        name = crb.metadata.name
        subjects = crb.subjects
        role = crb.role_ref.name
        if cluster_role_bindings_dict.get(role) == None:
            cluster_role_bindings_dict[role] = [[name, subjects]]
        else:
            cluster_role_bindings_dict[role].append([name, subjects])
    return cluster_role_bindings_dict


def get_cluster_roles():
    cluster_roles = r1.list_cluster_role()
    return cluster_roles.items


def get_role_bindings():
    role_bindings = r1.list_role_binding_for_all_namespaces()
    role_bindings_dict = {}
    for rb in role_bindings.items:
        name = rb.metadata.name
        subjects = rb.subjects
        namespace = rb.metadata.namespace
        full_name = namespace + "/" + name
        role = rb.role_ref.name
        full_role = namespace + "/" + role
        if role_bindings_dict.get(full_role) == None:
            role_bindings_dict[full_role] = [[full_name, subjects]]
        else:
            role_bindings_dict[full_role].append([full_name, subjects])
    return role_bindings_dict


def get_roles():
    roles = r1.list_role_for_all_namespaces()
    return roles.items


def get_service_account_pods():
    pods = v1.list_pod_for_all_namespaces(watch=False)
    service_accounts = {}
    for pod in pods.items:
        service_account = "default"
        if pod.spec.service_account != None:
            service_account = pod.spec.service_account
        pod_name = pod.metadata.name
        pod_namespace = pod.metadata.namespace
        service_account_full_name = pod_namespace + "/" + service_account
        if service_accounts.get(service_account_full_name):
            service_accounts[service_account_full_name].append(pod_namespace + "/" + pod_name)
        else:
            service_accounts[service_account_full_name] = [pod_namespace + "/" + pod_name]
    return service_accounts


def analyze_rule(rule):
    result = []
    if rule.resources != None:
        if "*" in rule.resources:
            result.append('{} all resources'.format("/".join(rule.verbs)))
        if 'secrets' in rule.resources:
            # Capability of reading secrets
            if '*' in rule.verbs or 'get' in rule.verbs or 'list' in rule.verbs or 'watch' in rule.verbs:
                result.append('read secrets')
        if 'pods' in rule.resources:
            # Capability of creating pods
            if '*' in rule.verbs or 'create' in rule.verbs or 'update' in rule.verbs or 'patch' in rule.verbs:
                result.append('create/update/patch pods')
            if '*' in rule.verbs or 'delete' in rule.verbs:
                result.append('delete pods')
        if 'deployments' in rule.resources:
            if '*' in rule.verbs or 'create' in rule.verbs or 'update' in rule.verbs or 'patch' in rule.verbs:
                result.append('create/update/patch deployments')
            if '*' in rule.verbs or 'delete' in rule.verbs:
                result.append('delete deployments')
        if 'pods/exec' in rule.resources:
            result.append('exec on pods')
        if ('volumes' in rule.resources or 'persistentvolumes' in rule.resources) and 'create' in rule.verbs:
            result.append('create new volumes')
        if 'roles' in rule.resources or 'clusterroles' in rule.resources:
            if 'escalate' in rule.verbs:
                result.append('create new {} with higher privileges'.format('/'.join(rule.resources))
            if 'bind' in rule.verbs:
                result.append('bind any {} to another subject'.format('/'.join(rule.resources))
        if ('serviceaccounts' in rule.resources or 'users' in rule.resources or 'groups' in rule.resources) and 'impersonate' in rule.verbs:
            result.append('impersonate any {}'.format('/'.join(rule.resources))
        if 'serviceaccounts/token' in rule.resources and 'create' on rule.resources:
            result.append('request tokens for service accounts')
    return result


def clean_bindings(bindings, service_account=True, groups=True, users=True):
    result = []
    for binding in bindings:
        binding_name = binding[0]
        subjects = []
        for subject in binding[1]:
            if service_account and subject.kind == "ServiceAccount":
                subjects.append(subject)
            if groups and subject.kind == "Group":
                subjects.append(subject)
            if users and subject.kind == "User":
                subjects.append(subject)
        if len(subjects) > 0:
            result.append([binding_name, subjects])
    return result


def get_risky_cluster_roles():
    # cluster_roles.items[0].metadata.name
    cluster_roles = get_cluster_roles()
    analyzed_roles = {}
    for cluster_role in cluster_roles:
        name = cluster_role.metadata.name
        rules = cluster_role.rules
        for rule in rules:
            analyzed_roles[name] = analyze_rule(rule)

    risky_cluster_roles = {}
    for role in analyzed_roles.keys():
        if len(analyzed_roles[role]) > 0:
            risky_cluster_roles[role] = analyzed_roles[role]
    return risky_cluster_roles


def get_risky_roles():
    roles = get_roles()
    analyzed_roles = {}
    for role in roles:
        name = role.metadata.name
        rules = role.rules
        namespace = role.metadata.namespace
        full_name = namespace + "/" + name
        for rule in rules:
            analyzed_roles[full_name] = analyze_rule(rule)

    risky_roles = {}
    for role in analyzed_roles.keys():
        if len(analyzed_roles[role]) > 0:
            risky_roles[role] = analyzed_roles[role]
    return risky_roles


def print_risky_roles_info(type = "ClusterRole"):
    if type == "ClusterRole":
        print("Discovering risky ClusterRoles")
        risky_roles = get_risky_cluster_roles()
        role_bindings = get_cluster_role_bindings()
    if type == "Role":
        print("Discovering risky Roles")
        risky_roles = get_risky_roles()
        role_bindings = get_role_bindings()
    pods_svc = get_service_account_pods()

    for risky_r in risky_roles.keys():
        print("--------")
        if type == "Role":
            full_name_split = risky_r.split("/")
            role_name = full_name_split[1]
            namespace = full_name_split[0]
            print("{type} name: " + Fore.YELLOW + "{}".format(
                role_name) + Style.RESET_ALL + " on namespace " + Fore.YELLOW + namespace)
        if type == "ClusterRole":
            print("{type} name: " + Fore.YELLOW + "{}".format(risky_r))
        print(Style.RESET_ALL)
        print("    - Allows to: ")
        for capability in risky_roles[risky_r]:
            print(Fore.YELLOW + "        {}".format(capability))
            print(Style.RESET_ALL)
        bindings = role_bindings.get(risky_r)
        if bindings == None:
            bindings = []

        bindings = clean_bindings(bindings, service_account=USE_SERVICE_ACCOUNTS, groups=USE_GROUPS, users=USE_USERS)

        if bindings != None and len(bindings) > 0:
            print("    - Assigned to: ")
            for binding in bindings:
                for subject in binding[1]:
                    if subject.kind == "ServiceAccount":
                        print(
                            "        - The " + Fore.YELLOW + subject.namespace + "/" + subject.name + Style.RESET_ALL + " " + subject.kind + " through the " + Fore.YELLOW +
                            binding[0] + Style.RESET_ALL + " {type}")

                        if pods_svc.get(subject.namespace + "/" + subject.name):
                            print(Fore.RED + "            - The pod(s) {} are using this service account".format(
                                ",".join(pods_svc[subject.namespace + "/" + subject.name])))
                        else:
                            print(Fore.GREEN + "            - There are no pods using this service account")
                        print(Style.RESET_ALL)
                    else:
                        print(
                            "        - The " + Fore.YELLOW + subject.name + Style.RESET_ALL + " " + subject.kind + " through the " + Fore.YELLOW +
                            binding[0] + Style.RESET_ALL + " {type}" + Style.RESET_ALL)
                        print(Style.RESET_ALL)

        else:
            print(Fore.GREEN + "    - Not assigned to any subject")
            print(Style.RESET_ALL)


if __name__ == "__main__":
    print_risky_roles_info(type = "ClusterRole")
    print("\n###########################\n")
    print_risky_roles_info(type = "Role")
