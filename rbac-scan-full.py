from kubernetes import client, config, stream
from colorama import Fore, Style
import os

# Load Kubernetes configuration
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
        if cluster_role_bindings_dict.get(role) is None:
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
        if role_bindings_dict.get(full_role) is None:
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
        if pod.spec.service_account is not None:
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
    if rule.resources is not None:
        if "*" in rule.resources:
            result.append('{} all resources'.format("/".join(rule.verbs)))
        if 'secrets' in rule.resources:
            if '*' in rule.verbs or 'get' in rule.verbs or 'list' in rule.verbs or 'watch' in rule.verbs:
                result.append('read secrets')
        if 'pods' in rule.resources:
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
                result.append('create new {} with higher privileges'.format('/'.join(rule.resources)))
            if 'bind' in rule.verbs:
                result.append('bind any {} to another subject'.format('/'.join(rule.resources)))
        if ('serviceaccounts' in rule.resources or 'users' in rule.resources or 'groups' in rule.resources) and 'impersonate' in rule.verbs:
            result.append('impersonate any {}'.format('/'.join(rule.resources)))
        if 'serviceaccounts/token' in rule.resources and 'create' in rule.resources:
            result.append('request tokens for service accounts')
    return result

def clean_bindings(bindings):
    result = []
    if bindings is None:
        return result
    for binding in bindings:
        binding_name = binding[0]
        subjects = []
        if binding[1] is None:
            continue
        for subject in binding[1]:
            subjects.append(subject)
        if len(subjects) > 0:
            result.append([binding_name, subjects])
    return result

def get_risky_cluster_roles():
    cluster_roles = get_cluster_roles()
    analyzed_roles = {}
    for cluster_role in cluster_roles:
        name = cluster_role.metadata.name
        rules = cluster_role.rules
        for rule in rules:
            if name not in analyzed_roles:
                analyzed_roles[name] = []
            analyzed_roles[name].extend(analyze_rule(rule))
    risky_cluster_roles = {role: capabilities for role, capabilities in analyzed_roles.items() if capabilities}
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
            if full_name not in analyzed_roles:
                analyzed_roles[full_name] = []
            analyzed_roles[full_name].extend(analyze_rule(rule))
    risky_roles = {role: capabilities for role, capabilities in analyzed_roles.items() if capabilities}
    return risky_roles

def check_exec_shell(namespace, pod, container):
    shells = ["/bin/bash", "/bin/sh", "sh", "bash"]
    for shell in shells:
        try:
            exec_command = [shell, '-c', 'whoami']
            resp = stream.stream(v1.connect_get_namespaced_pod_exec,
                                 name=pod,
                                 namespace=namespace,
                                 container=container,
                                 command=exec_command,
                                 stderr=True, stdin=False, stdout=True, tty=False)
            return shell, resp.strip()
        except client.exceptions.ApiException:
            continue
    return None, None

def print_risky_roles_info(type="ClusterRole"):
    if type == "ClusterRole":
        print("Discovering risky ClusterRoles")
        risky_roles = get_risky_cluster_roles()
        role_bindings = get_cluster_role_bindings()
    elif type == "Role":
        print("Discovering risky Roles")
        risky_roles = get_risky_roles()
        role_bindings = get_role_bindings()

    pods_svc = get_service_account_pods()
    for risky_r in risky_roles.keys():
        output_role_kind = type
        output_namespace = None
        output_subject = []
        output_subject_kind = []
        output_subject_namespace = []
        output_pods = []
        output_risks = []
        output_bindings = []
        output_role = risky_r

        print("--------")
        if type == "Role":
            full_name_split = risky_r.split("/")
            role_name = full_name_split[1]
            namespace = full_name_split[0]
            output_namespace = namespace
            print("Role name: " + Fore.YELLOW + "{}".format(role_name) + Style.RESET_ALL + " on namespace " + Fore.YELLOW + namespace)
        if type == "ClusterRole":
            print("ClusterRole name: " + Fore.YELLOW + "{}".format(risky_r))
        print(Style.RESET_ALL)
        print("    - Allows to: ")
        for capability in risky_roles[risky_r]:
            output_risks.append(capability)
            print(Fore.YELLOW + "        {}".format(capability))
            print(Style.RESET_ALL)
        bindings = role_bindings.get(risky_r, [])

        bindings = clean_bindings(bindings)

        if bindings:
            print("    - Assigned to: ")
            for binding in bindings:
                for subject in binding[1]:
                    output_subject.append(subject.name)
                    output_subject_kind.append(subject.kind)
                    output_bindings.append(binding[0])

                    if subject.kind == "ServiceAccount" and subject.namespace is not None:
                        output_subject_namespace.append(subject.namespace)
                        print("        - The " + Fore.YELLOW + subject.namespace + "/" + subject.name + Style.RESET_ALL + " " + subject.kind + " through the " + Fore.YELLOW + binding[0] + Style.RESET_ALL + f" {type}")

                        if pods_svc.get(subject.namespace + "/" + subject.name):
                            output_pods.append(pods_svc[subject.namespace + "/" + subject.name])
                            pods = pods_svc[subject.namespace + "/" + subject.name]
                            exec_shells = []
                            for pod in pods:
                                namespace, pod_name = pod.split("/")
                                containers = [c.name for c in v1.read_namespaced_pod(name=pod_name, namespace=namespace).spec.containers]
                                for container in containers:
                                    shell, user = check_exec_shell(namespace, pod_name, container)
                                    if shell:
                                        exec_shells.append((pod_name, container, shell, user))
                            if exec_shells:
                                root_exec = [exec_shell for exec_shell in exec_shells if exec_shell[3] == 'root']
                                non_root_exec = [exec_shell for exec_shell in exec_shells if exec_shell[3] != 'root']
                                if root_exec:
                                    print(Fore.RED + "            - The pod(s) {} are using this service account and can be exec using the following shells as root:".format(",".join(pods_svc[subject.namespace + "/" + subject.name])))
                                    for exec_shell in root_exec:
                                        print(Fore.RED + "                Pod: {}, Container: {}, Shell: {}".format(exec_shell[0], exec_shell[1], exec_shell[2]))
                                if non_root_exec:
                                    print(Fore.CYAN + "            - The pod(s) {} are using this service account and can be exec using the following shells as non-root user:".format(",".join(pods_svc[subject.namespace + "/" + subject.name])))
                                    for exec_shell in non_root_exec:
                                        print(Fore.CYAN + "                Pod: {}, Container: {}, Shell: {}, User: {}".format(exec_shell[0], exec_shell[1], exec_shell[2], exec_shell[3]))
                                if not root_exec and not non_root_exec:
                                    print(Fore.GREEN + "            - There are no pods using this service account that can be exec with the tested shells")
                            else:
                                print(Fore.GREEN + "            - There are no pods using this service account that can be exec with the tested shells")
                        else:
                            print(Fore.GREEN + "            - There are no pods using this service account")
                            output_pods.append([])
                        print(Style.RESET_ALL)
                    else:
                        print("        - The " + Fore.YELLOW + subject.name + Style.RESET_ALL + " " + subject.kind + " through the " + Fore.YELLOW + binding[0] + Style.RESET_ALL + f" {type}" + Style.RESET_ALL)
                        print(Style.RESET_ALL)
                        output_pods.append([])
                        output_subject_namespace.append([])
        else:
            print(Fore.GREEN + "    - Not assigned to any subject")
            print(Style.RESET_ALL)

if __name__ == "__main__":
    print_risky_roles_info(type="ClusterRole")
    print("\n###########################\n")
    print_risky_roles_info(type="Role")
