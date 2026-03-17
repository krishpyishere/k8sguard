"""
Security scanners — detect misconfigurations and vulnerabilities in a live K8s cluster.

Each scanner checks one category (RBAC, secrets, network, runtime, supply chain)
and returns a list of SecurityFinding objects.
"""

import logging
from kubernetes import client
from kubernetes.client.rest import ApiException

from .constants import (
    SYSTEM_NAMESPACES, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

try:
    from ..models import SecurityFinding
except ImportError:
    from models import SecurityFinding

logger = logging.getLogger(__name__)

_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "NET_RAW", "DAC_OVERRIDE"}
_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "access_key"}
_SENSITIVE_OS_DIRS = {"/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/boot"}
_SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_unprivileged_port_start",
}


def _is_sensitive_key(key: str) -> bool:
    return any(s in key.lower() for s in _SENSITIVE_KEYS)


def scan_all(v1: client.CoreV1Api, apps_v1: client.AppsV1Api, namespaces: list[str] | None = None) -> list[SecurityFinding]:
    """Run all scanners against the cluster. Returns combined findings."""
    if namespaces is None:
        namespaces = _get_app_namespaces(v1)

    findings = []
    findings.extend(scan_rbac(namespaces))
    findings.extend(scan_secrets(v1, namespaces))
    findings.extend(scan_network(v1, namespaces))
    findings.extend(scan_runtime(v1, apps_v1, namespaces))
    findings.extend(scan_supply_chain(v1, apps_v1, namespaces))
    findings.extend(scan_ingress(namespaces))
    findings.extend(scan_dashboard(apps_v1, namespaces))
    return findings


def _get_app_namespaces(v1: client.CoreV1Api) -> list[str]:
    """Get all non-system namespaces."""
    try:
        ns_list = v1.list_namespace()
        return [ns.metadata.name for ns in ns_list.items if ns.metadata.name not in SYSTEM_NAMESPACES]
    except ApiException:
        return ["default"]


def _finding(idx: int, category: str, severity: str, title: str, description: str,
             namespace: str, kind: str, name: str, evidence: str, remediation: str) -> SecurityFinding:
    return SecurityFinding(
        finding_id=f"{category}-{idx:04d}",
        category=category,
        severity=severity,
        title=title,
        description=description,
        namespace=namespace,
        resource_kind=kind,
        resource_name=name,
        evidence=evidence,
        remediation=remediation,
    )


# ============================================================
# RBAC Scanner
# ============================================================

def scan_rbac(namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0
    rbac_v1 = client.RbacAuthorizationV1Api()

    # Check ClusterRoles
    try:
        cluster_roles = rbac_v1.list_cluster_role()
        for cr in cluster_roles.items:
            if cr.metadata.name.startswith("system:"):
                continue
            for rule in (cr.rules or []):
                verbs = rule.verbs or []
                resources = rule.resources or []
                api_groups = rule.api_groups or []

                if "*" in verbs or "*" in resources:
                    findings.append(_finding(
                        idx, "rbac", SEVERITY_CRITICAL,
                        "Wildcard RBAC permissions",
                        f"ClusterRole '{cr.metadata.name}' grants wildcard access",
                        "*", "ClusterRole", cr.metadata.name,
                        f"verbs={verbs}, resources={resources}, apiGroups={api_groups}",
                        f"Restrict ClusterRole '{cr.metadata.name}' to specific verbs and resources",
                    ))
                    idx += 1

                escalation_verbs = {"escalate", "bind", "impersonate"} & set(verbs)
                if escalation_verbs:
                    findings.append(_finding(
                        idx, "rbac", SEVERITY_CRITICAL,
                        "RBAC allows privilege escalation",
                        f"ClusterRole '{cr.metadata.name}' grants {escalation_verbs}",
                        "*", "ClusterRole", cr.metadata.name,
                        f"verbs={verbs}, resources={resources}",
                        f"Remove {escalation_verbs} verbs from ClusterRole '{cr.metadata.name}'",
                    ))
                    idx += 1

                if "secrets" in resources and any(v in verbs for v in ("get", "list", "watch", "*")):
                    findings.append(_finding(
                        idx, "rbac", SEVERITY_HIGH,
                        "Broad secrets access",
                        f"ClusterRole '{cr.metadata.name}' can read secrets",
                        "*", "ClusterRole", cr.metadata.name,
                        f"verbs={verbs}, resources={resources}",
                        f"Limit secrets access to specific namespaces using Roles instead of ClusterRoles",
                    ))
                    idx += 1

                # KICS: pods/exec permission
                if "pods/exec" in resources and any(v in verbs for v in ("get", "create", "*")):
                    findings.append(_finding(
                        idx, "rbac", SEVERITY_MEDIUM,
                        "RBAC grants exec permission on pods",
                        f"ClusterRole '{cr.metadata.name}' grants exec access to pods via pods/exec",
                        "*", "ClusterRole", cr.metadata.name,
                        f"verbs={verbs}, resources={resources}",
                        f"Remove 'pods/exec' from ClusterRole '{cr.metadata.name}' resources",
                    ))
                    idx += 1

                # KICS: pods/portforward permission
                if "pods/portforward" in resources and any(v in verbs for v in ("get", "create", "*")):
                    findings.append(_finding(
                        idx, "rbac", SEVERITY_MEDIUM,
                        "RBAC grants port-forward permission",
                        f"ClusterRole '{cr.metadata.name}' grants port-forward access via pods/portforward",
                        "*", "ClusterRole", cr.metadata.name,
                        f"verbs={verbs}, resources={resources}",
                        f"Remove 'pods/portforward' from ClusterRole '{cr.metadata.name}' resources",
                    ))
                    idx += 1

                # KICS: permissive create-pods permission
                if ("pods" in resources or "*" in resources) and any(v in verbs for v in ("create", "*")):
                    if "" in api_groups or "*" in api_groups:
                        findings.append(_finding(
                            idx, "rbac", SEVERITY_MEDIUM,
                            "RBAC grants create permission on pods",
                            f"ClusterRole '{cr.metadata.name}' can create pods — privilege escalation vector",
                            "*", "ClusterRole", cr.metadata.name,
                            f"verbs={verbs}, resources={resources}, apiGroups={api_groups}",
                            f"Remove 'create' verb on 'pods' from ClusterRole '{cr.metadata.name}'",
                        ))
                        idx += 1

    except ApiException as e:
        logger.warning(f"RBAC scan error (ClusterRoles): {e.reason}")

    # Check ClusterRoleBindings for cluster-admin grants and default SA bindings
    try:
        crbs = rbac_v1.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.metadata.name.startswith("system:"):
                continue
            if crb.role_ref.name == "cluster-admin":
                subject_desc = ", ".join(
                    f"{s.kind}/{s.name}" + (f" in {s.namespace}" if s.namespace else "")
                    for s in (crb.subjects or [])
                )
                for subj in (crb.subjects or []):
                    if subj.namespace in namespaces or not subj.namespace:
                        findings.append(_finding(
                            idx, "rbac", SEVERITY_CRITICAL,
                            "Cluster-admin binding",
                            f"ClusterRoleBinding '{crb.metadata.name}' grants cluster-admin to {subject_desc}",
                            subj.namespace or "*", "ClusterRoleBinding", crb.metadata.name,
                            f"roleRef=cluster-admin, subjects=[{subject_desc}]",
                            f"Remove or restrict the ClusterRoleBinding '{crb.metadata.name}'",
                        ))
                        idx += 1
                        break

            # KICS: ClusterRoleBinding to default SA
            for subj in (crb.subjects or []):
                if subj.kind == "ServiceAccount" and subj.name == "default":
                    if subj.namespace in namespaces or not subj.namespace:
                        findings.append(_finding(
                            idx, "rbac", SEVERITY_MEDIUM,
                            "ClusterRole bound to default service account",
                            f"ClusterRoleBinding '{crb.metadata.name}' binds to default ServiceAccount",
                            subj.namespace or "*", "ClusterRoleBinding", crb.metadata.name,
                            f"roleRef={crb.role_ref.kind}/{crb.role_ref.name}, subject=ServiceAccount/default",
                            f"Create a dedicated ServiceAccount instead of binding cluster roles to 'default'",
                        ))
                        idx += 1
                        break
    except ApiException as e:
        logger.warning(f"RBAC scan error (ClusterRoleBindings): {e.reason}")

    # Check namespaced Roles
    for ns in namespaces:
        try:
            roles = rbac_v1.list_namespaced_role(ns)
            for role in roles.items:
                for rule in (role.rules or []):
                    verbs = rule.verbs or []
                    resources = rule.resources or []
                    if "*" in verbs or "*" in resources:
                        findings.append(_finding(
                            idx, "rbac", SEVERITY_HIGH,
                            "Wildcard Role permissions",
                            f"Role '{role.metadata.name}' in {ns} grants wildcard access",
                            ns, "Role", role.metadata.name,
                            f"verbs={verbs}, resources={resources}",
                            f"Restrict Role '{role.metadata.name}' to specific verbs and resources",
                        ))
                        idx += 1
        except ApiException:
            pass

    # KICS: RoleBindings to default SA
    for ns in namespaces:
        try:
            role_bindings = rbac_v1.list_namespaced_role_binding(ns)
            for rb in role_bindings.items:
                for subj in (rb.subjects or []):
                    if subj.kind == "ServiceAccount" and subj.name == "default":
                        findings.append(_finding(
                            idx, "rbac", SEVERITY_MEDIUM,
                            "Role bound to default service account",
                            f"RoleBinding '{rb.metadata.name}' in {ns} binds to default ServiceAccount",
                            ns, "RoleBinding", rb.metadata.name,
                            f"roleRef={rb.role_ref.kind}/{rb.role_ref.name}, subject=ServiceAccount/default",
                            f"Create a dedicated ServiceAccount instead of binding roles to 'default'",
                        ))
                        idx += 1
                        break
        except ApiException:
            pass

    return findings


# ============================================================
# Secrets Scanner
# ============================================================

def scan_secrets(v1: client.CoreV1Api, namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0

    for ns in namespaces:
        # Check for secrets exposed as env vars
        try:
            pods = v1.list_namespaced_pod(ns)
            for pod in pods.items:
                for container in pod.spec.containers:
                    for env in (container.env or []):
                        if env.value_from and env.value_from.secret_key_ref:
                            findings.append(_finding(
                                idx, "secrets", SEVERITY_HIGH,
                                "Secret exposed as environment variable",
                                f"Container '{container.name}' in pod '{pod.metadata.name}' "
                                f"exposes secret '{env.value_from.secret_key_ref.name}' via env var '{env.name}'",
                                ns, "Pod", pod.metadata.name,
                                f"env[{env.name}] -> secret/{env.value_from.secret_key_ref.name}",
                                "Mount secrets as volumes instead of env vars",
                            ))
                            idx += 1
                        elif env.value and _is_sensitive_key(env.name):
                            findings.append(_finding(
                                idx, "secrets", SEVERITY_HIGH,
                                "Hardcoded sensitive value in env",
                                f"Container '{container.name}' has suspicious env var '{env.name}' with a hardcoded value",
                                ns, "Pod", pod.metadata.name,
                                f"env[{env.name}] = <redacted>",
                                "Use Kubernetes Secrets or external secret managers instead of hardcoded values",
                            ))
                            idx += 1
        except ApiException:
            pass

        # Check ConfigMaps for sensitive data
        try:
            cms = v1.list_namespaced_config_map(ns)
            for cm in cms.items:
                if cm.metadata.name.startswith("kube-"):
                    continue
                for key in (cm.data or {}):
                    if _is_sensitive_key(key):
                        findings.append(_finding(
                            idx, "secrets", SEVERITY_HIGH,
                            "Sensitive data in ConfigMap",
                            f"ConfigMap '{cm.metadata.name}' has key '{key}' that may contain sensitive data",
                            ns, "ConfigMap", cm.metadata.name,
                            f"data key: {key}",
                            "Move sensitive data to a Secret resource or external secrets manager",
                        ))
                        idx += 1
        except ApiException:
            pass

    return findings


# ============================================================
# Network Scanner
# ============================================================

def scan_network(v1: client.CoreV1Api, namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0
    net_v1 = client.NetworkingV1Api()

    _DB_PORTS = {6379, 5432, 3306, 27017, 9200, 11211}

    for ns in namespaces:
        # Check for missing network policies
        policies_list = []
        try:
            policies = net_v1.list_namespaced_network_policy(ns)
            policies_list = policies.items or []
            if not policies_list:
                findings.append(_finding(
                    idx, "network", SEVERITY_HIGH,
                    "No NetworkPolicy in namespace",
                    f"Namespace '{ns}' has no network policies — all pod-to-pod traffic is unrestricted",
                    ns, "Namespace", ns,
                    "0 NetworkPolicy objects",
                    f"Create default-deny ingress/egress NetworkPolicy in namespace '{ns}'",
                ))
                idx += 1
            else:
                has_egress = any(
                    p.spec.policy_types and "Egress" in p.spec.policy_types
                    for p in policies_list
                )
                if not has_egress:
                    findings.append(_finding(
                        idx, "network", SEVERITY_MEDIUM,
                        "No egress restrictions",
                        f"Namespace '{ns}' has ingress policies but no egress restrictions",
                        ns, "Namespace", ns,
                        f"{len(policies_list)} policies, none with Egress type",
                        f"Add a default-deny egress NetworkPolicy in namespace '{ns}'",
                    ))
                    idx += 1

                # KICS: NetworkPolicy not targeting any pod
                try:
                    ns_pods = v1.list_namespaced_pod(ns)
                    pod_labels_list = [p.metadata.labels or {} for p in ns_pods.items]
                    for policy in policies_list:
                        selector = policy.spec.pod_selector
                        match_labels = (selector.match_labels or {}) if selector else {}
                        if not match_labels:
                            continue
                        matched = any(
                            all(pl.get(k) == v for k, v in match_labels.items())
                            for pl in pod_labels_list
                        )
                        if not matched:
                            findings.append(_finding(
                                idx, "network", SEVERITY_LOW,
                                "NetworkPolicy not targeting any pod",
                                f"NetworkPolicy '{policy.metadata.name}' in namespace '{ns}' has podSelector "
                                f"{match_labels} that matches no running pods — policy is ineffective",
                                ns, "NetworkPolicy", policy.metadata.name,
                                f"podSelector.matchLabels={match_labels}, matched_pods=0",
                                f"Update the podSelector in NetworkPolicy '{policy.metadata.name}' to match "
                                f"actual pod labels, or remove the unused policy",
                            ))
                            idx += 1
                except ApiException:
                    pass
        except ApiException:
            pass

        # Check for externally exposed services
        try:
            services = v1.list_namespaced_service(ns)
            for svc in services.items:
                if svc.spec.type in ("LoadBalancer", "NodePort"):
                    ports = ", ".join(f"{p.port}" for p in (svc.spec.ports or []))
                    findings.append(_finding(
                        idx, "network", SEVERITY_MEDIUM,
                        "Service exposed externally",
                        f"Service '{svc.metadata.name}' is type {svc.spec.type} — accessible outside cluster",
                        ns, "Service", svc.metadata.name,
                        f"type={svc.spec.type}, ports=[{ports}]",
                        f"Use ClusterIP with an Ingress controller, or restrict source IPs via loadBalancerSourceRanges",
                    ))
                    idx += 1

                # Check for unauthenticated database services
                for p in (svc.spec.ports or []):
                    target = p.target_port if isinstance(p.target_port, int) else p.port
                    if p.port in _DB_PORTS or target in _DB_PORTS:
                        if not policies_list:  # reuse the policies fetched earlier
                            findings.append(_finding(
                                idx, "network", SEVERITY_HIGH,
                                "Unauthenticated database service",
                                f"Service '{svc.metadata.name}' exposes port {p.port} (common DB port) with no NetworkPolicy",
                                ns, "Service", svc.metadata.name,
                                f"port={p.port}, no NetworkPolicy",
                                f"Add a NetworkPolicy to restrict access to '{svc.metadata.name}' and require authentication",
                            ))
                            idx += 1
        except ApiException:
            pass

    # KICS: Workloads running in the "default" namespace
    if "default" in namespaces:
        try:
            default_pods = v1.list_namespaced_pod("default")
            for pod in default_pods.items:
                if pod.metadata.labels and pod.metadata.labels.get("component"):
                    continue
                findings.append(_finding(
                    idx, "network", SEVERITY_MEDIUM,
                    "Workload in default namespace",
                    f"Pod '{pod.metadata.name}' is running in the 'default' namespace — "
                    f"workloads should use dedicated namespaces for isolation",
                    "default", "Pod", pod.metadata.name,
                    f"namespace=default, pod={pod.metadata.name}",
                    "Move workloads to dedicated namespaces and apply NetworkPolicies for isolation",
                ))
                idx += 1
        except ApiException:
            pass

    return findings


# ============================================================
# Ingress Scanner (KICS: Ingress Exposes Workload)
# ============================================================

def scan_ingress(namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0
    net_v1 = client.NetworkingV1Api()

    for ns in namespaces:
        try:
            ingresses = net_v1.list_namespaced_ingress(ns)
        except ApiException:
            continue

        for ing in ingresses.items:
            for rule in (ing.spec.rules or []):
                host = rule.host or "*"
                for path in (rule.http.paths if rule.http else []):
                    svc_name = path.backend.service.name if path.backend.service else "unknown"
                    svc_port = ""
                    if path.backend.service and path.backend.service.port:
                        svc_port = str(path.backend.service.port.number or path.backend.service.port.name or "")
                    findings.append(_finding(
                        idx, "network", SEVERITY_MEDIUM,
                        "Ingress exposes workload externally",
                        f"Ingress '{ing.metadata.name}' exposes service '{svc_name}' at host '{host}'",
                        ns, "Ingress", ing.metadata.name,
                        f"host={host}, service={svc_name}, port={svc_port}",
                        "Review whether external exposure is needed; add authentication and TLS termination",
                    ))
                    idx += 1

    return findings


# ============================================================
# Dashboard Scanner (KICS: Dashboard Is Enabled)
# ============================================================

def scan_dashboard(apps_v1: client.AppsV1Api, namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0

    for ns in namespaces:
        try:
            deploys = apps_v1.list_namespaced_deployment(ns)
        except ApiException:
            continue

        for deploy in deploys.items:
            labels = deploy.metadata.labels or {}
            d_name = deploy.metadata.name
            if (labels.get("k8s-app") == "kubernetes-dashboard"
                    or "kubernetes-dashboard" in d_name):
                findings.append(_finding(
                    idx, "runtime", SEVERITY_LOW,
                    "Kubernetes Dashboard is deployed",
                    f"Deployment '{d_name}' in namespace '{ns}' runs the Kubernetes Dashboard",
                    ns, "Deployment", d_name,
                    f"labels={labels}, name={d_name}",
                    "Remove the Kubernetes Dashboard if not needed — it can be used as an attack vector",
                ))
                idx += 1

    return findings


# ============================================================
# Runtime Security Scanner
# ============================================================

def scan_runtime(v1: client.CoreV1Api, apps_v1: client.AppsV1Api, namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0

    for ns in namespaces:
        try:
            pods = v1.list_namespaced_pod(ns)
        except ApiException:
            continue

        # KICS: Shared service account detection
        sa_pod_map: dict[str, list[str]] = {}
        for pod in pods.items:
            sa = pod.spec.service_account_name or ""
            if sa and sa != "default":
                sa_pod_map.setdefault(sa, []).append(pod.metadata.name)

        for sa, pod_names in sa_pod_map.items():
            if len(pod_names) > 1:
                findings.append(_finding(
                    idx, "rbac", SEVERITY_MEDIUM,
                    "Shared service account",
                    f"ServiceAccount '{sa}' in {ns} is shared by {len(pod_names)} pods: {', '.join(pod_names)}",
                    ns, "ServiceAccount", sa,
                    f"pods={pod_names}",
                    f"Assign a unique ServiceAccount to each workload instead of sharing '{sa}'",
                ))
                idx += 1

        for pod in pods.items:
            pod_name = pod.metadata.name
            pod_spec = pod.spec
            annotations = pod.metadata.annotations or {}

            # Host namespace checks
            if pod_spec.host_pid:
                findings.append(_finding(
                    idx, "runtime", SEVERITY_CRITICAL,
                    "Host PID namespace shared",
                    f"Pod '{pod_name}' shares host PID namespace",
                    ns, "Pod", pod_name, "hostPID: true",
                    "Set hostPID: false unless absolutely required",
                ))
                idx += 1

            if pod_spec.host_network:
                findings.append(_finding(
                    idx, "runtime", SEVERITY_CRITICAL,
                    "Host network namespace shared",
                    f"Pod '{pod_name}' shares host network namespace",
                    ns, "Pod", pod_name, "hostNetwork: true",
                    "Set hostNetwork: false and use Services for connectivity",
                ))
                idx += 1

            if getattr(pod_spec, 'host_ipc', False):
                findings.append(_finding(
                    idx, "runtime", SEVERITY_CRITICAL,
                    "Host IPC namespace shared",
                    f"Pod '{pod_name}' shares host IPC namespace",
                    ns, "Pod", pod_name, "hostIPC: true",
                    "Set hostIPC: false — host IPC sharing allows inter-process communication with host processes",
                ))
                idx += 1

            # HostPath volume mounts
            for vol in (pod_spec.volumes or []):
                if vol.host_path:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_HIGH,
                        "HostPath volume mount",
                        f"Pod '{pod_name}' mounts host path '{vol.host_path.path}'",
                        ns, "Pod", pod_name,
                        f"hostPath: {vol.host_path.path}",
                        "Use PersistentVolumeClaims instead of hostPath mounts",
                    ))
                    idx += 1

                    if any(sock in vol.host_path.path for sock in ("containerd.sock", "docker.sock", "crio.sock")):
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_CRITICAL,
                            "Container runtime socket mounted",
                            f"Pod '{pod_name}' mounts container runtime socket '{vol.host_path.path}' — enables container escape",
                            ns, "Pod", pod_name,
                            f"hostPath: {vol.host_path.path} (runtime socket)",
                            "Remove the runtime socket mount — this allows full container escape and host takeover",
                        ))
                        idx += 1

            # Control-plane tolerations check
            _CP_TAINT_KEYS = {"node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"}
            for tol in (pod_spec.tolerations or []):
                if tol.key in _CP_TAINT_KEYS:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_HIGH,
                        "Control-plane node targeting",
                        f"Pod '{pod_name}' has toleration for '{tol.key}' — can schedule on control-plane nodes",
                        ns, "Pod", pod_name,
                        f"toleration: key={tol.key}, operator={tol.operator}, effect={tol.effect}",
                        "Remove control-plane tolerations unless this pod truly needs to run on master nodes",
                    ))
                    idx += 1
                    break

            # KICS: Unsafe sysctls (pod-level)
            if pod_spec.security_context and pod_spec.security_context.sysctls:
                for sysctl in pod_spec.security_context.sysctls:
                    if sysctl.name not in _SAFE_SYSCTLS:
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_HIGH,
                            "Pod uses unsafe sysctl",
                            f"Pod '{pod_name}' sets unsafe sysctl '{sysctl.name}={sysctl.value}'",
                            ns, "Pod", pod_name,
                            f"sysctl: {sysctl.name}={sysctl.value}",
                            f"Remove unsafe sysctl '{sysctl.name}' or use only safe sysctls (kernel.shm_rmid_forced, net.ipv4.*)",
                        ))
                        idx += 1

            # Container-level checks
            for container in pod_spec.containers:
                sc = container.security_context
                c_name = container.name

                if sc is None:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_MEDIUM,
                        "Missing security context",
                        f"Container '{c_name}' in pod '{pod_name}' has no securityContext",
                        ns, "Pod", pod_name,
                        f"container '{c_name}': securityContext is null",
                        "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities",
                    ))
                    idx += 1
                    # Still check KICS probes/apparmor/seccomp/imagePullPolicy for containers without securityContext
                else:
                    if sc.privileged:
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_CRITICAL,
                            "Privileged container",
                            f"Container '{c_name}' in pod '{pod_name}' runs as privileged",
                            ns, "Pod", pod_name,
                            "privileged: true",
                            "Remove privileged: true and use specific capabilities instead",
                        ))
                        idx += 1

                    if sc.run_as_user == 0 or (not sc.run_as_non_root and sc.run_as_user is None):
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_HIGH,
                            "Container may run as root",
                            f"Container '{c_name}' in pod '{pod_name}' has no runAsNonRoot constraint",
                            ns, "Pod", pod_name,
                            f"runAsNonRoot={sc.run_as_non_root}, runAsUser={sc.run_as_user}",
                            "Set runAsNonRoot: true and runAsUser to a non-zero UID",
                        ))
                        idx += 1

                    if not sc.read_only_root_filesystem:
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_MEDIUM,
                            "Writable root filesystem",
                            f"Container '{c_name}' in pod '{pod_name}' has writable root filesystem",
                            ns, "Pod", pod_name,
                            "readOnlyRootFilesystem: false or unset",
                            "Set readOnlyRootFilesystem: true and use emptyDir for writable paths",
                        ))
                        idx += 1

                    # Capabilities
                    if sc.capabilities:
                        added = set(sc.capabilities.add or [])
                        dangerous = added & _DANGEROUS_CAPS
                        if dangerous:
                            findings.append(_finding(
                                idx, "runtime", SEVERITY_HIGH,
                                "Dangerous Linux capabilities",
                                f"Container '{c_name}' in pod '{pod_name}' has capabilities: {dangerous}",
                                ns, "Pod", pod_name,
                                f"capabilities.add: {list(added)}",
                                f"Remove dangerous capabilities: {dangerous}. Drop ALL and add only what's needed.",
                            ))
                            idx += 1

                        # KICS: No drop ALL capabilities
                        dropped = [c.upper() for c in (sc.capabilities.drop or [])]
                        if "ALL" not in dropped:
                            findings.append(_finding(
                                idx, "runtime", SEVERITY_LOW,
                                "Container does not drop all capabilities",
                                f"Container '{c_name}' in pod '{pod_name}' does not drop ALL capabilities",
                                ns, "Pod", pod_name,
                                f"capabilities.drop: {sc.capabilities.drop or []}",
                                "Set securityContext.capabilities.drop: ['ALL'] and add back only required capabilities",
                            ))
                            idx += 1

                        # KICS: NET_RAW not dropped
                        if "ALL" not in dropped and "NET_RAW" not in dropped:
                            findings.append(_finding(
                                idx, "runtime", SEVERITY_MEDIUM,
                                "NET_RAW capability not dropped",
                                f"Container '{c_name}' in pod '{pod_name}' does not drop NET_RAW — allows packet spoofing",
                                ns, "Pod", pod_name,
                                f"capabilities.drop: {sc.capabilities.drop or []}",
                                "Add NET_RAW to securityContext.capabilities.drop or drop ALL capabilities",
                            ))
                            idx += 1
                    elif sc:
                        # Has securityContext but no capabilities block at all
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_LOW,
                            "Container does not drop all capabilities",
                            f"Container '{c_name}' in pod '{pod_name}' has no capabilities.drop defined",
                            ns, "Pod", pod_name,
                            "capabilities: not set",
                            "Set securityContext.capabilities.drop: ['ALL'] and add back only required capabilities",
                        ))
                        idx += 1
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_MEDIUM,
                            "NET_RAW capability not dropped",
                            f"Container '{c_name}' in pod '{pod_name}' has no capabilities configured — NET_RAW is available",
                            ns, "Pod", pod_name,
                            "capabilities: not set",
                            "Add NET_RAW to securityContext.capabilities.drop or drop ALL capabilities",
                        ))
                        idx += 1

                    if sc.allow_privilege_escalation is True:
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_HIGH,
                            "Privilege escalation allowed",
                            f"Container '{c_name}' in pod '{pod_name}' allows privilege escalation",
                            ns, "Pod", pod_name,
                            "allowPrivilegeEscalation: true",
                            "Set allowPrivilegeEscalation: false to prevent child processes from gaining more privileges",
                        ))
                        idx += 1

                    # KICS: Unmasked procMount
                    if getattr(sc, 'proc_mount', None) == "Unmasked":
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_HIGH,
                            "Container runs with unmasked /proc",
                            f"Container '{c_name}' in pod '{pod_name}' has procMount: Unmasked — full /proc access",
                            ns, "Pod", pod_name,
                            "procMount: Unmasked",
                            "Set securityContext.procMount to Default or remove it entirely",
                        ))
                        idx += 1

                # KICS: No seccomp profile
                pod_seccomp = None
                if pod_spec.security_context and pod_spec.security_context.seccomp_profile:
                    pod_seccomp = pod_spec.security_context.seccomp_profile.type
                container_seccomp = None
                if sc and sc.seccomp_profile:
                    container_seccomp = sc.seccomp_profile.type
                has_valid_seccomp = (
                    (container_seccomp and container_seccomp != "Unconfined")
                    or (pod_seccomp and pod_seccomp != "Unconfined")
                )
                if not has_valid_seccomp:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_MEDIUM,
                        "No seccomp profile configured",
                        f"Container '{c_name}' in pod '{pod_name}' has no seccomp profile — all syscalls allowed",
                        ns, "Pod", pod_name,
                        f"seccompProfile: pod={pod_seccomp}, container={container_seccomp}",
                        "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost",
                    ))
                    idx += 1

                # KICS: No AppArmor profile annotation
                apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{c_name}"
                if apparmor_key not in annotations:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_LOW,
                        "No AppArmor profile configured",
                        f"Container '{c_name}' in pod '{pod_name}' has no AppArmor profile annotation",
                        ns, "Pod", pod_name,
                        f"missing annotation: {apparmor_key}",
                        f"Add annotation '{apparmor_key}: runtime/default' to the pod metadata",
                    ))
                    idx += 1

                # KICS: No liveness probe
                if not container.liveness_probe:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_LOW,
                        "No liveness probe configured",
                        f"Container '{c_name}' in pod '{pod_name}' has no liveness probe",
                        ns, "Pod", pod_name,
                        "livenessProbe: not set",
                        "Configure a livenessProbe to restart unresponsive containers",
                    ))
                    idx += 1

                # KICS: No readiness probe
                if not container.readiness_probe:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_MEDIUM,
                        "No readiness probe configured",
                        f"Container '{c_name}' in pod '{pod_name}' has no readiness probe",
                        ns, "Pod", pod_name,
                        "readinessProbe: not set",
                        "Configure a readinessProbe to avoid routing traffic to unready containers",
                    ))
                    idx += 1

                # KICS: Writable mount on sensitive OS directory
                for vm in (container.volume_mounts or []):
                    mount = vm.mount_path
                    is_sensitive = any(
                        mount == d or mount.startswith(d + "/")
                        for d in _SENSITIVE_OS_DIRS
                    )
                    if is_sensitive and not vm.read_only:
                        findings.append(_finding(
                            idx, "runtime", SEVERITY_HIGH,
                            "Writable mount on sensitive OS directory",
                            f"Container '{c_name}' in pod '{pod_name}' has writable mount at '{mount}'",
                            ns, "Pod", pod_name,
                            f"volumeMount: mountPath={mount}, readOnly={vm.read_only}",
                            f"Set readOnly: true on the volume mount at '{mount}' or use a non-sensitive path",
                        ))
                        idx += 1

                # KICS: imagePullPolicy not Always
                pull_policy = container.image_pull_policy
                if pull_policy and pull_policy != "Always":
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_LOW,
                        "Image pull policy not set to Always",
                        f"Container '{c_name}' in pod '{pod_name}' has imagePullPolicy: {pull_policy}",
                        ns, "Pod", pod_name,
                        f"imagePullPolicy: {pull_policy}",
                        "Set imagePullPolicy: Always to ensure fresh images are pulled on each deployment",
                    ))
                    idx += 1

            # Default service account check
            sa_name = pod_spec.service_account_name or "default"
            auto_mount = pod_spec.automount_service_account_token
            if sa_name == "default" and auto_mount is not False:
                findings.append(_finding(
                    idx, "runtime", SEVERITY_MEDIUM,
                    "Default service account token auto-mounted",
                    f"Pod '{pod_name}' uses default SA with token auto-mounted",
                    ns, "Pod", pod_name,
                    f"serviceAccountName=default, automountServiceAccountToken={auto_mount}",
                    "Set automountServiceAccountToken: false or use a dedicated service account",
                ))
                idx += 1

            # KICS: SA name undefined
            sa = pod_spec.service_account_name
            if not sa or sa == "default":
                findings.append(_finding(
                    idx, "rbac", SEVERITY_MEDIUM,
                    "Service account name undefined",
                    f"Pod '{pod_name}' in {ns} uses default/undefined serviceAccountName",
                    ns, "Pod", pod_name,
                    f"serviceAccountName={sa!r}",
                    f"Set an explicit serviceAccountName for pod '{pod_name}' to restrict API access",
                ))
                idx += 1

    return findings


# ============================================================
# Supply Chain Scanner
# ============================================================

def scan_supply_chain(v1: client.CoreV1Api, apps_v1: client.AppsV1Api, namespaces: list[str]) -> list[SecurityFinding]:
    findings = []
    idx = 0

    for ns in namespaces:
        try:
            pods = v1.list_namespaced_pod(ns)
        except ApiException:
            continue

        for pod in pods.items:
            for container in pod.spec.containers:
                image = container.image or ""

                # :latest or no tag
                if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                    findings.append(_finding(
                        idx, "supply_chain", SEVERITY_MEDIUM,
                        "Image uses :latest or no tag",
                        f"Container '{container.name}' in pod '{pod.metadata.name}' uses unpinned image '{image}'",
                        ns, "Pod", pod.metadata.name,
                        f"image: {image}",
                        "Pin images to specific version tags or sha256 digests",
                    ))
                    idx += 1

                # No digest pinning
                if "@sha256:" not in image:
                    findings.append(_finding(
                        idx, "supply_chain", SEVERITY_LOW,
                        "Image not pinned by digest",
                        f"Container '{container.name}' image '{image}' is not digest-pinned",
                        ns, "Pod", pod.metadata.name,
                        f"image: {image} (no @sha256: reference)",
                        "Use image digests (image@sha256:abc123...) for immutable references",
                    ))
                    idx += 1

                # No resource limits
                res = container.resources
                if not res or not res.limits:
                    findings.append(_finding(
                        idx, "supply_chain", SEVERITY_LOW,
                        "No resource limits",
                        f"Container '{container.name}' in pod '{pod.metadata.name}' has no resource limits",
                        ns, "Pod", pod.metadata.name,
                        "resources.limits: not set",
                        "Set CPU and memory limits to prevent resource exhaustion",
                    ))
                    idx += 1

    return findings
