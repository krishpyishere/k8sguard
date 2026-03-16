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
    except ApiException as e:
        logger.warning(f"RBAC scan error (ClusterRoles): {e.reason}")

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

    for ns in namespaces:
        # Check for missing network policies
        try:
            policies = net_v1.list_namespaced_network_policy(ns)
            if not policies.items:
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
                    for p in policies.items
                )
                if not has_egress:
                    findings.append(_finding(
                        idx, "network", SEVERITY_MEDIUM,
                        "No egress restrictions",
                        f"Namespace '{ns}' has ingress policies but no egress restrictions",
                        ns, "Namespace", ns,
                        f"{len(policies.items)} policies, none with Egress type",
                        f"Add a default-deny egress NetworkPolicy in namespace '{ns}'",
                    ))
                    idx += 1
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
        except ApiException:
            pass

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

        for pod in pods.items:
            pod_name = pod.metadata.name
            pod_spec = pod.spec

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

            # Container-level checks
            for container in pod_spec.containers:
                sc = container.security_context

                if sc is None:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_MEDIUM,
                        "Missing security context",
                        f"Container '{container.name}' in pod '{pod_name}' has no securityContext",
                        ns, "Pod", pod_name,
                        f"container '{container.name}': securityContext is null",
                        "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities",
                    ))
                    idx += 1
                    continue

                if sc.privileged:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_CRITICAL,
                        "Privileged container",
                        f"Container '{container.name}' in pod '{pod_name}' runs as privileged",
                        ns, "Pod", pod_name,
                        "privileged: true",
                        "Remove privileged: true and use specific capabilities instead",
                    ))
                    idx += 1

                if sc.run_as_user == 0 or (not sc.run_as_non_root and sc.run_as_user is None):
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_HIGH,
                        "Container may run as root",
                        f"Container '{container.name}' in pod '{pod_name}' has no runAsNonRoot constraint",
                        ns, "Pod", pod_name,
                        f"runAsNonRoot={sc.run_as_non_root}, runAsUser={sc.run_as_user}",
                        "Set runAsNonRoot: true and runAsUser to a non-zero UID",
                    ))
                    idx += 1

                if not sc.read_only_root_filesystem:
                    findings.append(_finding(
                        idx, "runtime", SEVERITY_MEDIUM,
                        "Writable root filesystem",
                        f"Container '{container.name}' in pod '{pod_name}' has writable root filesystem",
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
                            f"Container '{container.name}' in pod '{pod_name}' has capabilities: {dangerous}",
                            ns, "Pod", pod_name,
                            f"capabilities.add: {list(added)}",
                            f"Remove dangerous capabilities: {dangerous}. Drop ALL and add only what's needed.",
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
