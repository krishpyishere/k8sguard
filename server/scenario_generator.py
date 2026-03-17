"""
Security scenario generator — creates vulnerability scenarios for training episodes.

Generates targeted sets of K8s security misconfigurations at varying difficulty levels.
"""

import logging
import random
from uuid import uuid4

from .constants import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

try:
    from ..models import SecurityFinding, VulnerabilityScenario
except ImportError:
    from models import SecurityFinding, VulnerabilityScenario

logger = logging.getLogger(__name__)


# ---- Scenario templates ----
# Each template defines what to inject and the expected findings

SCENARIO_POOL = [
    # Tier 0: Remediation drills — single obvious vuln with exact fix in alert (difficulty 0.15)
    {
        "difficulty": 0.15,
        "category": "rbac",
        "description": "A wildcard ClusterRole needs to be deleted",
        "alert": "REMEDIATION DRILL: Delete the overpermissive ClusterRole 'test-admin'. Fix: kubectl delete clusterrole test-admin",
        "injections": [
            {"type": "wildcard_rbac", "params": {"namespace": "default", "role_name": "test-admin"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Wildcard RBAC permissions",
             "resource_kind": "ClusterRole", "resource_name": "test-admin", "namespace": "*",
             "evidence": "verbs=['*'], resources=['*']",
             "remediation": "kubectl delete clusterrole test-admin"},
        ],
    },
    {
        "difficulty": 0.15,
        "category": "runtime",
        "description": "A privileged debug pod must be removed from the cluster",
        "alert": "REMEDIATION DRILL: Delete the privileged pod 'priv-debug'. Fix: kubectl delete pod priv-debug -n default",
        "injections": [
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "priv-debug"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "priv-debug", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "kubectl delete pod priv-debug -n default"},
        ],
    },
    {
        "difficulty": 0.15,
        "category": "network",
        "description": "An internal service is exposed via NodePort and must be deleted",
        "alert": "REMEDIATION DRILL: Delete the exposed NodePort service 'exposed-svc'. Fix: kubectl delete svc exposed-svc -n default",
        "injections": [
            {"type": "exposed_service", "params": {"namespace": "default", "name": "exposed-svc", "node_port": 31000}},
        ],
        "expected_findings": [
            {"category": "network", "severity": SEVERITY_HIGH, "title": "Service exposed externally",
             "resource_kind": "Service", "resource_name": "exposed-svc", "namespace": "default",
             "evidence": "type=NodePort, nodePort=31000",
             "remediation": "kubectl delete svc exposed-svc -n default"},
        ],
    },

    # Tier 1: Single obvious vulnerability (difficulty 0.1-0.3)
    {
        "difficulty": 0.2,
        "category": "runtime",
        "description": "A privileged container is running in the cluster",
        "alert": "SECURITY ALERT: Potential privileged container detected",
        "injections": [
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "debug-tools"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "debug-tools", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "Remove privileged: true and use specific capabilities instead"},
        ],
    },
    {
        "difficulty": 0.2,
        "category": "runtime",
        "description": "A container is running as root with no security constraints",
        "alert": "SECURITY ALERT: Container running as root UID detected",
        "injections": [
            {"type": "run_as_root", "params": {"namespace": "default", "name": "legacy-app"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Container may run as root",
             "resource_kind": "Pod", "resource_name": "legacy-app", "namespace": "default",
             "evidence": "runAsUser=0",
             "remediation": "Set runAsNonRoot: true and runAsUser to a non-zero UID"},
        ],
    },
    {
        "difficulty": 0.2,
        "category": "supply_chain",
        "description": "A deployment is using an unpinned :latest image tag",
        "alert": "SECURITY ALERT: Unpinned container image detected",
        "injections": [
            {"type": "image_latest", "params": {"namespace": "default", "name": "app-deploy"}},
        ],
        "expected_findings": [
            {"category": "supply_chain", "severity": SEVERITY_MEDIUM, "title": "Image uses :latest or no tag",
             "resource_kind": "Pod", "resource_name": "app-deploy", "namespace": "default",
             "evidence": "image: nginx:latest",
             "remediation": "Pin images to specific version tags or sha256 digests"},
        ],
    },

    # Tier 2: Requires investigation (difficulty 0.3-0.5)
    {
        "difficulty": 0.4,
        "category": "rbac",
        "description": "An overly permissive RBAC role grants cluster-wide wildcard access",
        "alert": "SECURITY ALERT: Suspicious RBAC configuration detected",
        "injections": [
            {"type": "wildcard_rbac", "params": {"namespace": "default", "role_name": "overpermissive-role"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Wildcard RBAC permissions",
             "resource_kind": "ClusterRole", "resource_name": "overpermissive-role", "namespace": "*",
             "evidence": "verbs=['*'], resources=['*']",
             "remediation": "Restrict ClusterRole to specific verbs and resources"},
        ],
    },
    {
        "difficulty": 0.4,
        "category": "secrets",
        "description": "Secrets are exposed as environment variables in pods",
        "alert": "SECURITY ALERT: Possible secret exposure in workload configuration",
        "injections": [
            {"type": "secrets_in_env", "params": {"namespace": "default", "name": "api-server"}},
        ],
        "expected_findings": [
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Secret exposed as environment variable",
             "resource_kind": "Pod", "resource_name": "api-server", "namespace": "default",
             "evidence": "env[DB_PASSWORD] -> secret/api-server-creds",
             "remediation": "Mount secrets as volumes instead of env vars"},
        ],
    },
    {
        "difficulty": 0.35,
        "category": "network",
        "description": "A namespace has no network policies — unrestricted lateral movement",
        "alert": "SECURITY ALERT: Namespace with no network isolation detected",
        "injections": [
            {"type": "no_network_policy", "params": {"namespace": "default", "name": "web-app"}},
        ],
        "expected_findings": [
            {"category": "network", "severity": SEVERITY_HIGH, "title": "No NetworkPolicy in namespace",
             "resource_kind": "Namespace", "resource_name": "default", "namespace": "default",
             "evidence": "0 NetworkPolicy objects",
             "remediation": "Create default-deny ingress/egress NetworkPolicy"},
        ],
    },
    {
        "difficulty": 0.45,
        "category": "runtime",
        "description": "A pod has dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN)",
        "alert": "SECURITY ALERT: Pod with elevated capabilities detected",
        "injections": [
            {"type": "dangerous_caps", "params": {"namespace": "default", "name": "network-debug",
                                                   "capabilities": ["SYS_ADMIN", "NET_ADMIN"]}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Dangerous Linux capabilities",
             "resource_kind": "Pod", "resource_name": "network-debug", "namespace": "default",
             "evidence": "capabilities.add: ['SYS_ADMIN', 'NET_ADMIN']",
             "remediation": "Drop ALL capabilities and add only what's needed"},
        ],
    },

    # Tier 3: Multi-vulnerability (difficulty 0.5-0.7)
    {
        "difficulty": 0.6,
        "category": "mixed",
        "description": "Multiple security issues: privileged container + exposed service + no network policy",
        "alert": "SECURITY ALERT: Multiple security concerns detected in cluster",
        "injections": [
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "debug-tools"}},
            {"type": "exposed_service", "params": {"namespace": "default", "name": "internal-api", "node_port": 30080}},
            {"type": "no_network_policy", "params": {"namespace": "default", "name": "web-app"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "debug-tools", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "Remove privileged: true"},
            {"category": "network", "severity": SEVERITY_MEDIUM, "title": "Service exposed externally",
             "resource_kind": "Service", "resource_name": "internal-api", "namespace": "default",
             "evidence": "type=NodePort",
             "remediation": "Use ClusterIP with Ingress controller"},
            {"category": "network", "severity": SEVERITY_HIGH, "title": "No NetworkPolicy in namespace",
             "resource_kind": "Namespace", "resource_name": "default", "namespace": "default",
             "evidence": "0 NetworkPolicy objects",
             "remediation": "Create default-deny NetworkPolicy"},
        ],
    },
    {
        "difficulty": 0.65,
        "category": "mixed",
        "description": "RBAC + secrets misconfig: wildcard role with secrets in env vars and configmaps",
        "alert": "SECURITY ALERT: Access control and data exposure issues detected",
        "injections": [
            {"type": "wildcard_rbac", "params": {"namespace": "default", "role_name": "dev-admin"}},
            {"type": "secrets_in_env", "params": {"namespace": "default", "name": "backend"}},
            {"type": "sensitive_configmap", "params": {"namespace": "default", "name": "app-config"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Wildcard RBAC permissions",
             "resource_kind": "ClusterRole", "resource_name": "dev-admin", "namespace": "*",
             "evidence": "verbs=['*'], resources=['*']",
             "remediation": "Apply least-privilege RBAC"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Secret exposed as environment variable",
             "resource_kind": "Pod", "resource_name": "backend", "namespace": "default",
             "evidence": "env -> secret ref",
             "remediation": "Mount secrets as volumes"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Sensitive data in ConfigMap",
             "resource_kind": "ConfigMap", "resource_name": "app-config", "namespace": "default",
             "evidence": "keys contain sensitive data",
             "remediation": "Move to Secret resource"},
        ],
    },

    # Tier 4: Full-spectrum (difficulty 0.7+)
    {
        "difficulty": 0.8,
        "category": "mixed",
        "description": "Full spectrum: runtime + RBAC + network + secrets across multiple attack vectors",
        "alert": "SECURITY AUDIT: Comprehensive cluster security assessment required",
        "injections": [
            {"type": "host_path_mount", "params": {"namespace": "default", "name": "log-collector", "host_path": "/var/log"}},
            {"type": "wildcard_rbac", "params": {"namespace": "default", "role_name": "legacy-admin"}},
            {"type": "secrets_in_env", "params": {"namespace": "default", "name": "payment-svc"}},
            {"type": "no_network_policy", "params": {"namespace": "default", "name": "frontend"}},
            {"type": "host_pid_net", "params": {"namespace": "default", "name": "monitoring-agent"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "HostPath volume mount",
             "resource_kind": "Pod", "resource_name": "log-collector", "namespace": "default",
             "evidence": "hostPath: /var/log",
             "remediation": "Use PersistentVolumeClaims"},
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Wildcard RBAC permissions",
             "resource_kind": "ClusterRole", "resource_name": "legacy-admin", "namespace": "*",
             "evidence": "verbs=['*']", "remediation": "Apply least-privilege"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Secret exposed as environment variable",
             "resource_kind": "Pod", "resource_name": "payment-svc", "namespace": "default",
             "evidence": "env -> secret ref", "remediation": "Mount as volumes"},
            {"category": "network", "severity": SEVERITY_HIGH, "title": "No NetworkPolicy in namespace",
             "resource_kind": "Namespace", "resource_name": "default", "namespace": "default",
             "evidence": "0 policies", "remediation": "Create default-deny"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Host PID/Network namespace",
             "resource_kind": "Pod", "resource_name": "monitoring-agent", "namespace": "default",
             "evidence": "hostPID: true, hostNetwork: true",
             "remediation": "Remove host namespace sharing"},
        ],
    },

    # ---- Kubernetes Goat integration scenarios ----

    # Tier 0 (0.15) — Remediation drills
    {
        "difficulty": 0.15,
        "category": "runtime",
        "description": "A container runtime socket is mounted into a pod",
        "alert": "REMEDIATION DRILL: Delete the pod 'health-check' which mounts the container runtime socket. Fix: kubectl delete pod health-check -n default",
        "injections": [
            {"type": "container_socket_mount", "params": {"namespace": "default", "name": "health-check"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Container runtime socket mounted",
             "resource_kind": "Pod", "resource_name": "health-check", "namespace": "default",
             "evidence": "hostPath: /run/containerd/containerd.sock",
             "remediation": "kubectl delete pod health-check -n default"},
        ],
    },
    {
        "difficulty": 0.15,
        "category": "runtime",
        "description": "A pod is running with no resource limits set",
        "alert": "REMEDIATION DRILL: Delete the pod 'hunger-check' which has no resource limits. Fix: kubectl delete pod hunger-check -n default",
        "injections": [
            {"type": "no_resource_limits", "params": {"namespace": "default", "name": "hunger-check"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_LOW, "title": "No resource limits",
             "resource_kind": "Pod", "resource_name": "hunger-check", "namespace": "default",
             "evidence": "resources.limits: not set",
             "remediation": "kubectl delete pod hunger-check -n default"},
        ],
    },

    # Tier 1 (0.2-0.3) — Single obvious vulnerability
    {
        "difficulty": 0.25,
        "category": "runtime",
        "description": "A pod has the container runtime socket mounted, enabling container escape",
        "alert": "SECURITY ALERT: Container runtime socket detected in pod configuration",
        "injections": [
            {"type": "container_socket_mount", "params": {"namespace": "default", "name": "health-check"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Container runtime socket mounted",
             "resource_kind": "Pod", "resource_name": "health-check", "namespace": "default",
             "evidence": "hostPath: /run/containerd/containerd.sock",
             "remediation": "Remove the container runtime socket volume mount and disable privileged mode"},
        ],
    },
    {
        "difficulty": 0.2,
        "category": "supply_chain",
        "description": "A pod is running without resource limits, risking resource exhaustion",
        "alert": "SECURITY ALERT: Pod detected with no resource limits configured",
        "injections": [
            {"type": "no_resource_limits", "params": {"namespace": "default", "name": "hunger-check"}},
        ],
        "expected_findings": [
            {"category": "supply_chain", "severity": SEVERITY_LOW, "title": "No resource limits",
             "resource_kind": "Pod", "resource_name": "hunger-check", "namespace": "default",
             "evidence": "resources.limits: not set",
             "remediation": "Set CPU and memory resource limits on all containers"},
        ],
    },
    {
        "difficulty": 0.25,
        "category": "runtime",
        "description": "A pod has a writable root filesystem, allowing runtime modification",
        "alert": "SECURITY ALERT: Writable root filesystem detected in pod",
        "injections": [
            {"type": "writable_root_fs", "params": {"namespace": "default", "name": "writable-fs-app"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_MEDIUM, "title": "Writable root filesystem",
             "resource_kind": "Pod", "resource_name": "writable-fs-app", "namespace": "default",
             "evidence": "readOnlyRootFilesystem: false",
             "remediation": "Set readOnlyRootFilesystem: true in the security context"},
        ],
    },
    {
        "difficulty": 0.2,
        "category": "secrets",
        "description": "A pod has hardcoded credentials in plain-text environment variables",
        "alert": "SECURITY ALERT: Hardcoded credentials detected in pod environment",
        "injections": [
            {"type": "hardcoded_creds", "params": {"namespace": "default", "name": "legacy-api"}},
        ],
        "expected_findings": [
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Hardcoded sensitive value in env",
             "resource_kind": "Pod", "resource_name": "legacy-api", "namespace": "default",
             "evidence": "env DB_PASSWORD=admin123!, API_SECRET_TOKEN=sk-live-abc123xyz789",
             "remediation": "Move credentials to Kubernetes Secrets and reference via secretKeyRef"},
        ],
    },

    # Tier 2 (0.35-0.5) — Requires investigation
    {
        "difficulty": 0.4,
        "category": "runtime",
        "description": "A pod shares the host IPC namespace, enabling inter-process communication attacks",
        "alert": "SECURITY ALERT: Host IPC namespace sharing detected",
        "injections": [
            {"type": "host_ipc", "params": {"namespace": "default", "name": "ipc-shared"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Host IPC namespace shared",
             "resource_kind": "Pod", "resource_name": "ipc-shared", "namespace": "default",
             "evidence": "hostIPC: true",
             "remediation": "Remove hostIPC: true from the pod spec"},
        ],
    },
    {
        "difficulty": 0.35,
        "category": "runtime",
        "description": "A container has allowPrivilegeEscalation enabled",
        "alert": "SECURITY ALERT: Privilege escalation allowed in container security context",
        "injections": [
            {"type": "allow_privilege_escalation", "params": {"namespace": "default", "name": "priv-esc-app"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Privilege escalation allowed",
             "resource_kind": "Pod", "resource_name": "priv-esc-app", "namespace": "default",
             "evidence": "allowPrivilegeEscalation: true",
             "remediation": "Set allowPrivilegeEscalation: false in the security context"},
        ],
    },
    {
        "difficulty": 0.45,
        "category": "rbac",
        "description": "A ClusterRole grants escalate and bind verbs on RBAC resources",
        "alert": "SECURITY ALERT: RBAC role with privilege escalation verbs detected",
        "injections": [
            {"type": "escalation_rbac_verbs", "params": {"namespace": "default", "role_name": "escalation-role"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "RBAC allows privilege escalation",
             "resource_kind": "ClusterRole", "resource_name": "escalation-role", "namespace": "*",
             "evidence": "verbs=['escalate', 'bind'] on rbac.authorization.k8s.io",
             "remediation": "Remove escalate and bind verbs from the ClusterRole"},
        ],
    },
    {
        "difficulty": 0.4,
        "category": "rbac",
        "description": "A namespaced Role grants wildcard permissions for read access",
        "alert": "SECURITY ALERT: Wildcard Role permissions detected in namespace",
        "injections": [
            {"type": "wildcard_ns_role", "params": {"namespace": "default", "role_name": "wildcard-ns-role"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_HIGH, "title": "Wildcard Role permissions",
             "resource_kind": "Role", "resource_name": "wildcard-ns-role", "namespace": "default",
             "evidence": "apiGroups=['*'], resources=['*']",
             "remediation": "Restrict Role to specific API groups and resources"},
        ],
    },
    {
        "difficulty": 0.35,
        "category": "network",
        "description": "An unauthenticated database service is exposed within the cluster",
        "alert": "SECURITY ALERT: Unauthenticated database service detected",
        "injections": [
            {"type": "unauthed_db_service", "params": {"namespace": "default", "name": "cache-store", "port": 6379}},
        ],
        "expected_findings": [
            {"category": "network", "severity": SEVERITY_HIGH, "title": "Unauthenticated database service",
             "resource_kind": "Service", "resource_name": "cache-store", "namespace": "default",
             "evidence": "ClusterIP service on port 6379 with no NetworkPolicy",
             "remediation": "Add authentication and create a NetworkPolicy to restrict access"},
        ],
    },
    {
        "difficulty": 0.45,
        "category": "rbac",
        "description": "A ServiceAccount is bound to the cluster-admin ClusterRole",
        "alert": "SECURITY ALERT: Cluster-admin binding detected for a ServiceAccount",
        "injections": [
            {"type": "cluster_admin_binding", "params": {"namespace": "default", "name": "admin-sa"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Cluster-admin binding",
             "resource_kind": "ClusterRoleBinding", "resource_name": "admin-sa-cluster-admin", "namespace": "*",
             "evidence": "binds ServiceAccount/admin-sa to ClusterRole/cluster-admin",
             "remediation": "Delete the ClusterRoleBinding and create a least-privilege Role instead"},
        ],
    },
    {
        "difficulty": 0.4,
        "category": "runtime",
        "description": "A pod mounts the host root filesystem at /host",
        "alert": "SECURITY ALERT: Host root filesystem mount detected",
        "injections": [
            {"type": "host_path_root", "params": {"namespace": "default", "name": "system-monitor"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "HostPath volume mount",
             "resource_kind": "Pod", "resource_name": "system-monitor", "namespace": "default",
             "evidence": "hostPath: /",
             "remediation": "Remove the hostPath volume and use PersistentVolumeClaims instead"},
        ],
    },
    {
        "difficulty": 0.5,
        "category": "runtime",
        "description": "A pod targets control-plane nodes with tolerations and node affinity",
        "alert": "SECURITY ALERT: Pod targeting control-plane nodes detected",
        "injections": [
            {"type": "control_plane_toleration", "params": {"namespace": "default", "name": "bench-scanner"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Control-plane node targeting",
             "resource_kind": "Pod", "resource_name": "bench-scanner", "namespace": "default",
             "evidence": "tolerations for control-plane/master, nodeAffinity for control-plane, hostPath: /var/lib/etcd",
             "remediation": "Remove control-plane tolerations and node affinity; do not mount etcd data directory"},
        ],
    },

    # Tier 3 (0.55-0.6) — Multi-vulnerability combos
    {
        "difficulty": 0.6,
        "category": "mixed",
        "description": "Container escape combo: runtime socket + privileged pod + host PID/network",
        "alert": "SECURITY ALERT: Multiple container escape vectors detected in cluster",
        "injections": [
            {"type": "container_socket_mount", "params": {"namespace": "default", "name": "health-check"}},
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "debug-tools"}},
            {"type": "host_pid_net", "params": {"namespace": "default", "name": "monitoring-agent"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Container runtime socket mounted",
             "resource_kind": "Pod", "resource_name": "health-check", "namespace": "default",
             "evidence": "hostPath: /run/containerd/containerd.sock",
             "remediation": "Remove the container runtime socket mount"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "debug-tools", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "Remove privileged: true"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Host PID/Network namespace",
             "resource_kind": "Pod", "resource_name": "monitoring-agent", "namespace": "default",
             "evidence": "hostPID: true, hostNetwork: true",
             "remediation": "Remove host namespace sharing"},
        ],
    },
    {
        "difficulty": 0.55,
        "category": "mixed",
        "description": "Service exposure combo: unauthenticated DB + exposed NodePort + no network policy",
        "alert": "SECURITY ALERT: Multiple service exposure issues detected",
        "injections": [
            {"type": "unauthed_db_service", "params": {"namespace": "default", "name": "cache-store", "port": 6379}},
            {"type": "exposed_service", "params": {"namespace": "default", "name": "internal-api", "node_port": 30080}},
        ],
        "expected_findings": [
            {"category": "network", "severity": SEVERITY_HIGH, "title": "Unauthenticated database service",
             "resource_kind": "Service", "resource_name": "cache-store", "namespace": "default",
             "evidence": "ClusterIP service on port 6379 with no NetworkPolicy",
             "remediation": "Add authentication and create a NetworkPolicy"},
            {"category": "network", "severity": SEVERITY_MEDIUM, "title": "Service exposed externally",
             "resource_kind": "Service", "resource_name": "internal-api", "namespace": "default",
             "evidence": "type=NodePort, nodePort=30080",
             "remediation": "Use ClusterIP with Ingress controller"},
            {"category": "network", "severity": SEVERITY_HIGH, "title": "No NetworkPolicy in namespace",
             "resource_kind": "Namespace", "resource_name": "default", "namespace": "default",
             "evidence": "0 NetworkPolicy objects",
             "remediation": "Create default-deny NetworkPolicy"},
        ],
    },
    {
        "difficulty": 0.6,
        "category": "mixed",
        "description": "Credential exposure combo: hardcoded creds + secrets in env + sensitive configmap",
        "alert": "SECURITY ALERT: Multiple credential exposure vectors detected",
        "injections": [
            {"type": "hardcoded_creds", "params": {"namespace": "default", "name": "legacy-api"}},
            {"type": "secrets_in_env", "params": {"namespace": "default", "name": "api-server"}},
            {"type": "sensitive_configmap", "params": {"namespace": "default", "name": "app-config"}},
        ],
        "expected_findings": [
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Hardcoded sensitive value in env",
             "resource_kind": "Pod", "resource_name": "legacy-api", "namespace": "default",
             "evidence": "env DB_PASSWORD=admin123!, API_SECRET_TOKEN=sk-live-abc123xyz789",
             "remediation": "Move credentials to Kubernetes Secrets"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Secret exposed as environment variable",
             "resource_kind": "Pod", "resource_name": "api-server", "namespace": "default",
             "evidence": "env -> secret ref",
             "remediation": "Mount secrets as volumes"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Sensitive data in ConfigMap",
             "resource_kind": "ConfigMap", "resource_name": "app-config", "namespace": "default",
             "evidence": "keys contain sensitive data",
             "remediation": "Move to Secret resource"},
        ],
    },

    # Tier 4 (0.85-0.9) — Full-spectrum advanced
    {
        "difficulty": 0.85,
        "category": "mixed",
        "description": "System-monitor full: host namespaces + IPC + host root + privileged + priv escalation + secrets",
        "alert": "SECURITY AUDIT: Comprehensive host-level security assessment required",
        "injections": [
            {"type": "host_pid_net", "params": {"namespace": "default", "name": "system-monitor"}},
            {"type": "host_ipc", "params": {"namespace": "default", "name": "ipc-agent"}},
            {"type": "host_path_root", "params": {"namespace": "default", "name": "fs-accessor"}},
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "debug-tools"}},
            {"type": "allow_privilege_escalation", "params": {"namespace": "default", "name": "priv-esc-app"}},
            {"type": "secrets_in_env", "params": {"namespace": "default", "name": "api-server"}},
        ],
        "expected_findings": [
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Host PID/Network namespace",
             "resource_kind": "Pod", "resource_name": "system-monitor", "namespace": "default",
             "evidence": "hostPID: true, hostNetwork: true",
             "remediation": "Remove host namespace sharing"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Host IPC namespace shared",
             "resource_kind": "Pod", "resource_name": "ipc-agent", "namespace": "default",
             "evidence": "hostIPC: true",
             "remediation": "Remove hostIPC: true from the pod spec"},
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "HostPath volume mount",
             "resource_kind": "Pod", "resource_name": "fs-accessor", "namespace": "default",
             "evidence": "hostPath: /",
             "remediation": "Remove the hostPath volume and use PersistentVolumeClaims"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "debug-tools", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "Remove privileged: true"},
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Privilege escalation allowed",
             "resource_kind": "Pod", "resource_name": "priv-esc-app", "namespace": "default",
             "evidence": "allowPrivilegeEscalation: true",
             "remediation": "Set allowPrivilegeEscalation: false"},
            {"category": "secrets", "severity": SEVERITY_HIGH, "title": "Secret exposed as environment variable",
             "resource_kind": "Pod", "resource_name": "api-server", "namespace": "default",
             "evidence": "env -> secret ref",
             "remediation": "Mount secrets as volumes"},
        ],
    },
    {
        "difficulty": 0.9,
        "category": "mixed",
        "description": "Full cluster takeover: cluster-admin binding + wildcard RBAC + privileged + control-plane targeting + host root",
        "alert": "SECURITY AUDIT: Full cluster takeover vector assessment required",
        "injections": [
            {"type": "cluster_admin_binding", "params": {"namespace": "default", "name": "admin-sa"}},
            {"type": "wildcard_rbac", "params": {"namespace": "default", "role_name": "dev-admin"}},
            {"type": "privileged_pod", "params": {"namespace": "default", "name": "debug-tools"}},
            {"type": "control_plane_toleration", "params": {"namespace": "default", "name": "bench-scanner"}},
            {"type": "host_path_root", "params": {"namespace": "default", "name": "fs-accessor"}},
        ],
        "expected_findings": [
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Cluster-admin binding",
             "resource_kind": "ClusterRoleBinding", "resource_name": "admin-sa-cluster-admin", "namespace": "*",
             "evidence": "binds ServiceAccount/admin-sa to ClusterRole/cluster-admin",
             "remediation": "Delete the ClusterRoleBinding and create a least-privilege Role"},
            {"category": "rbac", "severity": SEVERITY_CRITICAL, "title": "Wildcard RBAC permissions",
             "resource_kind": "ClusterRole", "resource_name": "dev-admin", "namespace": "*",
             "evidence": "verbs=['*'], resources=['*']",
             "remediation": "Apply least-privilege RBAC"},
            {"category": "runtime", "severity": SEVERITY_CRITICAL, "title": "Privileged container",
             "resource_kind": "Pod", "resource_name": "debug-tools", "namespace": "default",
             "evidence": "privileged: true",
             "remediation": "Remove privileged: true"},
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "Control-plane node targeting",
             "resource_kind": "Pod", "resource_name": "bench-scanner", "namespace": "default",
             "evidence": "tolerations for control-plane/master, nodeAffinity for control-plane, hostPath: /var/lib/etcd",
             "remediation": "Remove control-plane tolerations and node affinity"},
            {"category": "runtime", "severity": SEVERITY_HIGH, "title": "HostPath volume mount",
             "resource_kind": "Pod", "resource_name": "fs-accessor", "namespace": "default",
             "evidence": "hostPath: /",
             "remediation": "Remove the hostPath volume and use PersistentVolumeClaims"},
        ],
    },
]


class ScenarioGenerator:
    """Generates security vulnerability scenarios for training episodes."""

    def generate(self, difficulty: float, category_hint: str | None = None) -> VulnerabilityScenario:
        """Pick a scenario matching the requested difficulty and category."""
        candidates = [s for s in SCENARIO_POOL if s["difficulty"] <= difficulty + 0.15]
        if not candidates:
            candidates = SCENARIO_POOL[:3]

        if category_hint and category_hint != "all":
            cat_candidates = [s for s in candidates if s["category"] == category_hint]
            if cat_candidates:
                candidates = cat_candidates

        template = random.choice(candidates)
        scenario_id = str(uuid4())[:8]

        findings = []
        for i, f in enumerate(template["expected_findings"]):
            findings.append(SecurityFinding(
                finding_id=f"{scenario_id}-{i:03d}",
                category=f["category"],
                severity=f["severity"],
                title=f["title"],
                description=f.get("description", f["title"]),
                namespace=f["namespace"],
                resource_kind=f["resource_kind"],
                resource_name=f["resource_name"],
                evidence=f["evidence"],
                remediation=f["remediation"],
            ))

        return VulnerabilityScenario(
            scenario_id=scenario_id,
            difficulty=template["difficulty"],
            category=template["category"],
            injected_findings=findings,
            alert_message=template["alert"],
            description=template["description"],
        )

