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

