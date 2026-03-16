"""
Shared constants for K8sGuard — Kubernetes Security Scanner.

Central place for scan categories, severity levels, namespace config, and defaults.
"""

import os

# ---- Default scan targets ----
# Scan all namespaces by default; can be overridden via env var
SCAN_NAMESPACES = os.environ.get(
    "SCAN_NAMESPACES", ""
).split(",") if os.environ.get("SCAN_NAMESPACES") else None  # None = all non-system namespaces

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}

DEFAULT_NAMESPACE = "default"
MAX_STEPS = 25  # max agent actions per scan episode

# ---- Security finding severity levels ----
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}

# ---- Security scan categories ----
SCAN_CATEGORIES = {
    # RBAC & Identity
    "rbac_wildcard": {
        "category": "rbac",
        "severity": SEVERITY_CRITICAL,
        "title": "Wildcard RBAC permissions",
        "description": "ClusterRole or Role grants '*' verbs or resources — equivalent to cluster-admin",
    },
    "rbac_privilege_escalation": {
        "category": "rbac",
        "severity": SEVERITY_CRITICAL,
        "title": "RBAC allows privilege escalation",
        "description": "Role grants 'escalate', 'bind', or 'impersonate' verbs",
    },
    "rbac_secrets_access": {
        "category": "rbac",
        "severity": SEVERITY_HIGH,
        "title": "Broad secrets access",
        "description": "Role grants get/list/watch on secrets across namespaces",
    },
    "default_sa_mounted": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "Default service account token auto-mounted",
        "description": "Pod uses default SA with automountServiceAccountToken not disabled",
    },
    "sa_token_mounted": {
        "category": "rbac",
        "severity": SEVERITY_LOW,
        "title": "Service account token mounted unnecessarily",
        "description": "Pod mounts SA token but doesn't need K8s API access",
    },
    # Secrets & Sensitive Data
    "secret_in_env": {
        "category": "secrets",
        "severity": SEVERITY_HIGH,
        "title": "Secret exposed as environment variable",
        "description": "Secret value injected via env var instead of volume mount (visible in describe/logs)",
    },
    "secret_unencrypted": {
        "category": "secrets",
        "severity": SEVERITY_MEDIUM,
        "title": "Secrets not encrypted at rest",
        "description": "Cluster does not have encryption-at-rest configured for secrets",
    },
    "configmap_sensitive": {
        "category": "secrets",
        "severity": SEVERITY_HIGH,
        "title": "Sensitive data in ConfigMap",
        "description": "ConfigMap contains passwords, tokens, or keys in plain text",
    },
    # Network & Isolation
    "no_network_policy": {
        "category": "network",
        "severity": SEVERITY_HIGH,
        "title": "No NetworkPolicy in namespace",
        "description": "Namespace has no network policies — all pod-to-pod traffic is allowed",
    },
    "service_external": {
        "category": "network",
        "severity": SEVERITY_MEDIUM,
        "title": "Service exposed externally",
        "description": "Service type LoadBalancer or NodePort exposes workload outside cluster",
    },
    "no_egress_policy": {
        "category": "network",
        "severity": SEVERITY_MEDIUM,
        "title": "No egress restrictions",
        "description": "No network policy restricts outbound traffic — pods can reach any external endpoint",
    },
    # Container & Runtime Security
    "privileged_container": {
        "category": "runtime",
        "severity": SEVERITY_CRITICAL,
        "title": "Privileged container",
        "description": "Container runs with privileged: true — full host access",
    },
    "host_pid_net": {
        "category": "runtime",
        "severity": SEVERITY_CRITICAL,
        "title": "Host PID/Network namespace",
        "description": "Pod shares host PID or network namespace — can see/interact with host processes",
    },
    "host_path_mount": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "HostPath volume mount",
        "description": "Pod mounts host filesystem path — potential container escape vector",
    },
    "run_as_root": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Container runs as root",
        "description": "Container runs as UID 0 or has no runAsNonRoot constraint",
    },
    "no_readonly_rootfs": {
        "category": "runtime",
        "severity": SEVERITY_MEDIUM,
        "title": "Writable root filesystem",
        "description": "Container has writable root filesystem — malware can persist",
    },
    "no_security_context": {
        "category": "runtime",
        "severity": SEVERITY_MEDIUM,
        "title": "Missing security context",
        "description": "Pod/container has no securityContext defined",
    },
    "capability_dangerous": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Dangerous Linux capabilities",
        "description": "Container has SYS_ADMIN, NET_ADMIN, SYS_PTRACE, or ALL capabilities",
    },
    "no_resource_limits": {
        "category": "supply_chain",
        "severity": SEVERITY_LOW,
        "title": "No resource limits",
        "description": "Container has no CPU/memory limits — can DoS the node",
    },
    # Supply Chain & Image Security
    "image_latest": {
        "category": "supply_chain",
        "severity": SEVERITY_MEDIUM,
        "title": "Image uses :latest tag",
        "description": "Container uses :latest or no tag — unpinned, mutable supply chain",
    },
    "image_no_digest": {
        "category": "supply_chain",
        "severity": SEVERITY_LOW,
        "title": "Image not pinned by digest",
        "description": "Image referenced by tag only, not sha256 digest",
    },
    "no_image_pull_policy": {
        "category": "supply_chain",
        "severity": SEVERITY_LOW,
        "title": "Missing imagePullPolicy",
        "description": "No explicit imagePullPolicy — may use cached (stale) images",
    },
}

# ---- Timeouts ----
SCAN_POLL_INTERVAL = 2
SCAN_MAX_POLLS = 15
LLM_TIMEOUT = 60
