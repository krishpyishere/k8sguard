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
    # Kubernetes Goat — additional vulnerability types
    "host_ipc": {
        "category": "runtime",
        "severity": SEVERITY_CRITICAL,
        "title": "Host IPC namespace shared",
        "description": "Pod shares host IPC namespace — can communicate with host processes via shared memory",
    },
    "allow_privilege_escalation": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Privilege escalation allowed",
        "description": "Container allows privilege escalation via setuid/setgid binaries",
    },
    "container_socket_mount": {
        "category": "runtime",
        "severity": SEVERITY_CRITICAL,
        "title": "Container runtime socket mounted",
        "description": "Pod mounts containerd/docker socket — enables full container escape",
    },
    "unauthed_db_service": {
        "category": "network",
        "severity": SEVERITY_HIGH,
        "title": "Unauthenticated database service",
        "description": "Service exposes a common DB port with no NetworkPolicy protection",
    },
    "cluster_admin_binding": {
        "category": "rbac",
        "severity": SEVERITY_CRITICAL,
        "title": "Cluster-admin binding",
        "description": "ServiceAccount or user bound to cluster-admin ClusterRole",
    },
    "control_plane_toleration": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Control-plane node targeting",
        "description": "Pod tolerates control-plane taints and can schedule on master nodes",
    },
    "hardcoded_creds": {
        "category": "secrets",
        "severity": SEVERITY_HIGH,
        "title": "Hardcoded sensitive value in env",
        "description": "Container has plain-text passwords or API keys directly in env.value",
    },
    "host_path_root": {
        "category": "runtime",
        "severity": SEVERITY_CRITICAL,
        "title": "HostPath volume mount",
        "description": "Pod mounts the entire host root filesystem (/) — full host read/write access",
    },
    # KICS-derived checks — Runtime/Container
    "no_drop_caps": {
        "category": "runtime",
        "severity": SEVERITY_LOW,
        "title": "Container does not drop all capabilities",
        "description": "Container does not drop ALL capabilities — unnecessary privileges retained",
    },
    "net_raw_not_dropped": {
        "category": "runtime",
        "severity": SEVERITY_MEDIUM,
        "title": "NET_RAW capability not dropped",
        "description": "Container does not drop NET_RAW — allows ARP/packet spoofing attacks",
    },
    "no_seccomp_profile": {
        "category": "runtime",
        "severity": SEVERITY_MEDIUM,
        "title": "No seccomp profile configured",
        "description": "Container has no seccomp profile — all syscalls are permitted",
    },
    "no_apparmor_profile": {
        "category": "runtime",
        "severity": SEVERITY_LOW,
        "title": "No AppArmor profile configured",
        "description": "Container has no AppArmor profile annotation — no MAC enforcement",
    },
    "no_liveness_probe": {
        "category": "runtime",
        "severity": SEVERITY_LOW,
        "title": "No liveness probe configured",
        "description": "Container has no liveness probe — unresponsive containers will not be restarted",
    },
    "no_readiness_probe": {
        "category": "runtime",
        "severity": SEVERITY_MEDIUM,
        "title": "No readiness probe configured",
        "description": "Container has no readiness probe — traffic may be routed to unready containers",
    },
    "unmasked_proc_mount": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Container runs with unmasked /proc",
        "description": "Container has procMount: Unmasked — can read sensitive kernel parameters",
    },
    "writable_os_dir_mount": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Writable mount on sensitive OS directory",
        "description": "Container has writable volume mount on /etc, /var, /usr, or other sensitive OS paths",
    },
    "unsafe_sysctls": {
        "category": "runtime",
        "severity": SEVERITY_HIGH,
        "title": "Pod uses unsafe sysctl",
        "description": "Pod sets unsafe kernel sysctls that can affect other pods on the node",
    },
    "image_pull_not_always": {
        "category": "runtime",
        "severity": SEVERITY_LOW,
        "title": "Image pull policy not set to Always",
        "description": "Container imagePullPolicy is not Always — may use stale cached images",
    },
    "ingress_exposes_workload": {
        "category": "network",
        "severity": SEVERITY_MEDIUM,
        "title": "Ingress exposes workload externally",
        "description": "Ingress resource routes external traffic to internal service",
    },
    "dashboard_enabled": {
        "category": "runtime",
        "severity": SEVERITY_LOW,
        "title": "Kubernetes Dashboard is deployed",
        "description": "Kubernetes Dashboard is running — common attack vector for cluster compromise",
    },
    # KICS-derived checks — RBAC/Identity
    "rbac_exec_permission": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "RBAC grants exec permission on pods",
        "description": "ClusterRole grants pods/exec access — allows kubectl exec shell access to containers",
    },
    "rbac_port_forward": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "RBAC grants port-forward permission",
        "description": "ClusterRole grants pods/portforward access — bypasses network security restrictions",
    },
    "rbac_create_pods": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "RBAC grants create permission on pods",
        "description": "ClusterRole grants create verb on pods — privilege escalation vector",
    },
    "role_binding_default_sa": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "Role bound to default service account",
        "description": "RoleBinding or ClusterRoleBinding grants permissions to the default ServiceAccount",
    },
    "shared_service_account": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "Shared service account",
        "description": "Multiple pods share the same non-default ServiceAccount token",
    },
    "sa_name_undefined": {
        "category": "rbac",
        "severity": SEVERITY_MEDIUM,
        "title": "Service account name undefined",
        "description": "Pod uses default/undefined serviceAccountName — implicit broad access",
    },
    # KICS-derived checks — Network
    "default_namespace_used": {
        "category": "network",
        "severity": SEVERITY_MEDIUM,
        "title": "Workload in default namespace",
        "description": "Workload deployed in the 'default' namespace — no isolation, bad practice",
    },
    "network_policy_no_target": {
        "category": "network",
        "severity": SEVERITY_LOW,
        "title": "NetworkPolicy not targeting any pod",
        "description": "NetworkPolicy podSelector matches zero pods — policy is ineffective",
    },
}

# ---- Timeouts ----
SCAN_POLL_INTERVAL = 2
SCAN_MAX_POLLS = 15
LLM_TIMEOUT = 60
