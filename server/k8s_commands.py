"""
Kubectl command handlers — parses and executes kubectl-style commands via K8s API.

Supports standard kubectl verbs plus security-relevant commands like 'auth can-i'.
Each handler takes (parts, namespace) and returns a string (matching kubectl output format).
"""

import logging
import re
import time
from datetime import datetime, timezone

from kubernetes import client
from kubernetes.client.rest import ApiException
from tabulate import tabulate

from .constants import DEFAULT_NAMESPACE

logger = logging.getLogger(__name__)


class CommandHandler:
    """Executes kubectl-style commands against the K8s API."""

    def __init__(
        self,
        v1: client.CoreV1Api,
        apps_v1: client.AppsV1Api,
        app_namespaces: list[str] | None = None,
    ):
        self.v1 = v1
        self.apps_v1 = apps_v1
        self.app_namespaces = app_namespaces or []

    def dispatch(self, verb: str, parts: list[str], ns: str | None, raw_cmd: str = "") -> str:
        """Route a kubectl verb to its handler. Returns kubectl-style output."""
        commands = {
            "get": self._cmd_get,
            "describe": self._cmd_describe,
            "logs": self._cmd_logs,
            "top": self._cmd_top,
            "rollout": self._cmd_rollout,
            "set": self._cmd_set,
            "delete": self._cmd_delete,
            "scale": self._cmd_scale,
            "taint": self._cmd_taint,
            "auth": self._cmd_auth,
        }
        if verb == "patch":
            return self._cmd_patch(raw_cmd, ns)

        handler = commands.get(verb)
        if not handler:
            return f"error: unknown command '{verb}'"
        return handler(parts, ns)

    # ---- get ----

    _GET_RESOURCES = None  # built lazily

    def _cmd_get(self, parts: list[str], ns: str | None) -> str:
        if not parts:
            return "error: resource type required"

        if self._GET_RESOURCES is None:
            self._GET_RESOURCES = {
                "pods": self._get_pods, "pod": self._get_pods, "po": self._get_pods,
                "deployments": self._get_deployments, "deployment": self._get_deployments, "deploy": self._get_deployments,
                "events": self._get_events, "ev": self._get_events,
                "nodes": self._get_nodes, "node": self._get_nodes,
                "services": self._get_services, "svc": self._get_services,
                "resourcequota": self._get_resourcequotas, "resourcequotas": self._get_resourcequotas, "quota": self._get_resourcequotas,
                "endpoints": self._get_endpoints, "ep": self._get_endpoints,
                "networkpolicy": self._get_networkpolicies, "networkpolicies": self._get_networkpolicies, "netpol": self._get_networkpolicies,
                "secrets": self._get_secrets, "secret": self._get_secrets,
                "serviceaccounts": self._get_serviceaccounts, "sa": self._get_serviceaccounts,
                "roles": self._get_roles, "role": self._get_roles,
                "clusterroles": self._get_clusterroles, "clusterrole": self._get_clusterroles,
                "rolebindings": self._get_rolebindings, "rolebinding": self._get_rolebindings,
                "clusterrolebindings": self._get_clusterrolebindings, "clusterrolebinding": self._get_clusterrolebindings,
                "configmaps": self._get_configmaps, "configmap": self._get_configmaps, "cm": self._get_configmaps,
            }

        resource = parts[0]
        handler = self._GET_RESOURCES.get(resource)
        if not handler:
            return f'error: the server doesn\'t have a resource type "{resource}"'
        return handler(ns)

    def _list_worker_items(self, fetch_fn):
        items = []
        for namespace in self.app_namespaces:
            try:
                items.extend(fetch_fn(namespace).items)
            except ApiException as e:
                if e.status == 404:
                    continue
                raise
        return items

    def _get_pods(self, ns: str | None) -> str:
        if ns == "__all__":
            pod_items = self._list_worker_items(self.v1.list_namespaced_pod)
        elif not ns:
            pods = self.v1.list_pod_for_all_namespaces()
            pod_items = pods.items
        else:
            pods = self.v1.list_namespaced_pod(ns)
            pod_items = pods.items

        if not pod_items:
            return "No resources found."

        show_ns = (ns == "__all__" or not ns)
        rows = []
        for p in pod_items:
            total = len(p.spec.containers)
            ready_count = sum(1 for cs in (p.status.container_statuses or []) if cs.ready)
            status = _pod_status(p)
            restarts = sum(cs.restart_count for cs in (p.status.container_statuses or []))
            row = []
            if show_ns:
                row.append(p.metadata.namespace or "")
            row.extend([
                p.metadata.name,
                f"{ready_count}/{total}",
                status,
                str(restarts),
                _format_age(p.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "READY", "STATUS", "RESTARTS", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_deployments(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            deploy_items = self.apps_v1.list_namespaced_deployment(ns).items
        elif ns == "__all__":
            deploy_items = self._list_worker_items(self.apps_v1.list_namespaced_deployment)
        else:
            deploy_items = self.apps_v1.list_deployment_for_all_namespaces().items

        show_ns = not ns or ns == "__all__"
        rows = []
        for d in deploy_items:
            row = []
            if show_ns:
                row.append(d.metadata.namespace or "")
            row.extend([
                d.metadata.name,
                f"{d.status.ready_replicas or 0}/{d.spec.replicas or 0}",
                str(d.status.updated_replicas or 0),
                str(d.status.available_replicas or 0),
                _format_age(d.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_events(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            event_items = self.v1.list_namespaced_event(ns).items
        elif ns == "__all__":
            event_items = self._list_worker_items(self.v1.list_namespaced_event)
        else:
            event_items = self.v1.list_event_for_all_namespaces().items

        # Sort by time; key is always str so we never mix None with datetime (avoids TypeError)
        def _key(e):
            t = e.last_timestamp or e.metadata.creation_timestamp
            return getattr(t, "isoformat", lambda: "")() if t else "z"

        sorted_events = sorted(event_items, key=_key)[-20:]
        rows = []
        for e in sorted_events:
            rows.append([
                _format_age(e.last_timestamp or e.metadata.creation_timestamp),
                e.type or "Normal",
                e.reason or "",
                f"{e.involved_object.kind}/{e.involved_object.name}"[:20],
                (e.message or "")[:80],
            ])
        return tabulate(rows, headers=["LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"], tablefmt="plain")

    def _get_nodes(self, _ns: str | None = None) -> str:
        nodes = self.v1.list_node()
        rows = []
        for n in nodes.items:
            conditions = {c.type: c.status for c in (n.status.conditions or [])}
            status = "Ready" if conditions.get("Ready") == "True" else "NotReady"
            labels = n.metadata.labels or {}
            roles = ",".join(k.split("/")[-1] for k in labels if "node-role" in k) or "<none>"
            version = getattr(n.status.node_info, "kubelet_version", "") if n.status.node_info else ""
            rows.append([
                n.metadata.name,
                status,
                roles,
                _format_age(n.metadata.creation_timestamp),
                version,
            ])
        return tabulate(rows, headers=["NAME", "STATUS", "ROLES", "AGE", "VERSION"], tablefmt="plain")

    def _get_services(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            service_items = self.v1.list_namespaced_service(ns).items
        elif ns == "__all__":
            service_items = self._list_worker_items(self.v1.list_namespaced_service)
        else:
            service_items = self.v1.list_service_for_all_namespaces().items

        rows = []
        for s in service_items:
            ports = ",".join(f"{p.port}/{p.protocol}" for p in (s.spec.ports or []))
            rows.append([
                s.metadata.name,
                s.spec.type or "ClusterIP",
                s.spec.cluster_ip or "None",
                ports,
            ])
        return tabulate(rows, headers=["NAME", "TYPE", "CLUSTER-IP", "PORT(S)"], tablefmt="plain")

    def _get_resourcequotas(self, ns: str | None) -> str:
        if not ns or ns == "__all__":
            return "error: namespace required for resourcequota"
        quotas = self.v1.list_namespaced_resource_quota(ns)
        if not quotas.items:
            return "No resources found."

        lines = []
        for q in quotas.items:
            lines.append(f"Name:    {q.metadata.name}")
            rows = []
            for resource, hard in (q.status.hard or {}).items():
                used = (q.status.used or {}).get(resource, "0")
                rows.append([resource, str(used), hard])
            lines.append(tabulate(rows, headers=["Resource", "Used", "Hard"], tablefmt="plain"))
        return "\n".join(lines)

    def _get_endpoints(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            endpoint_items = self.v1.list_namespaced_endpoints(ns).items
        elif ns == "__all__":
            endpoint_items = self._list_worker_items(self.v1.list_namespaced_endpoints)
        else:
            endpoint_items = self.v1.list_endpoints_for_all_namespaces().items

        show_ns = not ns or ns == "__all__"
        rows = []
        for ep in endpoint_items:
            addresses = []
            for subset in (ep.subsets or []):
                for addr in (subset.addresses or []):
                    for port in (subset.ports or []):
                        addresses.append(f"{addr.ip}:{port.port}")
            row = []
            if show_ns:
                row.append(ep.metadata.namespace or "")
            row.extend([
                ep.metadata.name,
                ", ".join(addresses) if addresses else "<none>",
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "ENDPOINTS"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_networkpolicies(self, ns: str | None) -> str:
        net_v1 = client.NetworkingV1Api()
        if ns and ns != "__all__":
            policy_items = net_v1.list_namespaced_network_policy(ns).items
        elif ns == "__all__":
            policy_items = self._list_worker_items(net_v1.list_namespaced_network_policy)
        else:
            policy_items = net_v1.list_network_policy_for_all_namespaces().items

        if not policy_items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for p in policy_items:
            selector = p.spec.pod_selector.match_labels or {} if p.spec.pod_selector else {}
            row = []
            if show_ns:
                row.append(p.metadata.namespace or "")
            row.extend([
                p.metadata.name,
                str(selector) if selector else "<all pods>",
                _format_age(p.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "POD-SELECTOR", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_secrets(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            items = self.v1.list_namespaced_secret(ns).items
        elif ns == "__all__":
            items = self._list_worker_items(self.v1.list_namespaced_secret)
        else:
            items = self.v1.list_secret_for_all_namespaces().items

        if not items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for s in items:
            row = []
            if show_ns:
                row.append(s.metadata.namespace or "")
            row.extend([
                s.metadata.name,
                s.type or "Opaque",
                str(len(s.data or {})),
                _format_age(s.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "TYPE", "DATA", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_serviceaccounts(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            items = self.v1.list_namespaced_service_account(ns).items
        elif ns == "__all__":
            items = self._list_worker_items(self.v1.list_namespaced_service_account)
        else:
            items = self.v1.list_service_account_for_all_namespaces().items

        if not items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for sa in items:
            row = []
            if show_ns:
                row.append(sa.metadata.namespace or "")
            row.extend([
                sa.metadata.name,
                str(len(sa.secrets or [])),
                _format_age(sa.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "SECRETS", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_roles(self, ns: str | None) -> str:
        rbac_v1 = client.RbacAuthorizationV1Api()
        if ns and ns != "__all__":
            items = rbac_v1.list_namespaced_role(ns).items
        else:
            items = rbac_v1.list_role_for_all_namespaces().items

        if not items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for r in items:
            row = []
            if show_ns:
                row.append(r.metadata.namespace or "")
            row.extend([r.metadata.name, _format_age(r.metadata.creation_timestamp)])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_clusterroles(self, _ns: str | None = None) -> str:
        rbac_v1 = client.RbacAuthorizationV1Api()
        items = rbac_v1.list_cluster_role().items
        # Filter out system roles for readability
        items = [cr for cr in items if not cr.metadata.name.startswith("system:")]
        if not items:
            return "No resources found."

        rows = []
        for cr in items:
            rule_count = len(cr.rules or [])
            rows.append([cr.metadata.name, str(rule_count), _format_age(cr.metadata.creation_timestamp)])
        return tabulate(rows, headers=["NAME", "RULES", "AGE"], tablefmt="plain")

    def _get_rolebindings(self, ns: str | None) -> str:
        rbac_v1 = client.RbacAuthorizationV1Api()
        if ns and ns != "__all__":
            items = rbac_v1.list_namespaced_role_binding(ns).items
        else:
            items = rbac_v1.list_role_binding_for_all_namespaces().items

        if not items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for rb in items:
            subjects = ", ".join(
                f"{s.kind}/{s.name}" for s in (rb.subjects or [])
            ) or "<none>"
            row = []
            if show_ns:
                row.append(rb.metadata.namespace or "")
            row.extend([
                rb.metadata.name,
                f"{rb.role_ref.kind}/{rb.role_ref.name}",
                subjects[:60],
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "ROLE", "SUBJECTS"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    def _get_clusterrolebindings(self, _ns: str | None = None) -> str:
        rbac_v1 = client.RbacAuthorizationV1Api()
        items = rbac_v1.list_cluster_role_binding().items
        items = [crb for crb in items if not crb.metadata.name.startswith("system:")]
        if not items:
            return "No resources found."

        rows = []
        for crb in items:
            subjects = ", ".join(
                f"{s.kind}/{s.name}" for s in (crb.subjects or [])
            ) or "<none>"
            rows.append([
                crb.metadata.name,
                f"{crb.role_ref.kind}/{crb.role_ref.name}",
                subjects[:60],
            ])
        return tabulate(rows, headers=["NAME", "ROLE", "SUBJECTS"], tablefmt="plain")

    def _get_configmaps(self, ns: str | None) -> str:
        if ns and ns != "__all__":
            items = self.v1.list_namespaced_config_map(ns).items
        elif ns == "__all__":
            items = self._list_worker_items(self.v1.list_namespaced_config_map)
        else:
            items = self.v1.list_config_map_for_all_namespaces().items

        # Filter out kube-system configmaps
        items = [cm for cm in items if not (cm.metadata.name or "").startswith("kube-")]
        if not items:
            return "No resources found."

        show_ns = not ns or ns == "__all__"
        rows = []
        for cm in items:
            row = []
            if show_ns:
                row.append(cm.metadata.namespace or "")
            row.extend([
                cm.metadata.name,
                str(len(cm.data or {})),
                _format_age(cm.metadata.creation_timestamp),
            ])
            rows.append(row)
        headers = (["NAMESPACE"] if show_ns else []) + ["NAME", "DATA", "AGE"]
        return tabulate(rows, headers=headers, tablefmt="plain")

    # ---- describe ----

    def _cmd_describe(self, parts: list[str], ns: str | None) -> str:
        if len(parts) < 2:
            return "error: resource name required"

        describe_map = {
            "pod": self._describe_pod, "pods": self._describe_pod, "po": self._describe_pod,
            "deployment": self._describe_deployment, "deploy": self._describe_deployment,
            "node": self._describe_node, "nodes": self._describe_node,
            "service": self._describe_service, "svc": self._describe_service,
            "secret": self._describe_secret, "secrets": self._describe_secret,
            "sa": self._describe_sa, "serviceaccount": self._describe_sa,
            "role": self._describe_role, "roles": self._describe_role,
            "clusterrole": self._describe_clusterrole, "clusterroles": self._describe_clusterrole,
            "networkpolicy": self._describe_networkpolicy, "netpol": self._describe_networkpolicy,
            "configmap": self._describe_configmap, "cm": self._describe_configmap,
        }
        rtype, rname = parts[0], parts[1]
        handler = describe_map.get(rtype)
        if not handler:
            return f"error: unsupported describe for {rtype}"
        return handler(rname, ns)

    def _describe_pod(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        pods = self.v1.list_namespaced_pod(namespace)
        pod = next((p for p in pods.items if name in p.metadata.name), None)
        if not pod:
            return f'Error from server (NotFound): pods "{name}" not found in namespace "{namespace}"'

        lines = [
            f"Name:         {pod.metadata.name}",
            f"Namespace:    {pod.metadata.namespace}",
            f"Node:         {pod.spec.node_name or '<none>'}",
            f"Status:       {pod.status.phase}",
            f"IP:           {pod.status.pod_ip or '<none>'}",
            "Containers:",
        ]
        for c in pod.spec.containers:
            lines.append(f"  {c.name}:")
            lines.append(f"    Image:          {c.image}")
            cs = next((s for s in (pod.status.container_statuses or []) if s.name == c.name), None)
            if cs:
                lines.extend(_format_container_status(cs))
            if c.resources:
                if c.resources.limits:
                    lines.append("    Limits:")
                    for k, v in c.resources.limits.items():
                        lines.append(f"      {k}:     {v}")
                if c.resources.requests:
                    lines.append("    Requests:")
                    for k, v in c.resources.requests.items():
                        lines.append(f"      {k}:     {v}")
            if c.liveness_probe:
                lines.append(f"    Liveness:       {_format_probe(c.liveness_probe)}")
            if c.env:
                lines.append("    Environment:")
                for e in c.env:
                    lines.append(_format_env_var(e))

        events = self.v1.list_namespaced_event(
            namespace, field_selector=f"involvedObject.name={pod.metadata.name}")
        if events.items:
            lines.append("Events:")
            for e in events.items[-10:]:
                lines.append(f"  {e.type}\t{e.reason}\t{e.message}")

        return "\n".join(lines)

    def _describe_deployment(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        try:
            d = self.apps_v1.read_namespaced_deployment(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): deployments.apps "{name}" not found'

        lines = [
            f"Name:               {d.metadata.name}",
            f"Namespace:          {d.metadata.namespace}",
            f"Replicas:           {d.spec.replicas} desired | {d.status.available_replicas or 0} available",
            f"Strategy:           {d.spec.strategy.type if d.spec.strategy else 'RollingUpdate'}",
        ]
        for cond in (d.status.conditions or []):
            lines.append(f"  {cond.type}: {cond.status} ({cond.reason}) - {cond.message}")

        lines.append("Pod Template:")
        for c in d.spec.template.spec.containers:
            lines.append(f"  Container: {c.name}")
            lines.append(f"    Image:      {c.image}")
            if c.command:
                lines.append(f"    Command:    {c.command}")
            if c.resources and c.resources.limits:
                lines.append(f"    Limits:     {', '.join(f'{k}={v}' for k, v in c.resources.limits.items())}")
            if c.resources and c.resources.requests:
                lines.append(f"    Requests:   {', '.join(f'{k}={v}' for k, v in c.resources.requests.items())}")
            if c.liveness_probe:
                lines.append(f"    Liveness:   {_format_probe(c.liveness_probe)}")
            if c.readiness_probe:
                lines.append(f"    Readiness:  {_format_probe(c.readiness_probe)}")
            if c.env:
                lines.append("    Environment:")
                for e in c.env:
                    lines.append(_format_env_var(e))

        events = self.v1.list_namespaced_event(
            namespace, field_selector=f"involvedObject.name={d.metadata.name}")
        if events.items:
            lines.append("Events:")
            for e in events.items[-5:]:
                lines.append(f"  {e.type}\t{e.reason}\t{e.message}")

        return "\n".join(lines)

    def _describe_node(self, name: str, _ns: str | None = None) -> str:
        try:
            n = self.v1.read_node(name)
        except ApiException:
            return f'Error from server (NotFound): nodes "{name}" not found'

        alloc = n.status.allocatable or {}
        cap = n.status.capacity or {}
        lines = [f"Name:         {n.metadata.name}"]

        # Taints (critical for diagnosing scheduling failures)
        taints = n.spec.taints or []
        if taints:
            lines.append("Taints:")
            for t in taints:
                val = f"={t.value}" if t.value else ""
                lines.append(f"             {t.key}{val}:{t.effect}")
        else:
            lines.append("Taints:       <none>")

        # Conditions
        lines.append("Conditions:")
        for c in (n.status.conditions or []):
            lines.append(f"  {c.type:<20s} {c.status}")

        lines.append(f"Capacity:     cpu={cap.get('cpu', '?')}, memory={cap.get('memory', '?')}")
        lines.append(f"Allocatable:  cpu={alloc.get('cpu', '?')}, memory={alloc.get('memory', '?')}")
        return "\n".join(lines)

    def _describe_service(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        try:
            svc = self.v1.read_namespaced_service(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): services "{name}" not found'

        lines = [
            f"Name:         {svc.metadata.name}",
            f"Namespace:    {svc.metadata.namespace}",
            f"Type:         {svc.spec.type or 'ClusterIP'}",
            f"ClusterIP:    {svc.spec.cluster_ip or 'None'}",
            f"Selector:     {svc.spec.selector}",
        ]
        ports = ", ".join(f"{p.port}/{p.protocol}" for p in (svc.spec.ports or []))
        lines.append(f"Port(s):      {ports}")

        # Endpoints — shows whether the service actually has backends
        try:
            ep = self.v1.read_namespaced_endpoints(name, namespace)
            addresses = []
            for subset in (ep.subsets or []):
                for addr in (subset.addresses or []):
                    for port in (subset.ports or []):
                        addresses.append(f"{addr.ip}:{port.port}")
            lines.append(f"Endpoints:    {', '.join(addresses) if addresses else '<none>'}")
        except ApiException:
            lines.append("Endpoints:    <none>")

        return "\n".join(lines)

    def _describe_secret(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        try:
            s = self.v1.read_namespaced_secret(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): secrets "{name}" not found'

        lines = [
            f"Name:         {s.metadata.name}",
            f"Namespace:    {s.metadata.namespace}",
            f"Type:         {s.type or 'Opaque'}",
            f"Data:",
        ]
        for key in (s.data or {}):
            lines.append(f"  {key}:  {len(s.data[key])} bytes")
        return "\n".join(lines)

    def _describe_sa(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        try:
            sa = self.v1.read_namespaced_service_account(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): serviceaccounts "{name}" not found'

        lines = [
            f"Name:                {sa.metadata.name}",
            f"Namespace:           {sa.metadata.namespace}",
            f"Mountable secrets:   {[s.name for s in (sa.secrets or [])]}",
            f"Tokens:              {[s.name for s in (sa.secrets or []) if 'token' in s.name]}",
        ]
        if sa.automount_service_account_token is not None:
            lines.append(f"AutomountToken:      {sa.automount_service_account_token}")
        return "\n".join(lines)

    def _describe_role(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        rbac_v1 = client.RbacAuthorizationV1Api()
        try:
            role = rbac_v1.read_namespaced_role(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): roles "{name}" not found'

        lines = [
            f"Name:         {role.metadata.name}",
            f"Namespace:    {role.metadata.namespace}",
            "PolicyRule:",
        ]
        for rule in (role.rules or []):
            lines.append(f"  Resources:  {rule.resources or ['*']}")
            lines.append(f"  Verbs:      {rule.verbs or ['*']}")
            lines.append(f"  API Groups: {rule.api_groups or ['']}")
            lines.append("  ---")
        return "\n".join(lines)

    def _describe_clusterrole(self, name: str, _ns: str | None) -> str:
        rbac_v1 = client.RbacAuthorizationV1Api()
        try:
            cr = rbac_v1.read_cluster_role(name)
        except ApiException:
            return f'Error from server (NotFound): clusterroles "{name}" not found'

        lines = [
            f"Name:         {cr.metadata.name}",
            "PolicyRule:",
        ]
        for rule in (cr.rules or []):
            lines.append(f"  Resources:  {rule.resources or ['*']}")
            lines.append(f"  Verbs:      {rule.verbs or ['*']}")
            lines.append(f"  API Groups: {rule.api_groups or ['']}")
            lines.append("  ---")
        return "\n".join(lines)

    def _describe_networkpolicy(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        net_v1 = client.NetworkingV1Api()
        try:
            np = net_v1.read_namespaced_network_policy(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): networkpolicies "{name}" not found'

        lines = [
            f"Name:         {np.metadata.name}",
            f"Namespace:    {np.metadata.namespace}",
            f"PodSelector:  {np.spec.pod_selector.match_labels if np.spec.pod_selector else '<all>'}",
            f"PolicyTypes:  {np.spec.policy_types or ['Ingress']}",
        ]
        if np.spec.ingress:
            lines.append("Ingress:")
            for rule in np.spec.ingress:
                lines.append(f"  From: {rule._from or ['<all>']}")
                lines.append(f"  Ports: {rule.ports or ['<all>']}")
        if np.spec.egress:
            lines.append("Egress:")
            for rule in np.spec.egress:
                lines.append(f"  To: {rule.to or ['<all>']}")
                lines.append(f"  Ports: {rule.ports or ['<all>']}")
        return "\n".join(lines)

    def _describe_configmap(self, name: str, ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        try:
            cm = self.v1.read_namespaced_config_map(name, namespace)
        except ApiException:
            return f'Error from server (NotFound): configmaps "{name}" not found'

        lines = [
            f"Name:         {cm.metadata.name}",
            f"Namespace:    {cm.metadata.namespace}",
            "Data:",
        ]
        for key, value in (cm.data or {}).items():
            # Show first 200 chars of each value
            display = value[:200] + "..." if len(value) > 200 else value
            lines.append(f"  {key}:")
            lines.append(f"    {display}")
        return "\n".join(lines)

    # ---- auth ----

    def _cmd_auth(self, parts: list[str], ns: str | None) -> str:
        """Handle kubectl auth can-i commands."""
        if not parts or parts[0] != "can-i":
            return "error: only 'auth can-i' is supported"
        if len(parts) < 3:
            return "error: usage: kubectl auth can-i <verb> <resource> [--as=<user>]"

        verb = parts[1]
        resource = parts[2]
        namespace = ns or DEFAULT_NAMESPACE

        # Parse --as flag
        as_user = None
        for p in parts:
            if p.startswith("--as="):
                as_user = p[5:]

        # Use SelfSubjectAccessReview
        from kubernetes.client import AuthorizationV1Api
        auth_api = AuthorizationV1Api()

        try:
            if as_user:
                # SubjectAccessReview (checking another user)
                review = client.V1SubjectAccessReview(
                    spec=client.V1SubjectAccessReviewSpec(
                        user=as_user,
                        resource_attributes=client.V1ResourceAttributes(
                            namespace=namespace,
                            verb=verb,
                            resource=resource,
                        ),
                    ),
                )
                result = auth_api.create_subject_access_review(review)
            else:
                review = client.V1SelfSubjectAccessReview(
                    spec=client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=client.V1ResourceAttributes(
                            namespace=namespace,
                            verb=verb,
                            resource=resource,
                        ),
                    ),
                )
                result = auth_api.create_self_subject_access_review(review)

            allowed = result.status.allowed
            reason = result.status.reason or ""
            return f"{'yes' if allowed else 'no'}" + (f" - {reason}" if reason else "")
        except ApiException as e:
            return f"Error: {e.reason}"

    # ---- logs ----

    def _cmd_logs(self, parts: list[str], ns: str | None) -> str:
        if not parts:
            return "error: pod name required"
        pod_name = parts[0]
        namespace = ns or DEFAULT_NAMESPACE
        tail = 50
        container = None
        previous = False
        for i, p in enumerate(parts):
            if p.startswith("--tail="):
                try:
                    tail = int(p.split("=")[1])
                except (ValueError, IndexError):
                    pass
            if p == "-c" and i + 1 < len(parts):
                container = parts[i + 1]
            if p in ("--previous", "-p"):
                previous = True

        pods = self.v1.list_namespaced_pod(namespace)
        matched = next((p for p in pods.items if pod_name in p.metadata.name), None)
        if not matched:
            return f'Error from server (NotFound): pods "{pod_name}" not found'
        try:
            logs = self.v1.read_namespaced_pod_log(
                matched.metadata.name, namespace, container=container,
                tail_lines=tail, previous=previous)
            return logs if logs else "(no logs)"
        except ApiException as e:
            return f"Error: {e.reason}"

    # ---- top ----

    def _cmd_top(self, parts: list[str], ns: str | None) -> str:
        if not parts:
            return "error: resource type required"
        if parts[0] == "pods":
            return self._top_pods(ns)
        elif parts[0] == "nodes":
            return self._top_nodes()
        return "error: unsupported"

    def _top_pods(self, ns: str | None) -> str:
        try:
            api = client.CustomObjectsApi()
            if ns and ns != "__all__":
                metrics = api.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", ns, "pods")
            else:
                metrics = api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods")
            rows = []
            for item in metrics.get("items", []):
                for c in item.get("containers", []):
                    rows.append([
                        item["metadata"]["name"],
                        c["usage"].get("cpu", "0"),
                        c["usage"].get("memory", "0"),
                    ])
            return tabulate(rows, headers=["NAME", "CPU(cores)", "MEMORY(bytes)"], tablefmt="plain")
        except Exception:
            return "error: Metrics API not available. Use 'kubectl describe pod' to see resource requests/limits."

    def _top_nodes(self) -> str:
        try:
            api = client.CustomObjectsApi()
            metrics = api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
            rows = []
            for item in metrics.get("items", []):
                rows.append([
                    item["metadata"]["name"],
                    item["usage"].get("cpu", "0"),
                    "-",
                    item["usage"].get("memory", "0"),
                    "-",
                ])
            return tabulate(rows, headers=["NAME", "CPU(cores)", "CPU%", "MEMORY(bytes)", "MEMORY%"], tablefmt="plain")
        except Exception:
            return "error: Metrics API not available."

    # ---- mutation commands (also used by injectors) ----

    def rollout_restart(self, deploy_name: str, namespace: str) -> str:
        """Restart a deployment (triggers new rollout)."""
        try:
            body = {"spec": {"template": {"metadata": {"annotations": {
                "kubectl.kubernetes.io/restartedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ")
            }}}}}
            self.apps_v1.patch_namespaced_deployment(deploy_name, namespace, body)
            return f"deployment.apps/{deploy_name} restarted"
        except ApiException as e:
            return f"Error: {e.reason}"

    def _cmd_rollout(self, parts: list[str], ns: str | None) -> str:
        if not parts:
            return "error: subcommand required (restart, status, undo)"
        sub = parts[0]
        # Support both "rollout restart deployment/name" and "rollout restart deployment name"
        if sub in ("restart", "status", "undo") and len(parts) > 1:
            if "/" in parts[1]:
                deploy_name = parts[1].split("/")[-1]
            elif parts[1] in ("deployment", "deploy", "deployments") and len(parts) > 2:
                deploy_name = parts[2]
            else:
                deploy_name = parts[1]
            namespace = ns or DEFAULT_NAMESPACE
            if sub == "restart":
                return self.rollout_restart(deploy_name, namespace)
            elif sub == "undo":
                return self._rollout_undo(deploy_name, namespace)
            else:
                return self._rollout_status(deploy_name, namespace)
        return "error: unsupported rollout command"

    def _rollout_status(self, deploy_name: str, ns: str) -> str:
        """Check rollout status of a deployment."""
        try:
            d = self.apps_v1.read_namespaced_deployment(deploy_name, ns)
            desired = d.spec.replicas or 0
            updated = d.status.updated_replicas or 0
            available = d.status.available_replicas or 0
            ready = d.status.ready_replicas or 0
            if ready == desired and updated == desired and available == desired:
                return f"deployment \"{deploy_name}\" successfully rolled out"
            return (f"Waiting for deployment \"{deploy_name}\" rollout to finish: "
                    f"{updated} out of {desired} new replicas have been updated, "
                    f"{available} available, {ready} ready...")
        except ApiException as e:
            return f"Error: {e.reason}"

    def _rollout_undo(self, deploy_name: str, ns: str) -> str:
        """Rollback deployment to previous revision by copying the previous
        ReplicaSet's pod template into the deployment spec."""
        try:
            # Find ReplicaSets owned by this deployment
            rs_list = self.apps_v1.list_namespaced_replica_set(ns)
            owned_rs = []
            for rs in rs_list.items:
                for ref in (rs.metadata.owner_references or []):
                    if ref.kind == "Deployment" and ref.name == deploy_name:
                        revision = int(
                            (rs.metadata.annotations or {}).get(
                                "deployment.kubernetes.io/revision", "0"
                            )
                        )
                        owned_rs.append((revision, rs))

            if len(owned_rs) < 2:
                return f"error: no previous revision found for deployment \"{deploy_name}\""

            # Sort by revision descending, pick the second-highest (previous)
            owned_rs.sort(key=lambda x: x[0], reverse=True)
            prev_revision, prev_rs = owned_rs[1]

            # Patch deployment's pod template to match the previous RS
            deploy = self.apps_v1.read_namespaced_deployment(deploy_name, ns)
            deploy.spec.template = prev_rs.spec.template
            self.apps_v1.replace_namespaced_deployment(deploy_name, ns, deploy)

            return f"deployment.apps/{deploy_name} rolled back to revision {prev_revision}"
        except ApiException as e:
            return f"Error: {e.reason}"

    def set_resources(self, parts: list[str], ns: str) -> str:
        """Set resource limits/requests on a deployment. Used by both agent commands and injectors."""
        deploy_name = None
        container_name = None
        limits = {}
        requests = {}
        for i, p in enumerate(parts):
            if "/" in p and not p.startswith("-"):
                deploy_name = p.split("/")[-1]
            elif p in ("deployment", "deploy", "deployments") and i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                deploy_name = parts[i + 1]
            if p == "-c" and i + 1 < len(parts):
                container_name = parts[i + 1]
            if p.startswith("--limits="):
                for kv in p[len("--limits="):].split(","):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        limits[k] = v
                    else:
                        limits["memory"] = kv
            if p.startswith("--requests="):
                for kv in p[len("--requests="):].split(","):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        requests[k] = v
                    else:
                        requests["memory"] = kv
        if not deploy_name:
            return "error: deployment name required"
        if not limits and not requests:
            return "error: --limits= or --requests= required"
        try:
            deploy = self.apps_v1.read_namespaced_deployment(deploy_name, ns)
            matched = False
            available_containers = [c.name for c in deploy.spec.template.spec.containers]
            for c in deploy.spec.template.spec.containers:
                if container_name is None or c.name == container_name:
                    if not c.resources:
                        c.resources = client.V1ResourceRequirements()
                    if limits:
                        c.resources.limits = {**(c.resources.limits or {}), **limits}
                        # Clear requests that would exceed new limits
                        if c.resources.requests:
                            for k in limits:
                                c.resources.requests.pop(k, None)
                    if requests:
                        c.resources.requests = {**(c.resources.requests or {}), **requests}
                    matched = True
            if not matched:
                return (f"error: container '{container_name}' not found in deployment {deploy_name}. "
                        f"Available containers: {available_containers}")
            self.apps_v1.patch_namespaced_deployment(deploy_name, ns, deploy)
            return f"deployment.apps/{deploy_name} resource requirements updated"
        except ApiException as e:
            return f"Error: {e.reason}"

    def set_image(self, parts: list[str], ns: str) -> str:
        """Set container image on a deployment."""
        deploy_name = None
        container_image = {}
        for i, p in enumerate(parts):
            if "/" in p and "=" not in p:
                deploy_name = p.split("/")[-1]
            elif p in ("deployment", "deploy", "deployments") and i + 1 < len(parts) and "=" not in parts[i + 1] and not parts[i + 1].startswith("-"):
                deploy_name = parts[i + 1]
            elif "=" in p and not p.startswith("-"):
                cname, img = p.split("=", 1)
                container_image[cname] = img
        if not deploy_name:
            return "error: deployment name required"
        try:
            deploy = self.apps_v1.read_namespaced_deployment(deploy_name, ns)
            matched = False
            available_containers = [c.name for c in deploy.spec.template.spec.containers]
            for c in deploy.spec.template.spec.containers:
                if c.name in container_image:
                    c.image = container_image[c.name]
                    matched = True
            if not matched:
                requested = list(container_image.keys())
                return (f"error: container(s) {requested} not found in deployment {deploy_name}. "
                        f"Available containers: {available_containers}")
            self.apps_v1.patch_namespaced_deployment(deploy_name, ns, deploy)
            return f"deployment.apps/{deploy_name} image updated"
        except ApiException as e:
            return f"Error: {e.reason}"

    def set_env(self, parts: list[str], ns: str) -> str:
        """Set environment variables on a deployment."""
        deploy_name = None
        env_vars = {}
        for i, p in enumerate(parts):
            if "/" in p and "=" not in p:
                deploy_name = p.split("/")[-1]
            elif p in ("deployment", "deploy", "deployments") and i + 1 < len(parts) and "=" not in parts[i + 1] and not parts[i + 1].startswith("-"):
                deploy_name = parts[i + 1]
            elif "=" in p and not p.startswith("-"):
                k, v = p.split("=", 1)
                env_vars[k] = v
        if not deploy_name:
            return "error: deployment name required"
        try:
            deploy = self.apps_v1.read_namespaced_deployment(deploy_name, ns)
            for c in deploy.spec.template.spec.containers:
                if not c.env:
                    c.env = []
                for k, v in env_vars.items():
                    existing = next((e for e in c.env if e.name == k), None)
                    if existing:
                        existing.value = v
                    else:
                        c.env.append(client.V1EnvVar(name=k, value=v))
            self.apps_v1.patch_namespaced_deployment(deploy_name, ns, deploy)
            return f"deployment.apps/{deploy_name} env updated"
        except ApiException as e:
            return f"Error: {e.reason}"

    def _cmd_set(self, parts: list[str], ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        if not parts:
            return "error: subcommand required"
        sub = parts[0]
        if sub == "resources":
            return self.set_resources(parts[1:], namespace)
        elif sub == "image":
            return self.set_image(parts[1:], namespace)
        elif sub == "env":
            return self.set_env(parts[1:], namespace)
        return "error: unsupported set command"

    # ---- delete ----

    def _cmd_delete(self, parts: list[str], ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        if not parts:
            return "error: resource type required"
        rtype = parts[0]
        if len(parts) < 2:
            return "error: resource name required"
        rname = parts[1]

        # Namespaced resources
        namespaced_deleters = {
            "pod": self.v1.delete_namespaced_pod,
            "pods": self.v1.delete_namespaced_pod,
            "po": self.v1.delete_namespaced_pod,
            "deployment": lambda n, ns: self.apps_v1.delete_namespaced_deployment(n, ns),
            "deployments": lambda n, ns: self.apps_v1.delete_namespaced_deployment(n, ns),
            "deploy": lambda n, ns: self.apps_v1.delete_namespaced_deployment(n, ns),
            "service": self.v1.delete_namespaced_service,
            "services": self.v1.delete_namespaced_service,
            "svc": self.v1.delete_namespaced_service,
            "secret": self.v1.delete_namespaced_secret,
            "secrets": self.v1.delete_namespaced_secret,
            "configmap": self.v1.delete_namespaced_config_map,
            "configmaps": self.v1.delete_namespaced_config_map,
            "cm": self.v1.delete_namespaced_config_map,
            "serviceaccount": self.v1.delete_namespaced_service_account,
            "serviceaccounts": self.v1.delete_namespaced_service_account,
            "sa": self.v1.delete_namespaced_service_account,
            "resourcequota": self.v1.delete_namespaced_resource_quota,
            "networkpolicy": lambda n, ns: client.NetworkingV1Api().delete_namespaced_network_policy(n, ns),
            "networkpolicies": lambda n, ns: client.NetworkingV1Api().delete_namespaced_network_policy(n, ns),
            "netpol": lambda n, ns: client.NetworkingV1Api().delete_namespaced_network_policy(n, ns),
        }

        # Cluster-scoped resources
        rbac_v1 = client.RbacAuthorizationV1Api()
        cluster_deleters = {
            "clusterrole": rbac_v1.delete_cluster_role,
            "clusterroles": rbac_v1.delete_cluster_role,
            "clusterrolebinding": rbac_v1.delete_cluster_role_binding,
            "clusterrolebindings": rbac_v1.delete_cluster_role_binding,
        }

        # Namespaced resources that also accept role/rolebinding
        namespaced_rbac = {
            "role": rbac_v1.delete_namespaced_role,
            "roles": rbac_v1.delete_namespaced_role,
            "rolebinding": rbac_v1.delete_namespaced_role_binding,
            "rolebindings": rbac_v1.delete_namespaced_role_binding,
        }

        try:
            if rtype in namespaced_deleters:
                namespaced_deleters[rtype](rname, namespace)
                return f'{rtype} "{rname}" deleted'
            elif rtype in cluster_deleters:
                cluster_deleters[rtype](rname)
                return f'{rtype} "{rname}" deleted'
            elif rtype in namespaced_rbac:
                namespaced_rbac[rtype](rname, namespace)
                return f'{rtype} "{rname}" deleted'
        except ApiException as e:
            return f"Error: {e.reason}"

        return "error: unsupported delete"

    # ---- scale ----

    def _cmd_scale(self, parts: list[str], ns: str | None) -> str:
        namespace = ns or DEFAULT_NAMESPACE
        deploy_name = None
        replicas = None
        for i, p in enumerate(parts):
            if "/" in p:
                deploy_name = p.split("/")[-1]
            elif p in ("deployment", "deploy", "deployments") and i + 1 < len(parts):
                # "scale deployment frontend-cache" — next part is the name
                deploy_name = parts[i + 1]
            if p.startswith("--replicas="):
                try:
                    replicas = int(p.split("=")[1])
                except (ValueError, IndexError):
                    return "error: --replicas must be an integer"
        if deploy_name and replicas is not None:
            try:
                body = {"spec": {"replicas": replicas}}
                self.apps_v1.patch_namespaced_deployment(deploy_name, namespace, body)
                return f"deployment.apps/{deploy_name} scaled"
            except ApiException as e:
                return f"Error: {e.reason}"
        return "error: deployment name and --replicas required"

    # ---- taint ----

    def _cmd_taint(self, parts: list[str], _ns: str | None) -> str:
        """Handle kubectl taint node <name> <key>=<value>:<effect> or <key>:<effect>-"""
        if not parts or parts[0] not in ("node", "nodes"):
            return "error: taint only supports nodes (kubectl taint node <name> <taint-spec>)"
        if len(parts) < 3:
            return "error: usage: kubectl taint node <name> <key>=<value>:<effect> or <key>:<effect>-"

        node_name = parts[1]
        taint_spec = parts[2]

        try:
            node = self.v1.read_node(node_name)
        except ApiException:
            return f'Error from server (NotFound): nodes "{node_name}" not found'

        # Remove taint: key:effect- or key-
        if taint_spec.endswith("-"):
            taint_spec = taint_spec[:-1]
            key, _, effect = taint_spec.partition(":")
            existing = node.spec.taints or []
            new_taints = [
                t for t in existing
                if not (t.key == key and (not effect or t.effect == effect))
            ]
            if len(new_taints) == len(existing):
                return f'taint "{key}" not found'
            body = {"spec": {"taints": new_taints if new_taints else None}}
            self.v1.patch_node(node_name, body)
            return f'node/{node_name} untainted'
        else:
            # Add taint: key=value:effect or key:effect
            if ":" not in taint_spec:
                return "error: taint must include effect (e.g., key=value:NoSchedule)"
            kv, effect = taint_spec.rsplit(":", 1)
            if effect not in ("NoSchedule", "PreferNoSchedule", "NoExecute"):
                return f"error: invalid effect '{effect}'"
            key, _, value = kv.partition("=")
            existing = node.spec.taints or []
            existing.append(client.V1Taint(key=key, value=value or None, effect=effect))
            body = {"spec": {"taints": [
                {"key": t.key, "value": t.value, "effect": t.effect} for t in existing
            ]}}
            self.v1.patch_node(node_name, body)
            return f'node/{node_name} tainted'

    # ---- patch ----

    def _cmd_patch(self, raw_cmd: str, ns: str | None) -> str:
        """Handle kubectl patch — parses from raw command string to preserve JSON body."""
        import json
        namespace = ns or DEFAULT_NAMESPACE
        parts = raw_cmd.split()
        if len(parts) < 2:
            return "error: resource type and name required"
        # Support both "patch deployment name" and "patch deployment/name"
        if "/" in parts[1]:
            rtype, rname = parts[1].split("/", 1)
        elif len(parts) >= 3:
            rtype, rname = parts[1], parts[2]
        else:
            return "error: resource type and name required"

        # Extract JSON patch body — find first '{' and match braces
        # Strip all single quotes first (shell quoting artifacts)
        cleaned_cmd = raw_cmd.replace("'", "")
        brace_start = cleaned_cmd.find("{")
        if brace_start < 0:
            # Also try finding JSON after -p flag
            return "error: patch body required (-p '{...}')"

        patch_str = None
        depth = 0
        for j, ch in enumerate(cleaned_cmd[brace_start:], brace_start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    patch_str = cleaned_cmd[brace_start:j + 1]
                    break

        if not patch_str:
            return "error: patch body required (-p '{...}')"
        try:
            body = json.loads(patch_str)
            if rtype in ("deployment", "deploy", "deployments"):
                self.apps_v1.patch_namespaced_deployment(rname, namespace, body)
                return f"deployment.apps/{rname} patched"
        except ValueError as e:
            return f"error: invalid JSON in patch body: {e}"
        except ApiException as e:
            return f"Error from server ({e.reason}): {e.body}"
        return "error: unsupported patch target"


# ---- Shared utility functions ----

def _format_age(timestamp) -> str:
    """Format a K8s timestamp into a human-readable age string."""
    if not timestamp:
        return "<unknown>"
    if not hasattr(timestamp, 'timestamp'):
        return "<unknown>"
    delta = datetime.now(timezone.utc) - timestamp.replace(tzinfo=timezone.utc)
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _pod_status(pod) -> str:
    """Extract the display status for a pod (matches kubectl output)."""
    status = pod.status.phase or "Unknown"
    for cs in (pod.status.container_statuses or []):
        if cs.state and cs.state.waiting and cs.state.waiting.reason:
            status = cs.state.waiting.reason
        elif cs.state and cs.state.terminated and cs.state.terminated.reason:
            status = cs.state.terminated.reason
    return status


def _format_probe(probe) -> str:
    """Format a liveness/readiness probe for display."""
    if not probe:
        return "configured"
    if probe.http_get:
        p = probe.http_get
        return (f"http-get {p.path or '/'}:{p.port or 0} "
                f"delay={probe.initial_delay_seconds or 0}s period={probe.period_seconds or 0}s")
    if probe._exec and probe._exec.command:
        return (f"exec {probe._exec.command} "
                f"delay={probe.initial_delay_seconds}s period={probe.period_seconds}s")
    if probe.tcp_socket:
        return (f"tcp-socket :{probe.tcp_socket.port} "
                f"delay={probe.initial_delay_seconds}s period={probe.period_seconds}s")
    return "configured"


def _format_env_var(e) -> str:
    """Format an env var for describe output, showing secret/configmap references."""
    if e.value_from:
        if e.value_from.secret_key_ref:
            ref = e.value_from.secret_key_ref
            return f"      {e.name}:  <set to the key '{ref.key}' of secret '{ref.name}'>"
        if e.value_from.config_map_key_ref:
            ref = e.value_from.config_map_key_ref
            return f"      {e.name}:  <set to the key '{ref.key}' of config map '{ref.name}'>"
        if e.value_from.field_ref:
            return f"      {e.name}:  ({e.value_from.field_ref.field_path})"
        return f"      {e.name}:  <set from external source>"
    return f"      {e.name}: {e.value}"


def _format_container_status(cs) -> list[str]:
    """Format container status lines for describe output."""
    lines = []
    if cs.state and cs.state.running:
        lines.append("    State:          Running")
    elif cs.state and cs.state.waiting:
        lines.append("    State:          Waiting")
        lines.append(f"      Reason:       {cs.state.waiting.reason}")
    elif cs.state and cs.state.terminated:
        lines.append("    State:          Terminated")
        lines.append(f"      Reason:       {cs.state.terminated.reason}")
        lines.append(f"      Exit Code:    {cs.state.terminated.exit_code}")
    if cs.last_state and cs.last_state.terminated:
        lines.append("    Last State:     Terminated")
        lines.append(f"      Reason:       {cs.last_state.terminated.reason}")
        lines.append(f"      Exit Code:    {cs.last_state.terminated.exit_code}")
    lines.append(f"    Ready:          {cs.ready}")
    lines.append(f"    Restart Count:  {cs.restart_count}")
    return lines
