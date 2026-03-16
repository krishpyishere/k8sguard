"""
Kubernetes API backend — auth, command dispatch, and health checks.

Command execution is delegated to k8s_commands.CommandHandler.
"""

import os
import logging

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .constants import SYSTEM_NAMESPACES
from .k8s_commands import CommandHandler, _pod_status

logger = logging.getLogger(__name__)


def _load_token_auth(endpoint: str, ca_cert_b64: str, token: str):
    """Authenticate to K8s with a bearer token + CA cert."""
    import tempfile
    import base64
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    configuration = client.Configuration()
    configuration.host = endpoint.strip()
    configuration.api_key = {"BearerToken": token.strip()}
    configuration.api_key_prefix = {"BearerToken": "Bearer"}

    ca_cert_b64 = ca_cert_b64.strip()
    try:
        ca_cert = base64.b64decode(ca_cert_b64)
        ca_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        ca_path.write(ca_cert)
        ca_path.close()
        configuration.ssl_ca_cert = ca_path.name
        logger.info(f"K8s CA cert loaded ({len(ca_cert)} bytes)")
    except Exception as e:
        logger.warning(f"Failed to decode K8S_CA_CERT ({e}), falling back to insecure TLS")
        configuration.verify_ssl = False

    client.Configuration.set_default(configuration)


class K8sBackend:
    """Gateway to a live Kubernetes cluster.

    Auth:  Token-based, kubeconfig, or in-cluster.
    Commands:  Delegated to CommandHandler (k8s_commands.py).
    """

    def __init__(self):
        # Auth priority: kubeconfig > in-cluster > token-based
        try:
            config.load_kube_config()
            logger.info("K8s auth: kubeconfig")
        except config.ConfigException:
            try:
                config.load_incluster_config()
                logger.info("K8s auth: in-cluster")
            except config.ConfigException:
                endpoint = os.environ.get("K8S_ENDPOINT")
                ca_cert_b64 = os.environ.get("K8S_CA_CERT")
                token = os.environ.get("K8S_TOKEN")
                if endpoint and ca_cert_b64 and token:
                    _load_token_auth(endpoint, ca_cert_b64, token)
                    logger.info(f"K8s auth: token-based ({endpoint})")
                else:
                    raise RuntimeError(
                        "No K8s auth available. Set kubeconfig, run in-cluster, "
                        "or set K8S_ENDPOINT + K8S_TOKEN + K8S_CA_CERT env vars."
                    )

        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()

        # Discover app namespaces (all non-system)
        self.app_namespaces = self._get_app_namespaces()
        self.commands = CommandHandler(self.v1, self.apps_v1, app_namespaces=self.app_namespaces)

    def _get_app_namespaces(self) -> list[str]:
        try:
            ns_list = self.v1.list_namespace()
            return [ns.metadata.name for ns in ns_list.items
                    if ns.metadata.name not in SYSTEM_NAMESPACES]
        except ApiException:
            return ["default"]

    def execute(self, command: str) -> str:
        """Parse and execute a kubectl-style command on the real cluster."""
        cmd = command.strip()
        if cmd.startswith("kubectl "):
            cmd = cmd[8:]

        parts = cmd.split()
        if not parts:
            return "error: empty command"

        verb = parts[0]
        ns = self._parse_namespace(parts)

        # Strip namespace flags from parts before passing to handler
        cleaned = []
        skip = False
        for p in parts[1:]:
            if skip:
                skip = False
                continue
            if p == "-n":
                skip = True
                continue
            if p in ("--all-namespaces", "-A"):
                continue
            cleaned.append(p)

        try:
            return self.commands.dispatch(verb, cleaned, ns, raw_cmd=cmd)
        except ApiException as e:
            return f"Error from server ({e.reason}): {e.body}"
        except Exception as e:
            logger.error(f"Execute error: {e}", exc_info=True)
            return f"ERROR: {str(e)}"

    def check_health(self) -> dict:
        """Return {namespace: {pod_name: status}} for all app namespaces."""
        health = {}
        for ns in self.app_namespaces:
            try:
                pods = self.v1.list_namespaced_pod(ns)
                health[ns] = {
                    p.metadata.name: _pod_status(p)
                    for p in pods.items
                }
            except ApiException as e:
                logger.error(f"check_health: failed to list pods in '{ns}': {e.reason}")
                health[ns] = {}
        return health

    @staticmethod
    def _parse_namespace(parts: list[str]) -> str | None:
        for i, p in enumerate(parts):
            if p == "-n" and i + 1 < len(parts):
                return parts[i + 1]
        if "--all-namespaces" in parts or "-A" in parts:
            return "__all__"
        return None
