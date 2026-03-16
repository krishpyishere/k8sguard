"""
Data models for K8sGuard — Kubernetes Security Scanner.

Defines Action, Observation, State for K8s security scanning and remediation.
"""

from dataclasses import dataclass, field
from pydantic import Field as PydanticField

from openenv.core.env_server.types import Action, Observation, State


class K8sGuardAction(Action):
    """Agent's action — a kubectl command or security assessment."""
    command: str = PydanticField(..., min_length=1, description="kubectl command or finding:/remediate: statement")


class K8sGuardObservation(Observation):
    """What the agent sees after each action."""
    command_output: str = PydanticField(default="", description="Output from the last command")
    cluster_status_summary: str = PydanticField(default="", description="Current security posture summary")
    findings: list[str] = PydanticField(default_factory=list, description="Security findings so far")
    steps_taken: int = PydanticField(default=0, ge=0, description="Steps taken this episode")
    max_steps: int = PydanticField(default=25, description="Max steps per episode")
    hint: str = PydanticField(default="", description="Guidance for the agent")


class K8sGuardState(State):
    """Episode metadata."""
    scan_id: str = ""
    difficulty: float = 0.2
    scan_scope: str = ""  # which namespaces/resources to scan
    injected_vulns: list[str] = PydanticField(default_factory=list)
    found_vulns: list[str] = PydanticField(default_factory=list)
    remediated_vulns: list[str] = PydanticField(default_factory=list)
    is_complete: bool = False
    cumulative_reward: float = 0.0
    scan_category: str = ""  # rbac, network, runtime, supply_chain, or "all"


@dataclass
class SecurityFinding:
    """A single security finding discovered during a scan."""
    finding_id: str
    category: str  # rbac, secrets, network, runtime, supply_chain
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    namespace: str
    resource_kind: str  # Pod, Deployment, Role, ClusterRole, etc.
    resource_name: str
    evidence: str  # the specific config/output that proves the finding
    remediation: str  # how to fix it
    cve: str = ""  # optional CVE reference


@dataclass
class VulnerabilityScenario:
    """A set of injected vulnerabilities for training episodes."""
    scenario_id: str
    difficulty: float
    category: str  # rbac, secrets, network, runtime, supply_chain, mixed
    injected_findings: list[SecurityFinding] = field(default_factory=list)
    alert_message: str = ""
    description: str = ""
