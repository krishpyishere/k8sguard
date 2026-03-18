"""
K8sGuard Environment — AI agent scans and remediates K8s security vulnerabilities.

Modes (set via SCAN_MODE env var):
  scan       — agent discovers vulnerabilities in the cluster (default)
  training   — vulnerabilities are injected, agent must find and remediate them
"""

import json
import os
import logging
import time
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from .constants import MAX_STEPS, SYSTEM_NAMESPACES

try:
    from ..models import K8sGuardAction, K8sGuardObservation, K8sGuardState
except ImportError:
    from models import K8sGuardAction, K8sGuardObservation, K8sGuardState

from .llm_client import LLMClient
from .k8s_backend import K8sBackend
from .scenario_generator import ScenarioGenerator, SCENARIO_POOL
from .judge import SecurityJudge
from .vulnerability_injectors import VulnerabilityInjector

logger = logging.getLogger(__name__)


class K8sGuardEnvironment(Environment):
    """
    K8s Security Scanner Environment — agent discovers and remediates vulnerabilities.

    Config via env vars:
      SCAN_MODE      - "scan" (real cluster) or "training" (injected vulns)
      LLM_BACKEND    - "openai" (default), "hf", or "anthropic"
      LLM_MODEL      - model name
      SCAN_NAMESPACES - comma-separated namespace list (default: all non-system)
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = False

    def __init__(self):
        try:
            logger.info("Initializing K8sGuardEnvironment...")
            llm = LLMClient()
            self.backend = K8sBackend()
            self.mode = os.environ.get("SCAN_MODE", "training")
            self.scenario = None
            self._step_count = 0
            self.max_steps = int(os.environ.get("MAX_STEPS", str(MAX_STEPS)))
            self.history = []
            self.found_findings: list[str] = []
            self._state = K8sGuardState(episode_id=str(uuid4()), step_count=0)

            self.generator = ScenarioGenerator()
            self.judge = SecurityJudge(llm)
            self.injector = VulnerabilityInjector(self.backend.v1, self.backend.apps_v1)

            self._training_namespace = os.environ.get("TRAINING_NAMESPACE", "k8sguard-training")
            self._episode_count = 0
            self._curriculum_enabled = os.environ.get("CURRICULUM", "1") == "1"

            logger.info(f"K8sGuardEnvironment initialized (mode={self.mode}, curriculum={self._curriculum_enabled})")
        except Exception as e:
            logger.error(f"FATAL: K8sGuardEnvironment.__init__ failed: {e}", exc_info=True)
            raise

    def reset(self) -> K8sGuardObservation:
        logger.info("reset() called — preparing scan environment...")
        try:
            return self._do_reset()
        except Exception as e:
            logger.error(f"FATAL: reset() failed: {e}", exc_info=True)
            raise

    def _do_reset(self) -> K8sGuardObservation:
        self._step_count = 0
        self.history = []
        self.found_findings = []
        self._episode_count += 1

        if self.mode == "training":
            # Clean up previous training resources (cleanup polls until empty)
            self.injector.cleanup(self._training_namespace)

            # Curriculum: ramp difficulty from 0.15 to 0.9 over episodes
            if self._curriculum_enabled:
                difficulty = min(0.15 + self._episode_count * 0.002, 0.9)
            else:
                difficulty = float(os.environ.get("DIFFICULTY", "0.3"))
            category = os.environ.get("SCAN_CATEGORY", None)
            self.scenario = self.generator.generate(difficulty, category)

            # Find the matching template to get injection instructions
            for template in SCENARIO_POOL:
                if template["description"] == self.scenario.description:
                    for injection in template["injections"]:
                        params = dict(injection["params"])
                        params["namespace"] = self._training_namespace
                        result = self.injector.inject(injection["type"], params)
                        logger.info(f"  Injected: {result}")
                    break

            time.sleep(3)  # wait for resources to create
            alert = self.scenario.alert_message
            scan_scope = self._training_namespace
        else:
            # Real scan mode — scan whatever namespaces are configured
            self.scenario = None
            alert = "SECURITY AUDIT: Scan this cluster for security vulnerabilities"
            scan_scope = "all non-system namespaces"

        self._state = K8sGuardState(
            episode_id=str(uuid4()),
            step_count=0,
            difficulty=self.scenario.difficulty if self.scenario else 0.5,
            scan_scope=scan_scope,
            scan_category=self.scenario.category if self.scenario else "all",
        )

        # Initial cluster overview
        cluster_summary = self._build_security_summary()

        return K8sGuardObservation(
            command_output=(
                f"{alert}\n\n"
                f"Scan scope: {scan_scope}\n"
                f"Your task: Investigate the cluster for security vulnerabilities.\n"
                f"Use kubectl commands to inspect resources, then report findings with:\n"
                f"  'finding: <severity> - <description>'\n"
                f"To propose a fix:\n"
                f"  'remediate: kubectl <fix command>'"
            ),
            cluster_status_summary=cluster_summary,
            findings=[],
            steps_taken=0,
            max_steps=self.max_steps,
            hint="Start with: kubectl get pods -A, kubectl get clusterroles, kubectl get networkpolicies -A",
            done=False,
            reward=0.0,
        )

    def _build_security_summary(self) -> str:
        """Build a high-level security posture summary."""
        sections = []

        namespaces = [self._training_namespace] if self.mode == "training" else None
        if namespaces is None:
            # Get all non-system namespaces
            try:
                ns_list = self.backend.v1.list_namespace()
                namespaces = [ns.metadata.name for ns in ns_list.items
                              if ns.metadata.name not in SYSTEM_NAMESPACES]
            except Exception:
                namespaces = ["default"]

        for ns in namespaces:
            pods_output = self.backend.execute(f"kubectl get pods -n {ns}")
            if pods_output and pods_output != "No resources found.":
                sections.append(f"=== PODS ({ns}) ===\n{pods_output}")

        return "\n\n".join(sections) if sections else "(no workloads found)"

    def step(self, action: K8sGuardAction) -> K8sGuardObservation:
        self._step_count += 1
        self._state.step_count = self._step_count
        logger.info(f"  Step {self._step_count}/{self.max_steps}: {action.command}")

        raw_cmd = action.command.strip()
        is_finding = raw_cmd.lower().startswith("finding:")
        is_remediate = raw_cmd.lower().startswith("remediate:")

        # Block commands repeated 3+ times before execution
        repeat_count = sum(1 for h in self.history if h.get("command") == action.command)
        if repeat_count >= 2:
            output = f"BLOCKED: Already ran this command {repeat_count + 1} times."
        elif is_finding:
            finding_text = raw_cmd[8:].strip()
            self.found_findings.append(finding_text)
            output = f"Finding recorded: {finding_text}"
        elif is_remediate:
            exec_cmd = raw_cmd[10:].strip()
            if exec_cmd.startswith("kubectl"):
                output = self.backend.execute(exec_cmd)
            else:
                output = "Remediation must be a kubectl command."
        elif raw_cmd.startswith("kubectl"):
            output = self.backend.execute(raw_cmd)
        else:
            output = "Use kubectl commands, 'finding: <description>', or 'remediate: kubectl <command>'."

        # Score the action — small per-step rewards (outcome reward dominates at episode end)
        if self.scenario:
            reward, feedback = self.judge.evaluate(
                action.command, output, self.scenario, self.history, self.found_findings
            )
        else:
            reward, feedback = 0.0, "Action executed."

        logger.info(f"    -> reward={reward:.2f} | {feedback[:80]}")

        done = False

        # Check completion or timeout — apply outcome reward
        if self._step_count >= self.max_steps:
            done = True
            # Timeout: compute outcome reward, zero out per-step accumulation
            outcome, outcome_reason = self.judge.compute_outcome_reward(
                self.scenario, self.found_findings, self.history, timed_out=True,
            )
            raw_sum = sum(h.get("reward", 0) for h in self.history) + reward
            reward -= raw_sum  # zero out per-step total
            reward += outcome  # replace with outcome score
            feedback = f"Scan timeout. {outcome_reason}"

        elif is_finding and self.scenario:
            is_complete, reason = self.judge.verify_scan_complete(
                self.scenario, self.found_findings, self.history
            )
            if is_complete:
                done = True
                # Scan complete: compute outcome reward, zero out per-step accumulation
                outcome, outcome_reason = self.judge.compute_outcome_reward(
                    self.scenario, self.found_findings, self.history, timed_out=False,
                )
                raw_sum = sum(h.get("reward", 0) for h in self.history) + reward
                reward -= raw_sum  # zero out per-step total
                reward += outcome  # replace with outcome score
                feedback = f"Scan complete! {reason} {outcome_reason}"

        self.history.append({
            "step": self._step_count,
            "command": action.command,
            "output": output[:300],
            "reward": reward,
            "feedback": feedback,
        })

        if done:
            self._save_transcript()

        return K8sGuardObservation(
            command_output=output,
            cluster_status_summary="" if not is_remediate else self._build_security_summary(),
            findings=list(self.found_findings),
            steps_taken=self._step_count,
            max_steps=self.max_steps,
            hint=feedback,
            done=done,
            reward=reward,
        )

    def _save_transcript(self):
        try:
            transcript = {
                "scan_id": self._state.episode_id,
                "mode": self.mode,
                "difficulty": self._state.difficulty,
                "category": self._state.scan_category,
                "steps": self._step_count,
                "findings": self.found_findings,
                "total_reward": sum(h.get("reward", 0) for h in self.history),
                "history": self.history,
            }
            log_path = os.environ.get("SCAN_LOG", "scan_transcripts.jsonl")
            with open(log_path, "a") as f:
                f.write(json.dumps(transcript) + "\n")
        except Exception as e:
            logger.warning(f"Failed to save transcript: {e}")

    @property
    def state(self) -> K8sGuardState:
        return self._state
