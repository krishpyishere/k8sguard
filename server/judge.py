"""
Security judge — evaluates agent's scanning actions and remediation quality.

Uses LLM to assess whether the agent:
1. Found the right vulnerabilities
2. Prioritized correctly (critical > high > medium > low)
3. Proposed correct remediations
4. Was thorough (didn't miss obvious findings)
"""

import logging
from .llm_client import LLMClient
from .constants import SEVERITY_ORDER

try:
    from ..models import SecurityFinding, VulnerabilityScenario
except ImportError:
    from models import SecurityFinding, VulnerabilityScenario

logger = logging.getLogger(__name__)

_MAX_PROMPT_CHARS = 4000
_MAX_HISTORY_ENTRIES = 6
_MAX_OUTPUT_CHARS = 200


def _truncate_text(text: str, max_chars: int) -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "... (truncated)"


JUDGE_SYSTEM = """You are a Kubernetes security expert evaluating an AI security scanner's actions.

Score each action on how well it contributes to finding and remediating cluster vulnerabilities.

Scoring guide:
  +0.5 to +1.0: Directly identifies a real vulnerability or applies correct remediation
  +0.1 to +0.4: Useful investigation (correct kubectl command targeting the right resource)
  0.0: Neutral (valid command but doesn't advance the scan)
  -0.1 to -0.3: Wasted step (irrelevant command, repeating work)
  -0.5 to -1.0: Wrong remediation that would break the cluster or create new vulnerabilities

Return JSON only: {"score": <float -1.0 to 1.0>, "feedback": "<1-2 sentence evaluation>"}"""


class SecurityJudge:
    """Evaluates agent actions during security scanning episodes."""

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def evaluate(
        self,
        command: str,
        output: str,
        scenario: VulnerabilityScenario,
        history: list,
        found_findings: list[str],
    ) -> tuple[float, str]:
        """Score an agent action.

        Returns (score, feedback) where score is -1.0 to 1.0.
        """
        # Heuristic fast-path for common patterns (no LLM call needed)
        score, feedback = self._heuristic_score(command, output, scenario, history)
        if score is not None:
            return score, feedback

        # Fall back to LLM judge
        return self._llm_score(command, output, scenario, history, found_findings)

    def _heuristic_score(
        self, command: str, output: str, scenario: VulnerabilityScenario, history: list
    ) -> tuple[float | None, str]:
        """Fast heuristic scoring for common patterns. Returns (None, "") to defer to LLM."""
        cmd_lower = command.lower()

        # Repeated command penalty
        repeat_count = sum(1 for h in history if h.get("command") == command)
        if repeat_count >= 2:
            return -0.5, "Command blocked — repeated too many times."
        if repeat_count == 1:
            return -0.2, "Repeated command — try a different approach."

        # Finding submission
        if cmd_lower.startswith("finding:"):
            finding_text = command[8:].strip().lower()
            for vuln in scenario.injected_findings:
                if (vuln.title.lower() in finding_text
                        or vuln.category in finding_text
                        or vuln.resource_name in finding_text):
                    sev_bonus = SEVERITY_ORDER.get(vuln.severity, 1) * 0.15
                    return 0.5 + sev_bonus, f"Correctly identified: {vuln.title}"
            return 0.1, "Finding submitted but doesn't match known vulnerabilities."

        # Remediation submission — heuristic scoring for common patterns
        if cmd_lower.startswith("remediate:"):
            remediation_text = command[10:].strip().lower()
            for vuln in scenario.injected_findings:
                resource = vuln.resource_name.lower()
                if resource in remediation_text:
                    # Exact delete command targeting a known-vulnerable resource
                    if "kubectl delete" in remediation_text:
                        return 0.5, f"Correct remediation: deleting {vuln.resource_kind}/{vuln.resource_name}"
                    # Targets the right resource but uses a complex action (patch, etc.)
                    return 0.3, f"Correct remediation target: {vuln.resource_kind}/{vuln.resource_name}"
            # No resource match — defer complex remediations to LLM
            return None, ""

        # Valid investigation commands
        _SCAN_COMMANDS = (
            "get pods", "get po", "get secrets", "get roles", "get clusterroles",
            "get rolebindings", "get clusterrolebindings", "get networkpolicies",
            "get netpol", "get sa", "get serviceaccounts", "get configmaps", "get cm",
            "describe pod", "describe deployment", "describe role", "describe clusterrole",
            "describe sa", "describe secret", "describe netpol", "describe networkpolicy",
            "describe rolebinding", "describe clusterrolebinding",
            "auth can-i", "get events",
        )
        if any(p in cmd_lower for p in _SCAN_COMMANDS):
            if repeat_count == 1:
                return -0.1, "Repeated investigation command — try a different approach."
            return 0.2, "Good investigation step."

        return None, ""  # defer to LLM

    def _llm_score(
        self,
        command: str,
        output: str,
        scenario: VulnerabilityScenario,
        history: list,
        found_findings: list[str],
    ) -> tuple[float, str]:
        vuln_summary = "\n".join(
            f"  - [{f.severity}] {f.title} ({f.resource_kind}/{f.resource_name} in {f.namespace})"
            for f in scenario.injected_findings
        )
        history_text = "\n".join(
            f"  Step {h['step']}: {h['command']} -> reward {h.get('reward', 0):.2f}"
            for h in history[-_MAX_HISTORY_ENTRIES:]
        ) or "  (first step)"

        user_prompt = f"""Evaluate this security scanning action.

SCENARIO:
- Description: {scenario.description}
- Known vulnerabilities:
{vuln_summary}

AGENT ACTION:
- Command: {command}
- Output: {_truncate_text(output, _MAX_OUTPUT_CHARS)}

ALREADY FOUND: {found_findings or "(none yet)"}

HISTORY:
{history_text}

Return JSON only: {{"score": <float -1.0 to 1.0>, "feedback": "<1-2 sentence evaluation>"}}"""

        try:
            result = self.llm.chat_json(JUDGE_SYSTEM, user_prompt, temperature=0.2, max_tokens=256)
            score = max(-1.0, min(1.0, float(result.get("score", 0.0))))
            feedback = result.get("feedback", "")
            return score, feedback
        except Exception as e:
            logger.error(f"Judge LLM error: {e}", exc_info=True)
            return 0.0, f"Judge error: {type(e).__name__}"

    def verify_scan_complete(
        self,
        scenario: VulnerabilityScenario,
        found_findings: list[str],
        history: list,
    ) -> tuple[bool, str]:
        """Check if the agent found all (or enough) vulnerabilities."""
        total = len(scenario.injected_findings)
        if total == 0:
            return True, "No vulnerabilities to find."

        found_count = len(found_findings)
        critical_high = [f for f in scenario.injected_findings
                         if f.severity in ("CRITICAL", "HIGH")]
        critical_high_found = sum(
            1 for f in critical_high
            if any(f.title.lower() in ff.lower() or f.resource_name in ff for ff in found_findings)
        )

        # Must find all critical/high to pass
        if critical_high and critical_high_found < len(critical_high):
            return False, (f"Found {critical_high_found}/{len(critical_high)} critical/high findings. "
                          f"Total: {found_count}/{total}")

        # Good enough if found >= 70% overall
        if found_count >= total * 0.7:
            return True, f"Scan complete: {found_count}/{total} findings identified."

        return False, f"Incomplete scan: {found_count}/{total} findings. Keep investigating."
