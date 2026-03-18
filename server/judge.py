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
_STOP_WORDS = {"a", "an", "the", "in", "is", "of", "to", "for", "on", "with", "not", "no", "and", "or", "has", "are", "was", "be"}


def _keyword_overlap(title: str, text: str) -> int:
    """Count significant keyword overlaps between vulnerability title and finding text."""
    title_words = {w for w in title.lower().split() if w not in _STOP_WORDS and len(w) > 2}
    text_words = {w for w in text.lower().split() if w not in _STOP_WORDS and len(w) > 2}
    # Also check for partial matches (e.g. "privileged" matches "privilege")
    count = 0
    for tw in title_words:
        if tw in text_words:
            count += 1
        elif any(tw[:4] in xw or xw[:4] in tw for xw in text_words if len(xw) > 3):
            count += 1
    return count


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
            return -0.2, "Command blocked — repeated too many times."
        if repeat_count == 1:
            return -0.1, "Repeated command — try a different approach."

        # Finding submission — small per-step reward; outcome score dominates
        if cmd_lower.startswith("finding:"):
            finding_text = command[8:].strip().lower()
            for vuln in scenario.injected_findings:
                exact = (vuln.title.lower() in finding_text
                         or vuln.category in finding_text
                         or vuln.resource_name.lower() in finding_text)
                keyword_hits = _keyword_overlap(vuln.title, finding_text)
                if exact or keyword_hits >= 2:
                    return 0.1, f"Correctly identified: {vuln.title}"
            return -0.1, "Finding submitted but doesn't match known vulnerabilities."

        # Remediation submission — small per-step reward
        if cmd_lower.startswith("remediate:"):
            remediation_text = command[10:].strip().lower()
            for vuln in scenario.injected_findings:
                resource = vuln.resource_name.lower()
                if resource in remediation_text:
                    return 0.1, f"Correct remediation target: {vuln.resource_kind}/{vuln.resource_name}"
            return -0.1, "Remediation doesn't target a known vulnerable resource."

        # Valid investigation commands — small reward, capped at first 5
        _SCAN_COMMANDS = (
            "get pods", "get po", "get secrets", "get roles", "get clusterroles",
            "get rolebindings", "get clusterrolebindings", "get networkpolicies",
            "get netpol", "get sa", "get serviceaccounts", "get configmaps", "get cm",
            "describe pod", "describe deployment", "describe role", "describe clusterrole",
            "describe sa", "describe secret", "describe netpol", "describe networkpolicy",
            "describe rolebinding", "describe clusterrolebinding",
            "auth can-i", "get events", "get services", "get svc",
            "get ingress", "get deployments", "get deploy",
            "describe service", "describe ingress",
        )
        if any(p in cmd_lower for p in _SCAN_COMMANDS):
            if repeat_count == 1:
                return -0.1, "Repeated investigation command — try a different approach."
            # Cap investigation rewards at first 5 unique commands
            investigation_count = sum(
                1 for h in history
                if not h["command"].startswith(("finding:", "remediate:"))
                and h.get("reward", 0) > 0
            )
            if investigation_count < 5:
                return 0.05, "Good investigation step."
            return 0.0, "Investigation step (reward capped)."

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
            if any(f.title.lower() in ff.lower() or f.resource_name in ff
                   or _keyword_overlap(f.title, ff) >= 2
                   for ff in found_findings)
        )

        # Must find all critical/high to pass
        if critical_high and critical_high_found < len(critical_high):
            return False, (f"Found {critical_high_found}/{len(critical_high)} critical/high findings. "
                          f"Total: {found_count}/{total}")

        # Good enough if found >= 70% overall
        if found_count >= total * 0.7:
            return True, f"Scan complete: {found_count}/{total} findings identified."

        return False, f"Incomplete scan: {found_count}/{total} findings. Keep investigating."

    def compute_outcome_reward(
        self,
        scenario: VulnerabilityScenario,
        found_findings: list[str],
        history: list,
        timed_out: bool,
    ) -> tuple[float, str]:
        """Compute episode outcome reward. Called once at episode end.

        This is the dominant reward signal — 10-20x larger than per-step rewards.
        """
        total = len(scenario.injected_findings)
        if total == 0:
            return 2.0, "No vulnerabilities in scenario."

        # Count matched findings (fuzzy)
        matched_ids = set()
        for ff in found_findings:
            ff_lower = ff.lower()
            for vuln in scenario.injected_findings:
                if vuln.finding_id in matched_ids:
                    continue
                exact = (vuln.title.lower() in ff_lower
                         or vuln.category in ff_lower
                         or vuln.resource_name.lower() in ff_lower)
                if exact or _keyword_overlap(vuln.title, ff_lower) >= 2:
                    matched_ids.add(vuln.finding_id)
                    break

        matched_count = len(matched_ids)
        match_ratio = matched_count / total

        # Count critical/high found
        critical_high = [f for f in scenario.injected_findings if f.severity in ("CRITICAL", "HIGH")]
        ch_found = sum(1 for f in critical_high if f.finding_id in matched_ids)
        all_ch_found = ch_found == len(critical_high) if critical_high else True

        # Count successful remediations
        remediation_count = sum(
            1 for h in history
            if h["command"].startswith("remediate:")
            and h.get("feedback", "").startswith("Correct remediation")
        )

        # Compute outcome score
        outcome = 0.0
        reason_parts = []

        if all_ch_found and match_ratio >= 0.7:
            outcome = 5.0
            reason_parts.append(f"full completion ({matched_count}/{total} findings)")
        elif match_ratio >= 0.5:
            outcome = 2.0
            reason_parts.append(f"partial completion ({matched_count}/{total} findings)")
        elif matched_count > 0:
            outcome = 0.5
            reason_parts.append(f"found {matched_count}/{total} findings")
        else:
            # Scale penalty by investigation quality for GRPO variance
            unique_investigation = len(set(
                h["command"] for h in history
                if not h["command"].startswith(("finding:", "remediate:"))
            ))
            # -3.0 for no investigation, -1.0 for thorough investigation (10+ unique commands)
            outcome = -3.0 + min(unique_investigation * 0.2, 2.0)
            reason_parts.append(f"no correct findings (investigation: {unique_investigation} unique commands)")

        # Remediation bonus: +2.0 each, max +4.0
        rem_bonus = min(remediation_count * 2.0, 4.0)
        if rem_bonus > 0:
            outcome += rem_bonus
            reason_parts.append(f"+{rem_bonus:.0f} remediation bonus ({remediation_count} fixes)")

        # Efficiency bonus (only if found something)
        steps = len(history)
        if matched_count > 0:
            if steps <= 10:
                outcome += 1.0
                reason_parts.append("+1.0 efficiency (≤10 steps)")
            elif steps <= 15:
                outcome += 0.5
                reason_parts.append("+0.5 efficiency (≤15 steps)")

        return outcome, "Outcome: " + ", ".join(reason_parts)
