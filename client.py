"""K8sGuard Environment Client."""

from typing import Dict

from openenv.core.client_types import StepResult
from openenv.core import EnvClient

from .models import K8sGuardAction, K8sGuardObservation, K8sGuardState


class K8sGuardEnv(
    EnvClient[K8sGuardAction, K8sGuardObservation, K8sGuardState]
):
    """
    Client for the K8sGuard Security Scanner Environment.

    Example:
        >>> with K8sGuardEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.command_output)
        ...     result = client.step(K8sGuardAction(command="kubectl get pods -A"))
        ...     print(result.observation.command_output)
    """

    def __init__(self, base_url: str, **kwargs):
        kwargs.setdefault("message_timeout_s", 300.0)
        super().__init__(base_url=base_url, **kwargs)

    def _step_payload(self, action: K8sGuardAction) -> Dict:
        return {"command": action.command}

    def _parse_result(self, payload: Dict) -> StepResult[K8sGuardObservation]:
        obs_data = payload.get("observation", {})
        observation = K8sGuardObservation(
            command_output=obs_data.get("command_output", ""),
            cluster_status_summary=obs_data.get("cluster_status_summary", ""),
            findings=obs_data.get("findings", []),
            steps_taken=obs_data.get("steps_taken", 0),
            max_steps=obs_data.get("max_steps", 25),
            hint=obs_data.get("hint", ""),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> K8sGuardState:
        return K8sGuardState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            scan_id=payload.get("scan_id", ""),
            difficulty=payload.get("difficulty", 0.3),
            scan_scope=payload.get("scan_scope", ""),
            is_complete=payload.get("is_complete", False),
            cumulative_reward=payload.get("cumulative_reward", 0.0),
            scan_category=payload.get("scan_category", "all"),
        )
