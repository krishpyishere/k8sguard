"""
Evaluation Script -- K8sGuard Security Scanner Agent

Compares a base Qwen3-8B model against a trained LoRA checkpoint
on K8sGuard security scanning scenarios.

Usage:
  # Terminal 1: OpenEnv server
  python -m server.app --scan-mode training

  # Terminal 2: Evaluation
  python eval.py \
    --base-model Qwen/Qwen3-8B \
    --trained-model outputs/k8sguard-grpo-.../checkpoint-50 \
    --num-episodes 10

Dependencies:
  pip install vllm transformers
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from transformers import AutoTokenizer
from vllm import LLM, SamplingParams
from vllm.lora.request import LoRARequest

from k8sguard import K8sGuardEnv, K8sGuardAction

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s:%(lineno)d: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ============================================================
# System prompt (same as train.py)
# ============================================================

SYSTEM_PROMPT = """You are an expert Kubernetes security scanner.
You scan clusters for security vulnerabilities across five domains:
RBAC, secrets, network isolation, container runtime, and supply chain.

You can run kubectl commands to investigate. After finding a vulnerability, submit:
- finding: <severity> - <description of the vulnerability>
- remediate: kubectl <the fix command>

WORKFLOW:
1. kubectl get pods -A                              (find workloads)
2. kubectl get clusterroles                         (check RBAC)
3. kubectl get networkpolicies -A                   (check network isolation)
4. kubectl describe pod <pod> -n <ns>               (inspect security context, env vars)
5. Report findings and apply remediations.

SECURITY CHECKS:
  RBAC: wildcard roles (* verbs/resources), privilege escalation verbs, broad secrets access
  Secrets: secrets in env vars, hardcoded credentials, sensitive data in ConfigMaps
  Network: missing NetworkPolicies, no egress restrictions, NodePort/LoadBalancer exposure
  Runtime: privileged containers, hostPID/hostNetwork, hostPath mounts, root UID, dangerous capabilities
  Supply Chain: :latest tags, no digest pinning, missing resource limits

Be systematic: scan all domains, then report findings and remediate.
Be efficient: minimize unnecessary commands.
Output one command per line. No explanations, just commands."""


# ============================================================
# Args
# ============================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate base vs trained K8sGuard agent"
    )
    parser.add_argument(
        "--base-model", default="Qwen/Qwen3-8B",
        help="Base model name or path",
    )
    parser.add_argument(
        "--trained-model", default=None,
        help="Path to trained LoRA checkpoint directory",
    )
    parser.add_argument(
        "--env-url", default="http://localhost:8000",
        help="OpenEnv server URL",
    )
    parser.add_argument(
        "--num-episodes", type=int, default=10,
        help="Number of evaluation episodes per model",
    )
    parser.add_argument(
        "--max-turns", type=int, default=15,
        help="Max agent turns per episode",
    )
    parser.add_argument(
        "--max-new-tokens", type=int, default=512,
        help="Max tokens per agent generation",
    )
    parser.add_argument(
        "--temperature", type=float, default=0.3,
        help="Sampling temperature (lower = more deterministic for eval)",
    )
    parser.add_argument(
        "--output", default="eval_results.json",
        help="Path to save evaluation results JSON",
    )
    parser.add_argument(
        "--gpu-memory-utilization", type=float, default=0.85,
        help="vLLM GPU memory utilization fraction",
    )
    parser.add_argument(
        "--tensor-parallel-size", type=int, default=1,
        help="Number of GPUs for tensor parallelism",
    )
    return parser.parse_args()


# ============================================================
# Helpers (reused from train.py)
# ============================================================

def format_observation(obs) -> str:
    """Format observation into agent-readable text."""
    command_output = getattr(obs, "command_output", "") or ""
    cluster_status = getattr(obs, "cluster_status_summary", "") or ""
    hint = getattr(obs, "hint", "") or ""
    steps = getattr(obs, "steps_taken", 0)
    max_steps = getattr(obs, "max_steps", 25)

    text = f"""{command_output}

CURRENT CLUSTER STATUS:
{cluster_status}"""

    if hint:
        text += f"\n\nHINT: {hint}"

    text += f"\n\nStep {steps}/{max_steps}. Scan this cluster for security vulnerabilities."
    return text


def parse_commands(text: str) -> list[str]:
    """Extract kubectl/finding/remediate commands from agent response."""
    commands = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line.startswith(("kubectl ", "finding:", "remediate:")):
            commands.append(line)
        elif line.startswith(("- kubectl", "* kubectl", "> kubectl")):
            commands.append(line.lstrip("-*> "))
    return commands


# ============================================================
# Episode result tracking
# ============================================================

@dataclass
class EpisodeResult:
    """Result of a single evaluation episode."""
    episode_id: int
    total_reward: float = 0.0
    finding_reward: float = 0.0
    remediation_reward: float = 0.0
    num_steps: int = 0
    num_findings: int = 0
    num_remediations: int = 0
    resolved: bool = False
    duration_s: float = 0.0


@dataclass
class ModelResults:
    """Aggregated results for one model."""
    model_name: str
    episodes: list[EpisodeResult] = field(default_factory=list)

    @property
    def avg_reward(self) -> float:
        if not self.episodes:
            return 0.0
        return statistics.mean(e.total_reward for e in self.episodes)

    @property
    def avg_finding_reward(self) -> float:
        if not self.episodes:
            return 0.0
        return statistics.mean(e.finding_reward for e in self.episodes)

    @property
    def avg_remediation_reward(self) -> float:
        if not self.episodes:
            return 0.0
        return statistics.mean(e.remediation_reward for e in self.episodes)

    @property
    def episodes_resolved(self) -> int:
        return sum(1 for e in self.episodes if e.resolved)

    @property
    def avg_steps(self) -> float:
        if not self.episodes:
            return 0.0
        return statistics.mean(e.num_steps for e in self.episodes)

    @property
    def avg_duration(self) -> float:
        if not self.episodes:
            return 0.0
        return statistics.mean(e.duration_s for e in self.episodes)

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "num_episodes": len(self.episodes),
            "avg_reward": round(self.avg_reward, 4),
            "avg_finding_reward": round(self.avg_finding_reward, 4),
            "avg_remediation_reward": round(self.avg_remediation_reward, 4),
            "episodes_resolved": self.episodes_resolved,
            "avg_steps": round(self.avg_steps, 2),
            "avg_duration_s": round(self.avg_duration, 2),
            "episodes": [asdict(e) for e in self.episodes],
        }


# ============================================================
# Generation helper
# ============================================================

def generate_response(
    llm: LLM,
    tokenizer: AutoTokenizer,
    sampling_params: SamplingParams,
    observation,
    lora_request: LoRARequest | None = None,
) -> str:
    """Build prompt from observation and generate a response."""
    user_prompt = format_observation(observation)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    try:
        prompt_text = tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=False,
            enable_thinking=False,
        )
    except TypeError:
        prompt_text = tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=False,
        )

    outputs = llm.generate(
        [prompt_text],
        sampling_params=sampling_params,
        lora_request=lora_request,
    )
    return outputs[0].outputs[0].text


# ============================================================
# Rollout -- one evaluation episode
# ============================================================

def eval_episode(
    llm: LLM,
    tokenizer: AutoTokenizer,
    sampling_params: SamplingParams,
    env: K8sGuardEnv,
    episode_id: int,
    max_turns: int,
    lora_request: LoRARequest | None = None,
) -> EpisodeResult:
    """Run one full security scanning episode and collect metrics."""
    t0 = time.time()

    result = env.reset()
    observation = result.observation

    step_rewards: list[float] = []
    finding_rewards: list[float] = []
    remediation_rewards: list[float] = []
    num_findings = 0
    num_remediations = 0
    resolved = False

    for _turn in range(max_turns):
        if result.done:
            resolved = True
            break

        # Generate agent response
        completion_text = generate_response(
            llm, tokenizer, sampling_params, observation, lora_request
        )

        # Parse and execute commands
        commands = parse_commands(completion_text)
        if not commands:
            step_rewards.append(-0.5)
            continue

        for cmd in commands:
            try:
                result = env.step(K8sGuardAction(command=cmd))
                reward = float(result.reward or 0.0)
                step_rewards.append(reward)
                observation = result.observation

                if cmd.startswith("finding:"):
                    finding_rewards.append(reward)
                    num_findings += 1
                elif cmd.startswith("remediate:"):
                    remediation_rewards.append(reward)
                    num_remediations += 1

                if result.done:
                    resolved = True
                    break
            except Exception as e:
                logger.warning(f"Episode {episode_id}, step error: {e}")
                step_rewards.append(-0.1)
                break

    duration = time.time() - t0

    return EpisodeResult(
        episode_id=episode_id,
        total_reward=sum(step_rewards) if step_rewards else -1.0,
        finding_reward=finding_rewards[-1] if finding_rewards else 0.0,
        remediation_reward=remediation_rewards[-1] if remediation_rewards else 0.0,
        num_steps=len(step_rewards),
        num_findings=num_findings,
        num_remediations=num_remediations,
        resolved=resolved,
        duration_s=round(duration, 2),
    )


# ============================================================
# Evaluation loop for one model variant
# ============================================================

def evaluate_model(
    llm: LLM,
    tokenizer: AutoTokenizer,
    sampling_params: SamplingParams,
    env: K8sGuardEnv,
    model_name: str,
    num_episodes: int,
    max_turns: int,
    lora_request: LoRARequest | None = None,
) -> ModelResults:
    """Run N episodes and aggregate results."""
    results = ModelResults(model_name=model_name)

    logger.info(f"Evaluating '{model_name}' for {num_episodes} episodes...")

    for i in range(num_episodes):
        logger.info(f"  Episode {i + 1}/{num_episodes}")
        ep_result = eval_episode(
            llm=llm,
            tokenizer=tokenizer,
            sampling_params=sampling_params,
            env=env,
            episode_id=i,
            max_turns=max_turns,
            lora_request=lora_request,
        )
        results.episodes.append(ep_result)
        logger.info(
            f"    reward={ep_result.total_reward:.2f}  "
            f"findings={ep_result.num_findings}  "
            f"remediations={ep_result.num_remediations}  "
            f"resolved={ep_result.resolved}  "
            f"time={ep_result.duration_s:.1f}s"
        )

    return results


# ============================================================
# Print comparison table
# ============================================================

def print_comparison(base: ModelResults, trained: ModelResults | None) -> None:
    """Print a side-by-side comparison table."""
    sep = "=" * 72
    header = f"{'Metric':<30} {'Base':>18}"
    if trained:
        header += f" {'Trained':>18}"
    print()
    print(sep)
    print("K8sGuard Evaluation Results")
    print(sep)
    print(header)
    print("-" * 72)

    rows = [
        ("Avg Total Reward", f"{base.avg_reward:.4f}",
         f"{trained.avg_reward:.4f}" if trained else None),
        ("Avg Finding Reward", f"{base.avg_finding_reward:.4f}",
         f"{trained.avg_finding_reward:.4f}" if trained else None),
        ("Avg Remediation Reward", f"{base.avg_remediation_reward:.4f}",
         f"{trained.avg_remediation_reward:.4f}" if trained else None),
        ("Episodes Resolved", f"{base.episodes_resolved}/{len(base.episodes)}",
         f"{trained.episodes_resolved}/{len(trained.episodes)}" if trained else None),
        ("Avg Steps", f"{base.avg_steps:.1f}",
         f"{trained.avg_steps:.1f}" if trained else None),
        ("Avg Duration (s)", f"{base.avg_duration:.1f}",
         f"{trained.avg_duration:.1f}" if trained else None),
    ]

    for label, base_val, trained_val in rows:
        line = f"{label:<30} {base_val:>18}"
        if trained_val is not None:
            line += f" {trained_val:>18}"
        print(line)

    # Improvement summary
    if trained:
        print("-" * 72)
        reward_delta = trained.avg_reward - base.avg_reward
        sign = "+" if reward_delta >= 0 else ""
        print(f"{'Reward Delta (trained-base)':<30} {sign + f'{reward_delta:.4f}':>38}")

        if base.avg_reward != 0:
            pct = (reward_delta / abs(base.avg_reward)) * 100
            sign_pct = "+" if pct >= 0 else ""
            print(f"{'Reward Improvement %':<30} {sign_pct + f'{pct:.1f}%':>38}")

    print(sep)
    print()


# ============================================================
# Main
# ============================================================

def main() -> None:
    args = parse_args()

    logger.info("=" * 60)
    logger.info("K8sGuard -- Evaluation: Base vs Trained")
    logger.info("=" * 60)
    logger.info(f"Base model:      {args.base_model}")
    logger.info(f"Trained model:   {args.trained_model or '(none -- base only)'}")
    logger.info(f"Env URL:         {args.env_url}")
    logger.info(f"Episodes/model:  {args.num_episodes}")
    logger.info(f"Max turns:       {args.max_turns}")
    logger.info(f"Temperature:     {args.temperature}")

    # ---- Tokenizer ----
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    tokenizer.pad_token = tokenizer.eos_token

    # ---- Sampling params ----
    sampling_params = SamplingParams(
        temperature=args.temperature,
        max_tokens=args.max_new_tokens,
        stop=["<|endoftext|>", "<|im_end|>"],
    )

    # ---- Load vLLM engine ----
    # Enable LoRA if a trained checkpoint is provided
    enable_lora = args.trained_model is not None
    logger.info(f"Loading vLLM engine (enable_lora={enable_lora})...")

    llm = LLM(
        model=args.base_model,
        enable_lora=enable_lora,
        max_lora_rank=64 if enable_lora else None,
        gpu_memory_utilization=args.gpu_memory_utilization,
        tensor_parallel_size=args.tensor_parallel_size,
        trust_remote_code=True,
    )
    logger.info("vLLM engine loaded.")

    # ---- Connect to environment ----
    env = K8sGuardEnv(base_url=args.env_url)

    try:
        # ---- Evaluate base model ----
        logger.info("")
        logger.info("-" * 40)
        logger.info("Phase 1: Evaluating BASE model")
        logger.info("-" * 40)

        base_results = evaluate_model(
            llm=llm,
            tokenizer=tokenizer,
            sampling_params=sampling_params,
            env=env,
            model_name=f"base ({args.base_model})",
            num_episodes=args.num_episodes,
            max_turns=args.max_turns,
            lora_request=None,
        )

        # ---- Evaluate trained model (if provided) ----
        trained_results = None
        if args.trained_model:
            logger.info("")
            logger.info("-" * 40)
            logger.info("Phase 2: Evaluating TRAINED model (LoRA)")
            logger.info("-" * 40)

            lora_path = str(Path(args.trained_model).resolve())
            lora_request = LoRARequest(
                lora_name="k8sguard-trained",
                lora_int_id=1,
                lora_path=lora_path,
            )

            trained_results = evaluate_model(
                llm=llm,
                tokenizer=tokenizer,
                sampling_params=sampling_params,
                env=env,
                model_name=f"trained ({args.trained_model})",
                num_episodes=args.num_episodes,
                max_turns=args.max_turns,
                lora_request=lora_request,
            )

        # ---- Print comparison ----
        print_comparison(base_results, trained_results)

        # ---- Save results ----
        output_data = {
            "config": {
                "base_model": args.base_model,
                "trained_model": args.trained_model,
                "env_url": args.env_url,
                "num_episodes": args.num_episodes,
                "max_turns": args.max_turns,
                "temperature": args.temperature,
                "max_new_tokens": args.max_new_tokens,
            },
            "base": base_results.to_dict(),
        }
        if trained_results:
            output_data["trained"] = trained_results.to_dict()
            output_data["comparison"] = {
                "reward_delta": round(
                    trained_results.avg_reward - base_results.avg_reward, 4
                ),
                "finding_reward_delta": round(
                    trained_results.avg_finding_reward - base_results.avg_finding_reward, 4
                ),
                "remediation_reward_delta": round(
                    trained_results.avg_remediation_reward - base_results.avg_remediation_reward, 4
                ),
                "resolved_delta": (
                    trained_results.episodes_resolved - base_results.episodes_resolved
                ),
            }

        output_path = Path(args.output)
        output_path.write_text(json.dumps(output_data, indent=2))
        logger.info(f"Results saved to {output_path.resolve()}")

    finally:
        env.close()
        logger.info("Environment connection closed.")

    logger.info("Evaluation complete.")


if __name__ == "__main__":
    main()
