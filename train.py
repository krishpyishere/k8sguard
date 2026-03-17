"""
GRPO Training Script — K8sGuard Security Scanner Agent

Follows the standard OpenEnv + TRL pattern.

Everything runs on the H100:
  1. vLLM serves the judge model (Qwen3-14B) on port 8001
  2. OpenEnv server runs locally on port 8000 (K8sGuard env + judge)
  3. This script trains the agent (Qwen3-8B) via GRPO with TRL's built-in vLLM

Setup (3 terminals on H100):

  # Terminal 1: Judge model
  trl vllm-serve --model Qwen/Qwen3-14B --host 0.0.0.0 --port 8001

  # Terminal 2: OpenEnv server (env + k8s backend + judge client)
  LLM_BACKEND=openai LLM_BASE_URL=http://localhost:8001/v1 \
    python -m server.app --scan-mode training

  # Terminal 3: GRPO training
  python train.py --vllm-mode colocate

Dependencies:
  pip install -e ".[train]"
"""

from __future__ import annotations

import argparse
import logging
from datetime import datetime
from pathlib import Path

from datasets import Dataset
from peft import LoraConfig
from transformers import AutoTokenizer

from trl import GRPOConfig, GRPOTrainer
from trl.experimental.openenv import generate_rollout_completions

from k8sguard import K8sGuardEnv, K8sGuardAction

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s:%(lineno)d: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)


# ---- TRL 0.29.0 / vLLM 0.11.x compatibility ----
# TRL 0.29.0 expects vLLM logprobs as list-of-lists (top-k per token),
# but vLLM 0.11.x returns plain floats. Patch until TRL releases a fix.

_orig_vllm_gen = None

def _patch_vllm_generate(trainer):
    """Wrap vLLM generate to ensure logprobs are in top-k list format."""
    global _orig_vllm_gen
    if _orig_vllm_gen is not None or not hasattr(trainer, 'vllm_generation'):
        return
    _orig_vllm_gen = trainer.vllm_generation.generate

    def _wrapped_generate(**kwargs):
        result = _orig_vllm_gen(**kwargs)
        prompt_ids, completion_ids, logprobs, *rest = result
        if logprobs and logprobs[0] and isinstance(logprobs[0][0], float):
            logprobs = [[[lp] for lp in seq] for seq in logprobs]
        return (prompt_ids, completion_ids, logprobs, *rest)

    trainer.vllm_generation.generate = _wrapped_generate

def patch_trl_vllm_compat():
    """Apply TRL/vLLM compatibility patches. Call before trainer.train()."""
    _orig_train = GRPOTrainer.train

    def _patched_train(self, *args, **kwargs):
        _patch_vllm_generate(self)
        return _orig_train(self, *args, **kwargs)

    GRPOTrainer.train = _patched_train

patch_trl_vllm_compat()


# ============================================================
# System prompt
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
After finding a vulnerability, always attempt a remediation before moving to the next one.
Output one command per line. No explanations, just commands."""


# ============================================================
# Args
# ============================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GRPO training for K8sGuard security scanner agent")
    parser.add_argument("--model-id", default="Qwen/Qwen3-8B", help="Agent model to fine-tune")
    parser.add_argument("--env-url", default="http://localhost:8000", help="OpenEnv server URL")
    parser.add_argument("--dataset-size", type=int, default=50, help="Number of training episodes")
    parser.add_argument("--max-turns", type=int, default=25, help="Max commands per episode")
    parser.add_argument("--max-new-tokens", type=int, default=512, help="Max tokens per agent response")
    parser.add_argument("--num-generations", type=int, default=4, help="G for GRPO")
    parser.add_argument("--learning-rate", type=float, default=5e-6)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=4)
    parser.add_argument("--num-epochs", type=int, default=1)
    parser.add_argument("--save-steps", type=int, default=10)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--max-steps", type=int, default=200, help="Max GRPO training steps")
    parser.add_argument("--push-to-hub", action="store_true", help="Push model to HF Hub after training")
    parser.add_argument("--hub-repo", default=None, help="HF Hub repo, e.g. your-name/k8sguard-agent")
    parser.add_argument(
        "--vllm-mode", choices=("colocate", "server"), default="colocate",
        help="vLLM mode: colocate (1 GPU) or server (separate vLLM process)",
    )
    parser.add_argument("--vllm-server-url", default="http://localhost:8000", help="vLLM server URL (server mode)")
    parser.add_argument("--vllm-server-timeout", type=float, default=60.0, help="Seconds to wait for vLLM server")
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--logging-steps", type=int, default=1)
    return parser.parse_args()


# ============================================================
# Helpers
# ============================================================

def sanitize_name(name: str) -> str:
    return name.replace("/", "-")


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
# Rollout — one full security scanning episode
# ============================================================

def rollout_once(
    trainer: GRPOTrainer,
    env: K8sGuardEnv,
    tokenizer: AutoTokenizer,
    system_prompt: str,
    max_turns: int,
) -> dict[str, list]:
    """
    Run one full K8s security scanning episode.
    Agent generates commands, environment executes them on real cluster,
    judge scores each action.
    """
    result = env.reset()
    observation = result.observation

    prompt_ids: list[int] = []
    completion_ids: list[int] = []
    logprobs: list[float] = []
    step_rewards: list[float] = []
    finding_rewards: list[float] = []
    remediation_rewards: list[float] = []

    for _turn in range(max_turns):
        if result.done:
            break

        # Build prompt from current observation
        user_prompt = format_observation(observation)
        messages = [
            {"role": "system", "content": system_prompt},
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

        # Generate with vLLM via TRL
        rollout_outputs = generate_rollout_completions(trainer, [prompt_text])[0]
        prompt_ids.extend(rollout_outputs["prompt_ids"])
        completion_ids.extend(rollout_outputs["completion_ids"])
        logprobs.extend(rollout_outputs["logprobs"])

        completion_text = rollout_outputs.get("text") or tokenizer.decode(
            rollout_outputs["completion_ids"], skip_special_tokens=True
        )

        # Parse and execute commands on real cluster
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

                # Track specific reward types
                if cmd.startswith("finding:"):
                    finding_rewards.append(reward)
                elif cmd.startswith("remediate:"):
                    remediation_rewards.append(reward)

                if result.done:
                    break
            except Exception as e:
                logger.warning(f"Step error: {e}")
                step_rewards.append(-0.1)
                break

    # Aggregate rewards
    total_reward = sum(step_rewards) if step_rewards else -1.0
    finding_score = finding_rewards[-1] if finding_rewards else 0.0
    remediation_score = remediation_rewards[-1] if remediation_rewards else 0.0

    return {
        "prompt_ids": prompt_ids,
        "completion_ids": completion_ids,
        "logprobs": logprobs,
        "total_reward": total_reward,
        "finding_reward": finding_score,
        "remediation_reward": remediation_score,
    }


# ============================================================
# Reward functions (TRL convention)
# ============================================================

def reward_total(completions: list[str], **kwargs) -> list[float]:
    rewards = kwargs.get("total_reward") if kwargs else None
    return [float(r) for r in rewards] if rewards else [0.0 for _ in completions]


def reward_finding(completions: list[str], **kwargs) -> list[float]:
    rewards = kwargs.get("finding_reward") if kwargs else None
    return [float(r) for r in rewards] if rewards else [0.0 for _ in completions]


def reward_remediation(completions: list[str], **kwargs) -> list[float]:
    rewards = kwargs.get("remediation_reward") if kwargs else None
    return [float(r) for r in rewards] if rewards else [0.0 for _ in completions]


# ============================================================
# Main
# ============================================================

def main() -> None:
    args = parse_args()

    logger.info("=" * 60)
    logger.info("K8sGuard — GRPO Training (OpenEnv + TRL)")
    logger.info("=" * 60)
    logger.info(f"Agent model:    {args.model_id}")
    logger.info(f"Env URL:        {args.env_url}")
    logger.info(f"Episodes:       {args.dataset_size}")
    logger.info(f"Generations/G:  {args.num_generations}")
    logger.info(f"vLLM mode:      {args.vllm_mode}")

    # ---- Tokenizer ----
    tokenizer = AutoTokenizer.from_pretrained(args.model_id)
    tokenizer.pad_token = tokenizer.eos_token

    # ---- Connect to OpenEnv server ----
    env = K8sGuardEnv(base_url=args.env_url)

    # ---- Dataset (each entry triggers one episode) ----
    dataset_prompt = "Scan this Kubernetes cluster for security vulnerabilities."
    dataset = Dataset.from_dict({"prompt": [dataset_prompt] * args.dataset_size})

    # ---- GRPO Config (matches wordle.py pattern) ----
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    default_output_dir = Path("outputs") / f"k8sguard-grpo-{sanitize_name(args.model_id)}-{timestamp}"
    output_dir = Path(args.output_dir or default_output_dir)

    grpo_config = GRPOConfig(
        use_vllm=True,
        vllm_mode=args.vllm_mode,
        vllm_server_base_url=args.vllm_server_url if args.vllm_mode == "server" else None,
        vllm_server_timeout=args.vllm_server_timeout,
        output_dir=str(output_dir),
        max_steps=args.max_steps,
        num_train_epochs=args.num_epochs,
        learning_rate=args.learning_rate,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        per_device_train_batch_size=1,
        num_generations=args.num_generations,
        max_completion_length=args.max_new_tokens,
        logging_steps=args.logging_steps,
        save_strategy="steps",
        save_steps=args.save_steps,
        temperature=args.temperature,
        report_to="none",
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        push_to_hub=args.push_to_hub,
    )

    # ---- LoRA config (fits 8B model on single GPU) ----
    peft_config = LoraConfig(
        r=64,
        lora_alpha=128,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )

    # ---- Rollout function (called by GRPOTrainer each step) ----
    def rollout_func(prompts: list[str], trainer: GRPOTrainer) -> dict[str, list]:
        episode_prompt_ids: list[list[int]] = []
        episode_completion_ids: list[list[int]] = []
        episode_logprobs: list[list[float]] = []
        total_rewards: list[float] = []
        finding_rewards: list[float] = []
        remediation_rewards: list[float] = []

        for prompt_text in prompts:
            episode = rollout_once(
                trainer=trainer,
                env=env,
                tokenizer=tokenizer,
                system_prompt=SYSTEM_PROMPT,
                max_turns=args.max_turns,
            )
            episode_prompt_ids.append(episode["prompt_ids"])
            episode_completion_ids.append(episode["completion_ids"])
            episode_logprobs.append(episode["logprobs"])
            total_rewards.append(episode["total_reward"])
            finding_rewards.append(episode["finding_reward"])
            remediation_rewards.append(episode["remediation_reward"])

        return {
            "prompt_ids": episode_prompt_ids,
            "completion_ids": episode_completion_ids,
            "logprobs": episode_logprobs,
            "total_reward": total_rewards,
            "finding_reward": finding_rewards,
            "remediation_reward": remediation_rewards,
        }

    # ---- Trainer ----
    trainer = GRPOTrainer(
        model=args.model_id,
        processing_class=tokenizer,
        reward_funcs=[
            reward_total,
            reward_finding,
            reward_remediation,
        ],
        train_dataset=dataset,
        args=grpo_config,
        rollout_func=rollout_func,
        peft_config=peft_config,
    )

    # ---- Train ----
    logger.info("Starting GRPO training...")
    logger.info(f"Using {args.num_generations} rollouts per episode")

    try:
        trainer.train()
    finally:
        env.close()

    # ---- Save ----
    trainer.save_model(str(output_dir))
    logger.info(f"Model saved to {output_dir}")

    if args.push_to_hub and args.hub_repo:
        trainer.push_to_hub()
        logger.info(f"Model pushed to https://huggingface.co/{args.hub_repo}")

    logger.info("Done!")


if __name__ == "__main__":
    main()
