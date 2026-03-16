# K8sGuard Training Log — 8xH100

Live training run on Lambda Cloud 8xH100 80GB instance.

## Hardware

- 8x NVIDIA H100 80GB HBM3
- 22TB NVMe storage
- Ubuntu 22.04, Python 3.10, k3s v1.34.5

## GPU Layout

| GPU | Role | Model | Memory |
|-----|------|-------|--------|
| 0 | GRPO training (LoRA) | Qwen3-8B | ~69 GB |
| 1-5 | Available for DDP scaling | — | — |
| 6-7 | Judge vLLM (TP=2) | Nemotron-120B NVFP4 | ~80 GB each |

## Runtime Bugs Found and Fixed

### 1. TRL 0.29 / vLLM 0.11 logprobs format mismatch

TRL 0.29 expects logprobs as `list[list[float]]` (top-k per token), but vLLM 0.11 returns `list[float]`. The trainer crashes with `TypeError: 'float' object is not subscriptable` at `grpo_trainer.py:1237`.

**Fix:** Monkey-patch `vllm_generation.generate` to wrap plain floats in lists:
```python
if logprobs and logprobs[0] and isinstance(logprobs[0][0], float):
    logprobs = [[[lp] for lp in seq] for seq in logprobs]
```

### 2. GRPOConfig rejects `max_prompt_length`

TRL 0.29's `GRPOConfig` does not accept `max_prompt_length` (the parameter was removed or renamed). Passing it raises `TypeError`.

**Fix:** Remove `max_prompt_length` from GRPOConfig.

### 3. kubernetes v35 renamed `V1Subject` to `RbacV1Subject`

The `kubernetes` Python client v35.0.0 renamed `client.V1Subject` to `client.RbacV1Subject`. The vulnerability injector's `_inject_wildcard_rbac` method crashed with `AttributeError: module 'kubernetes.client' has no attribute 'V1Subject'`.

**Fix:** Replace `client.V1Subject(...)` with `client.RbacV1Subject(...)` in `vulnerability_injectors.py`.

### 4. `trl vllm-serve` doesn't expose OpenAI-compatible API

`trl vllm-serve` serves a TRL-internal API for the trainer's rollout generation — it does NOT expose `/v1/chat/completions`. The judge's `LLMClient` needs a standard OpenAI-compatible endpoint.

**Fix:** Run the judge as `python -m vllm.entrypoints.openai.api_server` instead of `trl vllm-serve`.

### 5. Nemotron-120B FP8 model dimension constraints

The model has hidden dimensions (9984, 9728) that are only divisible by powers of 2. TP=2, TP=4, TP=8 are valid; TP=3, TP=5, TP=6, TP=7 all fail with `AssertionError: <dim> is not divisible by <tp>`.

FP8 variant OOMs on TP=2 (2x80GB) and TP=4 (4x80GB) because the BF16 intermediate activations exceed available memory. NVFP4 variant fits on TP=2.

### 6. Qwen3 `enable_thinking=False` kwarg

`tokenizer.apply_chat_template(enable_thinking=False)` is Qwen-specific. Other models raise `TypeError`.

**Fix:** Wrap in try/except with fallback to standard `apply_chat_template`.

## First Training Run Observations

- Step 1/200 completed in ~102 seconds (4 rollout episodes per step, 25 env steps each)
- Untrained model repeats the same commands (gets blocked after 3 repeats, -0.5 penalty)
- Heuristic judge handles ~80% of actions without LLM calls
- Judge LLM fallback requires OpenAI-compatible `/v1/chat/completions` endpoint
- Environment correctly injects vulnerabilities and resets between episodes
