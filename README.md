# K8sGuard

<p align="center">
  <img src="deragon.jpg" alt="K8sGuard" width="600">
</p>

### **Train LLMs to find and fix Kubernetes security vulnerabilities.**

> **K8sGuard is an RL training platform that teaches language models to become defensive security agents.** It combines an [OpenEnv](https://github.com/meta-pytorch/OpenEnv) gym (live K8s cluster with injected vulnerabilities), a security judge (heuristic + LLM reward signal), and a GRPO training pipeline (TRL + vLLM + LoRA) to produce models that can autonomously scan and remediate real clusters.

## How Training Works

```
                          ┌─────────────────────────────────────────────┐
                          │            GRPO Training Loop               │
                          │              (train.py)                     │
                          └────────────────────┬────────────────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
        ┌───────────────────┐    ┌──────────────────────┐    ┌────────────────────┐
        │   Agent LLM       │    │   K8sGuard Env       │    │   Security Judge   │
        │  (Qwen3-8B+LoRA)  │    │   (OpenEnv server)   │    │  (heuristic+LLM)   │
        │                   │    │                      │    │                    │
        │  vLLM generation  │    │  Scenario injection  │    │  Score actions:    │
        │  kubectl commands │    │  Command execution   │    │  +0.5 to +1.0 ✓   │
        │  finding: reports │    │  State tracking      │    │  -0.5 to -1.0 ✗   │
        │  remediate: fixes │    │  Episode management  │    │  Feedback hints    │
        └────────┬──────────┘    └──────────┬───────────┘    └─────────┬──────────┘
                 │                          │                          │
                 │    ┌─────────────────────┼──────────────────────┐   │
                 │    │                     ▼                      │   │
                 │    │    ┌────────────────────────────────┐      │   │
                 │    │    │       Live K8s Cluster         │      │   │
                 │    │    │      (k3s / EKS / GKE)        │      │   │
                 │    │    │                                │      │   │
                 │    │    │  ┌──────────┐  ┌───────────┐  │      │   │
                 │    │    │  │Injected  │  │ Real K8s   │  │      │   │
                 │    │    │  │  Vulns   │  │   API      │  │      │   │
                 │    │    │  └──────────┘  └───────────┘  │      │   │
                 │    │    └────────────────────────────────┘      │   │
                 │    └───────────────────────────────────────────-┘   │
                 │                                                     │
                 └──────────────────────┬──────────────────────────────┘
                                        │
                                        ▼
                          ┌─────────────────────────────┐
                          │     GRPO Policy Update      │
                          │                             │
                          │  Reward → Advantage → LoRA  │
                          │  weight update (BF16)       │
                          │                             │
                          │  Checkpoints → outputs/     │
                          └─────────────────────────────┘
```

**Each training episode:**

1. **Reset** — environment injects vulnerabilities (privileged pods, wildcard RBAC, exposed secrets, ...) into an isolated namespace
2. **Rollout** — agent generates kubectl commands, inspects resources, reports findings, proposes remediations
3. **Score** — SecurityJudge evaluates each action (see [reward signal](#reward-signal) below)
4. **Update** — GRPO computes advantages across multiple rollouts and updates LoRA weights

The agent learns to scan systematically across five security domains, identify real misconfigurations, and apply correct fixes — all on a live cluster.

## Training Quickstart

### Prerequisites

- Python 3.10+, GPU with 24GB+ VRAM (A100/H100 recommended)
- Access to a Kubernetes cluster (k3s, kind, EKS, GKE)
- `kubectl` configured with a valid kubeconfig

### Install

```bash
git clone https://github.com/krishpyishere/k8sguard.git
cd k8sguard
pip install -e ".[train]"
```

### Full setup (k3s from scratch)

```bash
bash deploy/setup.sh    # Installs k3s, kubectl, Python deps, creates training namespace
```

### Train an agent (3 terminals)

```bash
# Terminal 1: Judge model (scores agent actions)
trl vllm-serve --model Qwen/Qwen3-14B --host 0.0.0.0 --port 8001

# Terminal 2: K8sGuard environment (injects vulns, executes commands)
LLM_BACKEND=openai LLM_BASE_URL=http://localhost:8001/v1 \
  python -m server.app --scan-mode training

# Terminal 3: GRPO training (fine-tunes the agent)
python train.py \
  --model-id Qwen/Qwen3-8B \
  --vllm-mode colocate \
  --max-steps 200 \
  --dataset-size 50
```

The trainer runs GRPO episodes: the agent scans the cluster, the judge scores each action, and LoRA weights are updated. Checkpoints are saved to `outputs/`.

## Using a Trained Agent

Once training completes, the model can scan real clusters:

```bash
# Start the environment in scan mode (no injection, no training scaffolding)
python -m server.app --scan-mode scan
```

```python
from k8sguard import K8sGuardEnv, K8sGuardAction

with K8sGuardEnv(base_url="http://localhost:8000") as env:
    result = env.reset()
    print(result.observation.command_output)

    # Investigate
    result = env.step(K8sGuardAction(command="kubectl get pods -A"))
    print(result.observation.command_output)

    # Report a finding
    result = env.step(K8sGuardAction(command="finding: CRITICAL - Wildcard ClusterRole grants full cluster access"))
    print(result.reward, result.observation.hint)

    # Remediate
    result = env.step(K8sGuardAction(command="remediate: kubectl delete clusterrole overpermissive-role"))
    print(result.observation.command_output)
```

## Security Curriculum

The agent learns to detect vulnerabilities across five domains:

### RBAC & Identity
- Wildcard ClusterRoles/Roles (`*` verbs or resources)
- Privilege escalation verbs (`escalate`, `bind`, `impersonate`)
- Broad secrets access via ClusterRoles
- Default service account token auto-mounting

### Secrets & Sensitive Data
- Secrets exposed as environment variables (visible in `kubectl describe`)
- Hardcoded credentials in pod env vars
- Sensitive data stored in ConfigMaps instead of Secrets

### Network Isolation
- Namespaces with no NetworkPolicy (unrestricted lateral movement)
- Missing egress policies (unrestricted outbound traffic)
- Services exposed via NodePort/LoadBalancer

### Container Runtime
- Privileged containers (`privileged: true`)
- Host PID/Network namespace sharing
- HostPath volume mounts (container escape vector)
- Containers running as root (UID 0)
- Writable root filesystems
- Dangerous Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `ALL`)
- Missing security contexts

### Supply Chain
- Unpinned images (`:latest` or no tag)
- Images not pinned by digest
- Missing resource limits (DoS risk)

## Training Scenarios

Vulnerabilities are injected into an isolated namespace (`k8sguard-training`) with tiered difficulty:

| Tier | Difficulty | Example |
|------|-----------|---------|
| 1 | 0.1 - 0.3 | Single privileged container, root UID pod, `:latest` image |
| 2 | 0.3 - 0.5 | Wildcard RBAC, secrets in env vars, missing network policies, dangerous capabilities |
| 3 | 0.5 - 0.7 | Multiple vulns: privileged pod + exposed service + no network policy |
| 4 | 0.7+ | Full spectrum: hostPath mounts + wildcard RBAC + secrets exposure + host namespaces |

### Reward Signal

The SecurityJudge uses a fast heuristic path for common patterns and falls back to an LLM judge for nuanced evaluation:

| Score | Meaning |
|-------|---------|
| +0.5 to +1.0 | Correctly identifies a real vulnerability |
| +0.1 to +0.4 | Useful investigation step |
| 0.0 | Neutral (valid but doesn't advance the scan) |
| -0.1 to -0.3 | Wasted step or repeated command |
| -0.5 to -1.0 | Wrong remediation that could break the cluster |

## Architecture

```
K8sGuard/
├── train.py                          # GRPO training (TRL + vLLM + LoRA)
├── __init__.py                       # Package exports
├── client.py                         # OpenEnv WebSocket client
├── models.py                         # K8sGuardAction, Observation, SecurityFinding, VulnerabilityScenario
├── pyproject.toml                    # Package config & dependencies
├── Dockerfile                        # Container build
├── deploy/
│   ├── setup.sh                      # k3s + Python env setup
│   └── start.sh                      # Server launcher
└── server/
    ├── app.py                        # FastAPI server (OpenEnv endpoints + /healthz)
    ├── constants.py                  # Severity levels, scan categories, system namespaces
    ├── k8s_backend.py                # K8s auth (kubeconfig/in-cluster/token) + command dispatch
    ├── k8s_commands.py               # kubectl command handler (get/describe/logs/auth can-i/...)
    ├── llm_client.py                 # LLM client (OpenAI-compatible, Anthropic, HuggingFace)
    ├── scanners.py                   # Programmatic scanners (RBAC, secrets, network, runtime, supply chain)
    ├── vulnerability_injectors.py    # 12 injectors for training scenarios
    ├── scenario_generator.py         # Tiered scenario templates (single vuln → full spectrum)
    ├── judge.py                      # Heuristic + LLM scoring of agent actions
    └── k8sguard_environment.py       # OpenEnv Environment (reset/step loop, scan + training modes)
```

### Key Components

**`train.py`** — GRPO training script. Each training step runs a full security scanning episode against the environment and updates the agent's LoRA weights.

**`k8s_commands.py`** — Executes kubectl-style commands against the K8s API. Supports:
- Resources: pods, deployments, services, secrets, configmaps, serviceaccounts, roles, clusterroles, rolebindings, clusterrolebindings, networkpolicies, endpoints, resourcequotas, nodes, events
- Verbs: `get`, `describe`, `logs`, `top`, `delete`, `scale`, `set`, `patch`, `rollout`, `taint`, `auth can-i`

**`scanners.py`** — Five category scanners that programmatically inspect cluster resources and return `SecurityFinding` objects. Can be used standalone to audit a cluster or to validate agent discoveries.

**`vulnerability_injectors.py`** — 12 injection types that create real misconfigurations matching the security curriculum above.

**`llm_client.py`** — Unified LLM client for the judge (OpenAI-compatible/vLLM, Anthropic, or HuggingFace).

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_MODE` | `training` | `training` (injected vulns) or `scan` (real cluster) |
| `LLM_BACKEND` | `openai` | `openai`, `anthropic`, or `hf` |
| `LLM_MODEL` | auto | Model name (e.g., `claude-sonnet-4-20250514`) |
| `LLM_BASE_URL` | `http://localhost:8001/v1` | vLLM/OpenAI-compatible endpoint |
| `LLM_API_KEY` | `local` | API key for OpenAI-compatible backend |
| `ANTHROPIC_API_KEY` | — | Required when `LLM_BACKEND=anthropic` |
| `HF_TOKEN` | — | Required when `LLM_BACKEND=hf` |
| `SCAN_NAMESPACES` | all non-system | Comma-separated namespace list |
| `TRAINING_NAMESPACE` | `k8sguard-training` | Namespace for injected vulnerabilities |
| `DIFFICULTY` | `0.3` | Scenario difficulty (0.0-1.0) in training mode |
| `SCAN_CATEGORY` | all | Focus: `rbac`, `secrets`, `network`, `runtime`, `supply_chain` |
| `MAX_STEPS` | `25` | Max agent actions per episode |
| `SCAN_LOG` | `scan_transcripts.jsonl` | Path for episode transcripts |

## License

MIT
