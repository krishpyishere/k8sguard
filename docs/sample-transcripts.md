# K8sGuard — Sample Training Transcripts

Real transcripts from the 8xH100 GRPO training run showing the agent's progression.

## Early training (step ~5): Agent wanders aimlessly

Scenario: No NetworkPolicy in namespace (the agent should find the missing policy).

```
reset() — Injected: no-network-policy scenario in k8sguard-training

Step  1: kubectl get networkpolicies -A          → reward=+0.20 (investigation)
Step  2: kubectl describe pod api-server          → reward=+0.20 (investigation)
Step  3: kubectl describe pod debug-tools         → reward=+0.20 (investigation)
Step  4: kubectl describe pod web-app             → reward=+0.20 (investigation)
Step  5: kubectl get clusterroles                 → reward=+0.20 (investigation)
Step  6: kubectl get clusterrolebindings          → reward=+0.20 (investigation)
Step  7: kubectl get serviceaccount -A            → reward=-0.20 (typo: "serviceaccount" not "serviceaccounts")
Step  8: kubectl describe serviceaccount default  → reward=-0.20 (judge: "does not address missing NetworkPolicy")
Step  9: kubectl get secrets -A                   → reward=+0.20 (investigation)
Step 10: kubectl get configmap -A                 → reward=-0.20 (judge: "unrelated to detecting missing NetworkPolicy")
Step 11: kubectl describe pod api-server          → reward=-0.20 (REPEATED — already ran at step 2)
Step 12: kubectl describe pod debug-tools         → reward=-0.20 (REPEATED)
Step 13: kubectl describe pod web-app             → reward=-0.20 (REPEATED)
Step 14: kubectl get pod api-server -o jsonpath   → reward=+0.20 (investigation)
...continued investigating without ever reporting a finding
```

The untrained agent runs valid kubectl commands but **never reports a finding**. It circles through the same resources, gets penalized for repeats, and runs out of steps.

## Late training (step ~140+): Agent identifies vulnerabilities instantly

### Privileged container — found on step 1

```
reset() — Injected: privileged pod 'debug-tools' in k8sguard-training

Step  1: finding: high - Potential privileged container detected in pod 'debug-tools'
         → reward=+1.10 | Correctly identified: Privileged container

(episode complete — scan complete!)
```

### Root UID container — found on step 1

```
reset() — Injected: run-as-root pod 'legacy-app' in k8sguard-training

Step  1: finding: high - Container is running as root UID in pod 'legacy-app' in namespace 'k8sguard-training'
         → reward=+0.95 | Correctly identified: Container may run as root

(episode complete)
```

### Unpinned image — found on step 1

```
reset() — Injected: :latest image pod 'app-deploy' in k8sguard-training

Step  1: finding: high - Unpinned container image detected in pod app-deploy
         → reward=+0.80 | Correctly identified: Image uses :latest or no tag

(episode complete)
```

### Secrets in env vars — multi-step investigation then finding

```
reset() — Injected: secret-in-env pod 'api-server' in k8sguard-training

Step  1: finding: medium - Possible secret exposure in workload configuration
         → reward=+0.10 (too vague — doesn't match known vulnerability)
Step  2: remediate: kubectl describe pod api-server -n k8sguard-training
         → reward=+0.10 (investigating, not actually remediating)
Step  3: kubectl get clusterroles
         → reward=+0.20 (investigation)
Step  4: kubectl get networkpolicies -A
         → reward=+0.20 (investigation)
Step  5: kubectl describe pod api-server -n k8sguard-training
         → reward=+0.20 (investigation — found the env vars)
Step  6: finding: medium - Secrets are exposed via environment variables in the api-server pod
         → reward=+0.95 | Correctly identified: Secret exposed as environment variable

(episode complete — scan complete!)
```

The trained agent first tries a generic finding (rejected), then investigates the pod, reads the env var details, and submits a precise finding that matches.

## Key observations

1. **Speed**: the trained agent identifies tier-1 vulnerabilities on step 1 — no investigation needed. It learned the patterns.
2. **Precision**: findings use specific language matching the vulnerability ("privileged container", "running as root UID", "unpinned container image").
3. **Adaptiveness**: for harder vulnerabilities (secrets in env), the agent falls back to investigation, reads describe output, then submits a targeted finding.
4. **Remediation gap**: the agent rarely attempts correct fix commands — it finds vulnerabilities but doesn't apply fixes. This is the focus of the next training run.
