#!/bin/bash
# Start multiple K8sGuard env servers for parallel DDP training.
# Each server gets its own port and K8s training namespace.
#
# Usage: bash deploy/start_env_servers.sh [NUM_RANKS] [BASE_PORT]
#   NUM_RANKS: number of DDP training ranks (default: 6)
#   BASE_PORT: starting port (default: 8000)

set -e

NUM_RANKS=${1:-6}
BASE_PORT=${2:-8000}

echo "Starting $NUM_RANKS env servers (ports $BASE_PORT-$((BASE_PORT + NUM_RANKS - 1)))"

for i in $(seq 0 $((NUM_RANKS - 1))); do
    PORT=$((BASE_PORT + i))
    NS="k8sguard-training-${i}"
    LOG="/tmp/env_server_${i}.log"

    echo "  Rank $i: port=$PORT namespace=$NS log=$LOG"

    TRAINING_NAMESPACE="$NS" \
    LLM_BACKEND="${LLM_BACKEND:-openai}" \
    LLM_MODEL="${LLM_MODEL:-nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-FP8}" \
    LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:8001/v1}" \
    LLM_API_KEY="${LLM_API_KEY:-local}" \
    CURRICULUM="${CURRICULUM:-1}" \
    nohup python -m server.app --scan-mode training --port "$PORT" > "$LOG" 2>&1 &
done

echo "Waiting for servers to start..."
sleep 5

# Health check all servers
OK=0
for i in $(seq 0 $((NUM_RANKS - 1))); do
    PORT=$((BASE_PORT + i))
    if curl -s "http://localhost:${PORT}/healthz" > /dev/null 2>&1; then
        echo "  Port $PORT: OK"
        OK=$((OK + 1))
    else
        echo "  Port $PORT: FAIL"
    fi
done

echo "$OK/$NUM_RANKS env servers healthy"
