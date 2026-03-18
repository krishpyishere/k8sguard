#!/bin/bash
# Auto-restart training loop. Resumes from latest checkpoint on crash.
# Usage: bash deploy/train_loop.sh [VENV] [BASE_ENV_PORT] [MAX_RESTARTS]
#
# The training will crash every ~30-35 steps due to GPU memory creep.
# This script automatically restarts from the latest checkpoint.

set -e

VENV=${1:-.venv_train}
BASE_PORT=${2:-8010}
MAX_RESTARTS=${3:-20}

cd /home/ubuntu/k8sguard
source "$VENV/bin/activate"

for attempt in $(seq 1 $MAX_RESTARTS); do
    echo ""
    echo "============================================"
    echo "Training attempt $attempt/$MAX_RESTARTS"
    echo "============================================"

    # Find latest checkpoint
    LATEST_DIR=$(ls -dt outputs/k8sguard-grpo-*Instruct-2507*/ 2>/dev/null | head -1)
    RESUME_ARG=""
    if [ -n "$LATEST_DIR" ]; then
        LATEST_CKPT=$(ls -dt "$LATEST_DIR"/checkpoint-* 2>/dev/null | head -1)
        if [ -n "$LATEST_CKPT" ]; then
            echo "Resuming from: $LATEST_CKPT"
            RESUME_ARG="--resume_from_checkpoint $LATEST_CKPT"
        fi
    fi

    # Start training
    TORCH_NCCL_ENABLE_MONITORING=0 TORCH_NCCL_HEARTBEAT_TIMEOUT_SEC=7200 \
    CUDA_VISIBLE_DEVICES=0,1,2,3,4,5 torchrun --nproc_per_node=6 --master_port=29500 \
      train.py --model-id Qwen/Qwen3-4B-Instruct-2507 --vllm-mode colocate \
      --env-url "http://localhost:$BASE_PORT" --max-steps 200 --dataset-size 100 \
      --num-generations 12 --gradient-accumulation-steps 4 \
      --max-turns 25 --max-new-tokens 2048 --temperature 1.0 --save-steps 10 \
      $RESUME_ARG \
      2>&1 | tee /tmp/training.log

    EXIT_CODE=$?
    echo "Training exited with code $EXIT_CODE"

    if [ $EXIT_CODE -eq 0 ]; then
        echo "Training completed successfully!"
        break
    fi

    echo "Crash detected. Waiting 10s before restart..."
    sleep 10
done

echo "Training loop finished after $attempt attempts"
