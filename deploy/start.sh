#!/bin/bash
# K8sGuard — Start server
# Usage: bash deploy/start.sh [scan|training]
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate 2>/dev/null || true

MODE="${1:-training}"
export SCAN_MODE="$MODE"

echo "Starting K8sGuard server (mode=$MODE)..."
python -m server.app --scan-mode "$MODE"
