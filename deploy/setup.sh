#!/bin/bash
# K8sGuard — Setup (k3s cluster + dependencies)
#
# Sets up:
#   1. k3s single-node cluster (lightweight K8s)
#   2. Python venv with dependencies
#   3. RBAC for scanning
#
# After setup:  python -m server.app --scan-mode training

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"

echo "============================================================"
echo " K8sGuard — Setup"
echo "============================================================"

# ---- 1. Install k3s ----
if ! command -v k3s &>/dev/null; then
    echo "[1/4] Installing k3s..."
    curl -sfL https://get.k3s.io | sh -s - \
        --write-kubeconfig-mode 644 \
        --disable traefik
    sleep 15
    mkdir -p ~/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
    sudo chown "$(id -u):$(id -g)" ~/.kube/config
else
    echo "[1/4] k3s already installed: $(k3s --version 2>/dev/null | head -1)"
fi

# ---- 2. Install kubectl ----
if ! command -v kubectl &>/dev/null; then
    echo "[2/4] Installing kubectl..."
    KUBE_VERSION=$(curl -sL https://dl.k8s.io/release/stable.txt)
    curl -Lo /tmp/kubectl "https://dl.k8s.io/release/${KUBE_VERSION}/bin/linux/amd64/kubectl"
    chmod +x /tmp/kubectl
    sudo mv /tmp/kubectl /usr/local/bin/kubectl
else
    echo "[2/4] kubectl available"
fi

# ---- 3. Create Python venv ----
echo "[3/4] Setting up Python venv..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install \
    kubernetes \
    tabulate \
    anthropic \
    openai \
    requests \
    2>&1 | tail -5

pip install -e "$REPO_DIR" 2>&1 | tail -3

# ---- 4. Create training namespace ----
echo "[4/4] Creating training namespace..."
kubectl create namespace k8sguard-training --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "============================================================"
echo " Setup complete!"
echo ""
echo " To start the scanner server:"
echo "   source .venv/bin/activate"
echo "   python -m server.app --scan-mode training"
echo ""
echo " To scan a real cluster:"
echo "   python -m server.app --scan-mode scan"
echo "============================================================"
