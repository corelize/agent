#!/bin/bash
set -e

echo "=== Mesh Agent Kubernetes Deployment ==="

# Build the Rust binary for Linux
echo "[1/5] Building mesh-agent for Linux..."
GOOS=linux GOARCH=arm64 cargo build --release 2>/dev/null || cargo build --release

# Build Docker image
echo "[2/5] Building Docker image..."
docker build -t mesh-agent:latest .

# Apply Kubernetes manifests
echo "[3/5] Applying Kubernetes manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/echo-server.yaml
kubectl apply -f k8s/mesh-agent.yaml

# Wait for deployments
echo "[4/5] Waiting for deployments to be ready..."
kubectl -n mesh-vpn rollout status deployment/echo-server --timeout=60s
kubectl -n mesh-vpn rollout status deployment/mesh-agent --timeout=60s

# Show status
echo "[5/5] Deployment complete!"
echo ""
echo "=== Status ==="
kubectl -n mesh-vpn get pods
echo ""
kubectl -n mesh-vpn get services
echo ""
echo "=== Access Points ==="
echo "Echo server (via mesh-agent): http://localhost:30888/"
echo "Mesh agent health: http://localhost:30081/health"
echo ""
echo "To test: curl http://localhost:30888/"
