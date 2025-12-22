#!/bin/bash
# Setup DNS for mesh VPN testing
# Adds echo.dev.int to /etc/hosts

set -e

MESH_IP="${MESH_IP:-127.0.0.1}"

echo "=== Mesh VPN DNS Setup ==="
echo "Adding echo.dev.int -> $MESH_IP"

# Check if already exists
if grep -q "echo.dev.int" /etc/hosts; then
    echo "echo.dev.int already exists in /etc/hosts"
    grep "echo.dev.int" /etc/hosts
    exit 0
fi

# Add entry
echo "$MESH_IP    echo.dev.int" | sudo tee -a /etc/hosts

echo "Done! echo.dev.int now resolves to $MESH_IP"
echo ""
echo "Test with: curl http://echo.dev.int:8888/"
