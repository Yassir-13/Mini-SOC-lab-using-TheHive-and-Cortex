#!/bin/bash
# =============================================================
# TheHive + Cortex - Host Preparation Script
# Run this ONCE before launching docker compose
# =============================================================
set -e

echo "=============================================="
echo " TheHive + Cortex - Host Setup"
echo "=============================================="

# 1. Set vm.max_map_count for Elasticsearch
echo ""
echo "[1/5] Setting vm.max_map_count for Elasticsearch..."
CURRENT_MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
if [ "$CURRENT_MAP_COUNT" -lt 262144 ]; then
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "  -> Set to 262144 (persisted in /etc/sysctl.conf)"
else
    echo "  -> Already set to $CURRENT_MAP_COUNT (OK)"
fi

# 2. Create directory structure
echo ""
echo "[2/5] Creating directory structure..."
mkdir -p cortex
echo "  -> Directories created"

# 3. Set permissions for Docker socket (Cortex needs it for analyzers)
echo ""
echo "[3/5] Checking Docker socket permissions..."
if [ -S /var/run/docker.sock ]; then
    echo "  -> Docker socket found at /var/run/docker.sock"
    # Ensure current user is in docker group
    if groups $USER | grep -q docker; then
        echo "  -> User '$USER' is in the docker group (OK)"
    else
        echo "  -> Adding user '$USER' to docker group..."
        sudo usermod -aG docker $USER
        echo "  -> IMPORTANT: Log out and back in for group changes to take effect!"
    fi
else
    echo "  -> WARNING: Docker socket not found. Is Docker installed?"
fi

# 4. Create /tmp/cortex-jobs directory
echo ""
echo "[4/5] Creating Cortex jobs directory..."
mkdir -p /tmp/cortex-jobs
sudo chmod 1777 /tmp/cortex-jobs
echo "  -> /tmp/cortex-jobs created with proper permissions"

# 5. Verify Docker & Docker Compose
echo ""
echo "[5/5] Verifying Docker installation..."
if command -v docker &> /dev/null; then
    echo "  -> Docker version: $(docker --version)"
else
    echo "  -> ERROR: Docker not found! Install Docker first."
    exit 1
fi

if docker compose version &> /dev/null; then
    echo "  -> Docker Compose version: $(docker compose version --short)"
else
    echo "  -> ERROR: Docker Compose not found!"
    exit 1
fi

echo ""
echo "=============================================="
echo " Setup complete! Next steps:"
echo "=============================================="
echo ""
echo "  1. Review/edit the .env file:"
echo "     nano .env"
echo ""
echo "  2. Launch the stack:"
echo "     docker compose up -d"
echo ""
echo "  3. Watch the logs:"
echo "     docker compose logs -f"
echo ""
echo "  4. Access the services:"
echo "     TheHive  -> http://<your-ip>:9000"
echo "     Cortex   -> http://<your-ip>:9001"
echo "     MinIO    -> http://<your-ip>:9090"
echo ""
