#!/bin/bash
# Install Grob as a rootless Podman container with systemd
# Usage: ./scripts/install-rootless.sh

set -e

GROB_DIR="${HOME}/.grob"
CONFIG_DIR="${GROB_DIR}/config"
DATA_DIR="${GROB_DIR}/data"
QUADLET_DIR="${HOME}/.config/containers/systemd"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Installing Grob as rootless Podman container...${NC}"

# Check Podman
if ! command -v podman &> /dev/null; then
    echo -e "${RED}Podman not found. Please install first.${NC}"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p "${CONFIG_DIR}"
mkdir -p "${DATA_DIR}"
mkdir -p "${QUADLET_DIR}"

# Generate default config if not exists
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    echo "Creating default config..."
    cat > "${CONFIG_DIR}/config.toml" << 'EOF'
# Grob Configuration
# See docs/CONFIGURATION.md for full reference

[server]
host = "0.0.0.0"
port = 8080
metrics_port = 9090

[auth]
mode = "api_key"  # or "jwt" or "none"

[security]
rate_limit_requests_per_second = 100
rate_limit_burst = 200
max_body_size = 10485760  # 10MB

[dlp]
enabled = true
scan_input = true
scan_output = true

[audit]
enabled = true
directory = "/var/lib/grob/audit"
encrypt = true

[log]
level = "info"
format = "json"
EOF
fi

# Install Quadlet files
echo "Installing systemd unit files..."
if [ -f "grob.container" ]; then
    cp grob.container "${QUADLET_DIR}/"
fi

if [ -f "grob.volume" ]; then
    cp grob.volume "${QUADLET_DIR}/"
fi

# Reload systemd
echo "Reloading systemd..."
systemctl --user daemon-reload

# Enable service
echo "Enabling Grob service..."
systemctl --user enable grob 2>/dev/null || true

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "To start Grob:"
echo "  systemctl --user start grob"
echo ""
echo "To check status:"
echo "  systemctl --user status grob"
echo "  podman logs grob"
echo "  curl http://localhost:8080/health"
echo ""
echo "Config directory: ${CONFIG_DIR}"
echo "Data directory: ${DATA_DIR}"
