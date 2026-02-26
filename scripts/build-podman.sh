#!/bin/bash
# Build Grob container image with Podman (rootless)
# Usage: ./scripts/build-podman.sh [tag]

set -e

TAG=${1:-latest}
CONTAINERFILE="Containerfile"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building Grob container image with Podman...${NC}"
echo "Tag: ${TAG}"
echo "Containerfile: ${CONTAINERFILE}"
echo ""

# Check Podman is available
if ! command -v podman &> /dev/null; then
    echo -e "${RED}Error: Podman is not installed${NC}"
    echo "Install with: sudo apt install podman  # Debian/Ubuntu"
    echo "             : sudo dnf install podman  # Fedora"
    echo "             : brew install podman      # macOS"
    exit 1
fi

# Check we're in the project root
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Must run from project root${NC}"
    exit 1
fi

# Build with Podman
echo -e "${YELLOW}Building image (this may take a few minutes)...${NC}"
podman build \
    --tag "grob:${TAG}" \
    --file "${CONTAINERFILE}" \
    --format oci \
    --layers \
    .

echo ""
echo -e "${GREEN}Build successful!${NC}"
echo ""
echo "Image: grob:${TAG}"
echo ""
echo "To run (rootless):"
echo "  podman play kube grob-kube.yml"
echo ""
echo "Or with Quadlet (systemd):"
echo "  mkdir -p ~/.config/containers/systemd"
echo "  cp grob.container ~/.config/containers/systemd/"
echo "  cp grob.volume ~/.config/containers/systemd/"
echo "  systemctl --user daemon-reload"
echo "  systemctl --user enable --now grob"
echo ""
echo "To check status:"
echo "  podman ps"
echo "  podman logs grob"
echo "  curl http://localhost:8080/health"
