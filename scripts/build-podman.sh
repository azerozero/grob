#!/usr/bin/env bash
#
# Build Grob container image with Podman (rootless).
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly CONTAINERFILE="Containerfile"

usage() {
  cat <<EOF
${SCRIPT_NAME} - Build Grob container image with Podman (rootless)

Usage: ${SCRIPT_NAME} [options] [tag]

Arguments:
  tag              Image tag (default: latest)

Options:
  -h, --help       Show this help and exit
  -v, --verbose    Enable verbose output (shell trace)

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} v0.1.0
  ${SCRIPT_NAME} --verbose latest

Exit codes:
  0  success
  1  error (missing podman, wrong directory, build failure)
EOF
}

main() {
  local verbose=0
  while getopts "hv-:" opt; do
    case "${opt}" in
      h) usage; exit 0 ;;
      v) verbose=1 ;;
      -)
        case "${OPTARG}" in
          help) usage; exit 0 ;;
          verbose) verbose=1 ;;
          *) echo "Unknown option --${OPTARG}" >&2; usage >&2; exit 1 ;;
        esac
        ;;
      *) usage >&2; exit 1 ;;
    esac
  done
  shift $((OPTIND - 1))

  if [[ "${verbose}" -eq 1 ]]; then
    set -x
  fi

  local tag="${1:-latest}"

  local red green yellow nc
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    red='\033[0;31m'
    green='\033[0;32m'
    yellow='\033[1;33m'
    nc='\033[0m'
  else
    red='' green='' yellow='' nc=''
  fi

  echo -e "${green}Building Grob container image with Podman...${nc}"
  echo "Tag: ${tag}"
  echo "Containerfile: ${CONTAINERFILE}"
  echo ""

  if ! command -v podman &> /dev/null; then
    echo -e "${red}Error: Podman is not installed${nc}"
    echo "Install with: sudo apt install podman  # Debian/Ubuntu"
    echo "             : sudo dnf install podman  # Fedora"
    echo "             : brew install podman      # macOS"
    exit 1
  fi

  if [ ! -f "Cargo.toml" ]; then
    echo -e "${red}Error: Must run from project root${nc}"
    exit 1
  fi

  echo -e "${yellow}Building image (this may take a few minutes)...${nc}"
  podman build \
    --tag "grob:${tag}" \
    --file "${CONTAINERFILE}" \
    --format oci \
    --layers \
    .

  echo ""
  echo -e "${green}Build successful!${nc}"
  echo ""
  echo "Image: grob:${tag}"
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
}

main "$@"
