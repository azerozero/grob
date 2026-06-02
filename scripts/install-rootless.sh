#!/usr/bin/env bash
#
# Install Grob as a rootless Podman container with systemd.
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly DEPLOY_DIR="${REPO_ROOT}/deploy"
readonly GROB_DIR="${HOME}/.grob"
readonly CONFIG_DIR="${GROB_DIR}/config"
readonly DATA_DIR="${GROB_DIR}/data"
readonly QUADLET_DIR="${HOME}/.config/containers/systemd"

usage() {
  cat <<EOF
${SCRIPT_NAME} - Install Grob as a rootless Podman container

Creates ~/.grob/{config,data} and installs systemd Quadlet units.
Generates a default config.toml if none exists.

Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help       Show this help and exit
  -v, --verbose    Enable verbose output (shell trace)

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --verbose

Exit codes:
  0  success
  1  error (missing podman)
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

  local red green nc
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    red='\033[0;31m'
    green='\033[0;32m'
    nc='\033[0m'
  else
    red='' green='' nc=''
  fi

  echo -e "${green}Installing Grob as rootless Podman container...${nc}"

  if ! command -v podman &> /dev/null; then
    echo -e "${red}Podman not found. Please install first.${nc}"
    exit 1
  fi

  echo "Creating directories..."
  mkdir -p "${CONFIG_DIR}"
  mkdir -p "${DATA_DIR}"
  mkdir -p "${QUADLET_DIR}"

  if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    echo "Creating default config..."
    cat > "${CONFIG_DIR}/config.toml" << 'EOF'
# Grob Configuration
# See docs/reference/configuration.md for full reference.

[server]
host = "0.0.0.0"
port = 8080
log_level = "info"

[server.timeouts]
api_timeout_ms = 600000
connect_timeout_ms = 10000

[auth]
mode = "none"

[router]
default = "placeholder-model"

[security]
audit_dir = "/var/lib/grob/audit"

[dlp]
enabled = true
scan_input = true
scan_output = true
EOF
  fi

  echo "Installing systemd unit files..."
  cp "${DEPLOY_DIR}/grob.container" "${QUADLET_DIR}/"
  cp "${DEPLOY_DIR}/grob.volume" "${QUADLET_DIR}/"

  echo "Reloading systemd..."
  systemctl --user daemon-reload

  echo "Enabling Grob service..."
  systemctl --user enable grob

  echo ""
  echo -e "${green}Installation complete!${nc}"
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
}

main "$@"
