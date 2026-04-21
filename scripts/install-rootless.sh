#!/usr/bin/env bash
#
# Install Grob as a rootless Podman container with systemd.
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
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

  echo "Installing systemd unit files..."
  if [ -f "grob.container" ]; then
    cp grob.container "${QUADLET_DIR}/"
  fi

  if [ -f "grob.volume" ]; then
    cp grob.volume "${QUADLET_DIR}/"
  fi

  echo "Reloading systemd..."
  systemctl --user daemon-reload

  echo "Enabling Grob service..."
  systemctl --user enable grob 2>/dev/null || true

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
