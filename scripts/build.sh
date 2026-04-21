#!/usr/bin/env bash
#
# Build script for Grob with security modules.
#
# Usage: see --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

usage() {
  cat <<EOF
${SCRIPT_NAME} - Build Grob with full security stack

Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help       Show this help and exit
  -v, --verbose    Enable verbose output (shell trace)

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --verbose

Exit codes:
  0  success
  1  error
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

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "${script_dir}/.."

  echo "Building Grob with full security stack..."

  echo "Running security tests..."
  cargo test --lib security:: 2>&1 | head -50

  echo "Checking compilation..."
  cargo check --release --features tls

  echo "Build complete!"
}

main "$@"
