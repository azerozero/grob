#!/bin/sh
#
# Grob installer — POSIX sh compatible for curl|sh usage.
#
# Usage: see --help
#
# Note: this script intentionally targets POSIX sh (not bash) so it can
# be piped through `curl ... | sh`. Bashisms (set -o pipefail, getopts
# long-opts, [[ ]]) must not be used here.
set -eu

SCRIPT_NAME=$(basename "$0")
BINARY_NAME="grob"
REPO="azerozero/grob"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

usage() {
    cat <<EOF
${SCRIPT_NAME} - Grob installer

Downloads the latest release binary from GitHub and installs it to
\${INSTALL_DIR} (default: \$HOME/.local/bin).

Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help       Show this help and exit
  -v, --verbose    Enable verbose output (shell trace)

Environment:
  INSTALL_DIR      Install destination (default: \$HOME/.local/bin)
  VERSION          Specific version tag to install (default: latest)

Examples:
  ${SCRIPT_NAME}
  curl -fsSL https://raw.githubusercontent.com/azerozero/grob/main/scripts/install.sh | sh
  INSTALL_DIR=/usr/local/bin ${SCRIPT_NAME}
  VERSION=v0.36.0 ${SCRIPT_NAME}

Exit codes:
  0  success
  1  error (unsupported platform, download failure, checksum mismatch)
EOF
}

verbose=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -v|--verbose) verbose=1; shift ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ "${verbose}" -eq 1 ]; then
    set -x
fi

detect_target() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64)       echo "x86_64-unknown-linux-musl" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
                *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
            esac ;;
        Darwin)
            case "$ARCH" in
                x86_64)  echo "x86_64-apple-darwin" ;;
                arm64)   echo "aarch64-apple-darwin" ;;
                *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
            esac ;;
        *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
    esac
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        echo "Error: curl or wget required" >&2; exit 1
    fi
}

get_latest_version() {
    fetch "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

TARGET="$(detect_target)"
VERSION="${VERSION:-$(get_latest_version)}"
ARCHIVE="${BINARY_NAME}-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

echo "Installing ${BINARY_NAME} ${VERSION} for ${TARGET}..."

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

fetch "${URL}" > "${TMPDIR}/${ARCHIVE}"

# Verify checksum
SHA_URL="${URL}.sha256"
if fetch "${SHA_URL}" > "${TMPDIR}/${ARCHIVE}.sha256" 2>/dev/null; then
    echo "Verifying checksum..."
    (cd "${TMPDIR}" && {
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c "${ARCHIVE}.sha256"
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c "${ARCHIVE}.sha256"
        fi
    })
fi

tar xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}" "${BINARY_NAME}"
mkdir -p "${INSTALL_DIR}"
mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

echo "${BINARY_NAME} ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
