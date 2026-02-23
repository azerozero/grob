#!/bin/sh
# Grob installer
# Usage: curl -fsSL https://raw.githubusercontent.com/azerozero/grob/main/scripts/install.sh | sh
set -eu

BINARY_NAME="grob"
REPO="azerozero/grob"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

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
