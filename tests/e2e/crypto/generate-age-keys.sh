#!/usr/bin/env bash
set -euo pipefail

# Generates age encryption keypairs for the three personas used in e2e tests:
#   rssi      - security officer (can decrypt all)
#   dpo       - data protection officer (can decrypt PII-tagged payloads)
#   intruder  - adversarial role (should NOT be able to decrypt anything)
#
# Output files (git-ignored):
#   crypto/keys/rssi.key      crypto/keys/rssi.pub
#   crypto/keys/dpo.key       crypto/keys/dpo.pub
#   crypto/keys/intruder.key  crypto/keys/intruder.pub
#
# Dependencies: age (https://github.com/FiloSottile/age)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}/keys"

PERSONAS=(rssi dpo intruder)

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
if ! command -v age-keygen &>/dev/null; then
    echo "ERROR: age-keygen is not installed." >&2
    echo "  Install: https://github.com/FiloSottile/age#installation" >&2
    echo "  macOS:   brew install age" >&2
    echo "  Linux:   apt install age  or  snap install age" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Generate keypairs
# ---------------------------------------------------------------------------
mkdir -p "${KEYS_DIR}"

echo "=== Generating age keypairs ==="

for persona in "${PERSONAS[@]}"; do
    key_file="${KEYS_DIR}/${persona}.key"
    pub_file="${KEYS_DIR}/${persona}.pub"

    if [[ -f "${key_file}" ]]; then
        echo "  → ${persona}: key already exists, skipping"
    else
        echo "  → ${persona}: generating…"
        age-keygen -o "${key_file}" 2>/dev/null
        chmod 600 "${key_file}"
    fi

    # Extract the public key from the key file (the comment line "# public key: age1...")
    pub=$(grep "^# public key:" "${key_file}" | sed 's/^# public key: //')
    echo "${pub}" > "${pub_file}"
    echo "     public key: ${pub}"
done

# ---------------------------------------------------------------------------
# Print instructions
# ---------------------------------------------------------------------------
echo ""
echo "✓ age keypairs generated in ${KEYS_DIR}/"
echo ""
echo "To enable age encryption in grob-test.toml, add the following section:"
echo ""
echo "  [encryption.age]"
echo "  enabled = true"
echo ""
for persona in "${PERSONAS[@]}"; do
    pub_file="${KEYS_DIR}/${persona}.pub"
    pub=$(cat "${pub_file}")
    echo "  # ${persona}"
    echo "  [[encryption.age.recipients]]"
    echo "  id     = \"${persona}\""
    echo "  pubkey = \"${pub}\""
    echo ""
done
echo "NOTE: crypto/keys/ is git-ignored. Do not commit private keys."
