#!/usr/bin/env bash
set -euo pipefail

# Generates all auth fixtures needed by the e2e test suite:
#   - EC P-256 signing keypair  (auth/keys/)
#   - JWKS document             (auth/jwks.json)
#   - 10 JWT fixtures           (auth/tokens/)
#   - nginx.conf for mock-jwks  (auth/nginx.conf)
#
# Dependencies: openssl, python3, pip packages: cryptography, PyJWT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# AUTH_OUTPUT_DIR allows writing to a shared volume (e.g. emptyDir in pod).
# Falls back to SCRIPT_DIR for local/host usage.
OUT_DIR="${AUTH_OUTPUT_DIR:-${SCRIPT_DIR}}"
KEYS_DIR="${OUT_DIR}/keys"
TOKENS_DIR="${OUT_DIR}/tokens"
PRIVATE_KEY="${KEYS_DIR}/test-signing.key"
PUBLIC_KEY="${KEYS_DIR}/test-signing.pub"
JWKS_FILE="${OUT_DIR}/jwks.json"
NGINX_CONF="${OUT_DIR}/nginx.conf"

ISSUER="https://openbao.test"
AUDIENCE="grob-siege"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_deps() {
    local missing=()
    command -v openssl  >/dev/null || missing+=("openssl")
    command -v python3  >/dev/null || missing+=("python3")

    if (( ${#missing[@]} > 0 )); then
        echo "ERROR: missing required tools: ${missing[*]}" >&2
        exit 1
    fi

    python3 -c "import jwt, cryptography" 2>/dev/null || {
        echo "→ Installing python3 dependencies (PyJWT, cryptography)…"
        pip3 install --quiet PyJWT cryptography
    }
}

# ---------------------------------------------------------------------------
# 1. Generate RSA 2048 keypair (grob JWKS parser only supports RSA)
# ---------------------------------------------------------------------------
generate_keypair() {
    mkdir -p "${KEYS_DIR}"

    if [[ -f "${PRIVATE_KEY}" ]]; then
        echo "→ Signing key already exists at ${PRIVATE_KEY}, skipping"
        return
    fi

    echo "→ Generating RSA 2048 signing keypair…"
    openssl genrsa -out "${PRIVATE_KEY}" 2048 2>/dev/null
    openssl rsa -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}" 2>/dev/null
    chmod 600 "${PRIVATE_KEY}"
    echo "   private: ${PRIVATE_KEY}"
    echo "   public:  ${PUBLIC_KEY}"
}

# ---------------------------------------------------------------------------
# 2. Build JWKS + JWTs via Python
# ---------------------------------------------------------------------------
run_python() {
    python3 - "${PRIVATE_KEY}" "${JWKS_FILE}" "${TOKENS_DIR}" "${ISSUER}" "${AUDIENCE}" <<'PYEOF'
import sys, json, time, base64, secrets
from pathlib import Path
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PublicFormat, NoEncryption, PrivateFormat
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as rsa_generate
from cryptography.hazmat.backends import default_backend
import jwt as pyjwt

private_key_path = Path(sys.argv[1])
jwks_path        = Path(sys.argv[2])
tokens_dir       = Path(sys.argv[3])
issuer           = sys.argv[4]
audience         = sys.argv[5]

tokens_dir.mkdir(parents=True, exist_ok=True)

# Load the RSA private key
with open(private_key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

public_key = private_key.public_key()
pub_numbers = public_key.public_numbers()

# --------------------------------------------------------------------------
# Build JWKS from the RSA public key
# --------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(length, byteorder="big"))

jwk = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "grob-e2e-signing-key-v1",
    "n": int_to_b64url(pub_numbers.n),
    "e": int_to_b64url(pub_numbers.e),
}
jwks = {"keys": [jwk]}

with open(jwks_path, "w") as f:
    json.dump(jwks, f, indent=2)
print(f"   JWKS written to {jwks_path}")

# --------------------------------------------------------------------------
# Helper: sign a JWT
# --------------------------------------------------------------------------
def sign_jwt(payload: dict, key=None, algorithm="RS256", headers=None) -> str:
    if key is None:
        key = private_key
    # Default: include kid so JWKS lookup works
    if headers is None:
        headers = {"kid": "grob-e2e-signing-key-v1"}
    kw = {"headers": headers}
    return pyjwt.encode(payload, key, algorithm=algorithm, **kw)

now = int(time.time())
one_hour = 3600

# --------------------------------------------------------------------------
# jwt-default: valid, minimal claims
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-default",
    "tenant": "default",
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-default.txt").write_text(tok)
print("   jwt-default          ✓")

# --------------------------------------------------------------------------
# jwt-hospital-eu: tenant=hospital-cardiology-fr, compliance=[gdpr]
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-hospital-eu",
    "tenant": "hospital-cardiology-fr",
    "compliance": ["gdpr"],
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-hospital-eu.txt").write_text(tok)
print("   jwt-hospital-eu      ✓")

# --------------------------------------------------------------------------
# jwt-team-perf: tenant=team-perf-engineering
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-team-perf",
    "tenant": "team-perf-engineering",
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-team-perf.txt").write_text(tok)
print("   jwt-team-perf        ✓")

# --------------------------------------------------------------------------
# jwt-project-gdpr: generic GDPR-tagged project token
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-project-gdpr",
    "tenant": "project-gdpr-analytics",
    "compliance": ["gdpr", "euai"],
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-project-gdpr.txt").write_text(tok)
print("   jwt-project-gdpr     ✓")

# --------------------------------------------------------------------------
# jwt-expired: exp in the past
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-expired",
    "tenant": "default",
    "iat": now - 7200,
    "exp": now - 3600,   # expired 1 hour ago
})
(tokens_dir / "jwt-expired.txt").write_text(tok)
print("   jwt-expired          ✓")

# --------------------------------------------------------------------------
# jwt-wrong-issuer: iss does not match
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": "https://attacker.evil",
    "aud": audience,
    "sub": "user-wrong-issuer",
    "tenant": "default",
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-wrong-issuer.txt").write_text(tok)
print("   jwt-wrong-issuer     ✓")

# --------------------------------------------------------------------------
# jwt-wrong-audience: aud does not match
# --------------------------------------------------------------------------
tok = sign_jwt({
    "iss": issuer,
    "aud": "wrong-audience",
    "sub": "user-wrong-aud",
    "tenant": "default",
    "iat": now,
    "exp": now + one_hour,
})
(tokens_dir / "jwt-wrong-audience.txt").write_text(tok)
print("   jwt-wrong-audience   ✓")

# --------------------------------------------------------------------------
# jwt-tampered: valid structure but payload modified after signing
# We take a valid token and flip a base64 character in the payload section.
# --------------------------------------------------------------------------
valid_tok = sign_jwt({
    "iss": issuer,
    "aud": audience,
    "sub": "user-tampered",
    "tenant": "default",
    "iat": now,
    "exp": now + one_hour,
})
parts = valid_tok.split(".")
# Decode payload, flip one character, re-encode without padding
payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
payload_str = payload_bytes.decode()
# Replace "default" with "adminXX" in the payload to simulate tampering
tampered_payload = payload_str.replace('"default"', '"admin-tampered"')
tampered_b64 = base64.urlsafe_b64encode(tampered_payload.encode()).rstrip(b"=").decode()
tampered_tok = f"{parts[0]}.{tampered_b64}.{parts[2]}"
(tokens_dir / "jwt-tampered.txt").write_text(tampered_tok)
print("   jwt-tampered         ✓")

# --------------------------------------------------------------------------
# jwt-self-signed: signed with a freshly generated random key (not in JWKS)
# --------------------------------------------------------------------------
rogue_key = rsa_generate(public_exponent=65537, key_size=2048, backend=default_backend())
tok = sign_jwt(
    {
        "iss": issuer,
        "aud": audience,
        "sub": "user-self-signed",
        "tenant": "default",
        "iat": now,
        "exp": now + one_hour,
    },
    key=rogue_key,
    headers={"kid": "rogue-key-not-in-jwks"},
)
(tokens_dir / "jwt-self-signed.txt").write_text(tok)
print("   jwt-self-signed      ✓")

# --------------------------------------------------------------------------
# jwt-algo-none: alg=none, no signature — should be rejected by any sane impl
# Manually construct the token without using PyJWT's none algorithm to avoid
# library-level rejection.
# --------------------------------------------------------------------------
header_b64  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
payload_obj = {
    "iss": issuer,
    "aud": audience,
    "sub": "user-algo-none",
    "tenant": "default",
    "iat": now,
    "exp": now + one_hour,
}
payload_b64 = base64.urlsafe_b64encode(
    json.dumps(payload_obj).encode()
).rstrip(b"=").decode()
algo_none_tok = f"{header_b64}.{payload_b64}."
(tokens_dir / "jwt-algo-none.txt").write_text(algo_none_tok)
print("   jwt-algo-none        ✓")

print("")
print(f"Tokens written to {tokens_dir}/")
PYEOF
}

# ---------------------------------------------------------------------------
# 3. Write a minimal nginx.conf for the mock-jwks container
# ---------------------------------------------------------------------------
write_nginx_conf() {
    cat > "${NGINX_CONF}" <<'NGINX'
server {
    listen       8443;
    server_name  localhost;

    root  /usr/share/nginx/html;
    index index.html;

    # Serve the JWKS document
    location /.well-known/jwks.json {
        default_type application/json;
        add_header Cache-Control "no-store";
    }

    # Health check endpoint
    location /health {
        default_type text/plain;
        return 200 "ok\n";
    }
}
NGINX
    echo "   nginx.conf written to ${NGINX_CONF}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "=== Generating e2e auth fixtures ==="
check_deps
generate_keypair
echo "→ Building JWKS and JWT fixtures…"
run_python
write_nginx_conf
echo ""
echo "✓ Auth fixtures generated"
echo "  JWKS:   ${JWKS_FILE}"
echo "  Tokens: ${TOKENS_DIR}/"
echo ""
echo "NOTE: auth/keys/ and auth/tokens/ are git-ignored. Do not commit them."
