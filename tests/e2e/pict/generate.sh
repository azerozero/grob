#!/usr/bin/env bash
set -euo pipefail

# Generates the pairwise test matrix from grob.pict using the PICT tool,
# then produces .hurl test files for each row.
#
# Output:
#   pict/grob-pairwise.txt       — raw PICT matrix
#   tests/pairwise/PW-NN-*.hurl  — one hurl file per matrix row
#
# Dependencies: pict (https://github.com/microsoft/pict)
#   macOS:  brew install pict
#   Linux:  build from source or download release binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODEL_FILE="${SCRIPT_DIR}/grob.pict"
MATRIX_FILE="${SCRIPT_DIR}/grob-pairwise.txt"
OUTPUT_DIR="${E2E_DIR}/tests/pairwise"

# ---------------------------------------------------------------------------
# Step 1: Generate the matrix (or use pre-generated fallback)
# ---------------------------------------------------------------------------
if command -v pict &>/dev/null; then
    echo "-> pict $(pict 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "(version unknown)")"
    echo "-> Generating pairwise matrix from ${MODEL_FILE}..."
    pict "${MODEL_FILE}" > "${MATRIX_FILE}"
else
    echo "WARN: pict is not installed, using pre-generated matrix." >&2
    echo "  macOS:  brew install pict" >&2
    echo "  Linux:  https://github.com/microsoft/pict/releases" >&2
    if [[ ! -f "${MATRIX_FILE}" ]]; then
        echo "ERROR: No pre-generated matrix at ${MATRIX_FILE}." >&2
        echo "  Install pict and run again." >&2
        exit 1
    fi
fi

total_lines=$(wc -l < "${MATRIX_FILE}")
case_count=$(( total_lines - 1 ))
echo "-> Matrix: ${case_count} test cases"

# ---------------------------------------------------------------------------
# Step 2: Generate .hurl files from the matrix
# ---------------------------------------------------------------------------
# Clean previous generated files (keep fixtures/)
find "${OUTPUT_DIR}" -name 'PW-*.hurl' -delete 2>/dev/null || true
mkdir -p "${OUTPUT_DIR}"

# Map dimension values to hurl constructs
auth_header() {
    case "$1" in
        jwt_valid)    echo "Authorization: Bearer {{jwt_default}}" ;;
        jwt_expired)  echo "Authorization: Bearer {{jwt_expired}}" ;;
        jwt_tampered) echo "Authorization: Bearer {{jwt_tampered}}" ;;
        api_key)      echo "X-Grob-API-Key: invalid-key" ;;
        none)         echo "" ;;
        *)            echo "Authorization: Bearer {{jwt_default}}" ;;
    esac
}

format_endpoint() {
    case "$1" in
        openai)    echo "/v1/chat/completions" ;;
        anthropic) echo "/v1/messages" ;;
        *)         echo "/v1/chat/completions" ;;
    esac
}

payload_fixture() {
    case "$1" in
        clean)     echo "fixtures/chat-simple.json" ;;
        secrets)   echo "fixtures/dlp/prompt-with-aws-key.json" ;;
        pii)       echo "fixtures/dlp/prompt-with-cc.json" ;;
        injection) echo "fixtures/dlp/prompt-with-jwt.json" ;;
        *)         echo "fixtures/chat-simple.json" ;;
    esac
}

# Determine expected HTTP status based on the combination.
# Auth failures are caught before anything else.
# all_down with valid auth yields 502.
expected_status() {
    local auth="$1" provider="$2"
    case "$auth" in
        jwt_expired|jwt_tampered|api_key|none)
            echo "401" ;;
        *)
            if [[ "$provider" == "all_down" ]]; then
                echo "502"
            else
                echo "200"
            fi
            ;;
    esac
}

# Determine which JWT variable to use for policy-bearing tokens.
jwt_variable() {
    local auth="$1" policy="$2"
    if [[ "$auth" != "jwt_valid" ]]; then
        # Non-valid JWTs use their specific variable.
        case "$auth" in
            jwt_expired)  echo "jwt_expired" ;;
            jwt_tampered) echo "jwt_tampered" ;;
            *)            echo "jwt_default" ;;
        esac
        return
    fi
    # Valid JWT: pick the token matching the policy.
    case "$policy" in
        hospital_eu) echo "jwt_hospital_eu" ;;
        team_perf)   echo "jwt_team_perf" ;;
        *)           echo "jwt_default" ;;
    esac
}

# Build assertions based on status and dimensions.
build_asserts() {
    local status="$1" auth="$2" provider="$3" dlp="$4" format="$5" payload="$6"

    if [[ "$status" == "401" ]]; then
        echo 'jsonpath "$.error.type" == "authentication_error"'
        return
    fi

    if [[ "$status" == "502" ]]; then
        # All providers down — just check status code (already in HTTP line).
        return
    fi

    # Status 200 assertions
    if [[ "$format" == "openai" ]]; then
        echo 'jsonpath "$.choices" exists'
    fi
    echo 'header "x-ai-provider" exists'

    # DLP assertions for requests carrying sensitive payloads
    if [[ "$dlp" != "disabled" && "$payload" != "clean" ]]; then
        case "$payload" in
            secrets)   echo 'body not contains "AKIAIOSFODNN7EXAMPLE"' ;;
            pii)       echo 'body not contains "4111111111111111"' ;;
            injection) echo 'body not contains "eyJhbGciOiJIUzI1NiI"' ;;
        esac
    fi
}

# Slug for filename
slug() {
    local auth="$1" provider="$2" dlp="$3" policy="$4" format="$5" payload="$6"
    # Shorten values for readable filenames
    local a="${auth/jwt_/}" p="${provider}" d="${dlp}" po="${policy}" f="${format}" pl="${payload}"
    echo "${a}-${p}-${d}-${po}-${f}-${pl}"
}

# ---------------------------------------------------------------------------
# Read the matrix and emit .hurl files
# ---------------------------------------------------------------------------
row=0
while IFS=$'\t' read -r auth provider dlp policy format payload; do
    # Skip the header row
    if [[ "$auth" == "Auth" ]]; then continue; fi

    row=$((row + 1))
    num=$(printf "%02d" "$row")

    status=$(expected_status "$auth" "$provider")
    name=$(slug "$auth" "$provider" "$dlp" "$policy" "$format" "$payload")
    file="${OUTPUT_DIR}/PW-${num}-${name}.hurl"

    jwt_var=$(jwt_variable "$auth" "$policy")
    endpoint=$(format_endpoint "$format")
    fixture=$(payload_fixture "$payload")
    auth_hdr=$(auth_header "$auth")

    {
        echo "# Pairwise: Auth=${auth}, Provider=${provider}, DLP=${dlp}, Policy=${policy}, Format=${format}, Payload=${payload}"

        # Request line
        echo "POST http://{{host}}${endpoint}"

        # Headers
        if [[ -n "$auth_hdr" ]]; then
            # Replace the generic variable with the correct one for this combination
            case "$auth" in
                jwt_valid)    echo "Authorization: Bearer {{${jwt_var}}}" ;;
                jwt_expired)  echo "Authorization: Bearer {{jwt_expired}}" ;;
                jwt_tampered) echo "Authorization: Bearer {{jwt_tampered}}" ;;
                api_key)      echo "X-Grob-API-Key: invalid-key" ;;
            esac
        fi
        echo "Content-Type: application/json"

        # Body
        echo "file,${fixture};"

        # Expected status
        echo "HTTP ${status}"

        # Assertions
        local asserts
        asserts=$(build_asserts "$status" "$auth" "$provider" "$dlp" "$format" "$payload")
        if [[ -n "$asserts" ]]; then
            echo "[Asserts]"
            echo "$asserts"
        fi
    } > "$file"

done < "${MATRIX_FILE}"

echo "-> Generated ${row} .hurl files in ${OUTPUT_DIR}/"
echo ""
echo "First 5 rows:"
head -6 "${MATRIX_FILE}" | column -t -s $'\t'
