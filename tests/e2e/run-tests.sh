#!/usr/bin/env bash
set -euo pipefail

# Runs the e2e test suite inside the runner container, attached to the pod
# network so it can reach all services on 127.0.0.1.
#
# Usage:
#   ./run-tests.sh              # run all tests
#   ./run-tests.sh happy        # run only happy path
#   ./run-tests.sh auth fuzz    # run auth + fuzz suites

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="127.0.0.1:13456"

# Default: run all suites
SUITES=("${@:-happy fuzz secu budget cache circuit-breaker auth policies negative}")

# Read generated JWT tokens from the auth-init volume
# The runner mounts the e2e tree; tokens are in auth/tokens/
read_token() {
    podman exec e2e-pod-mock-jwks cat "/e2e-tokens/$1" 2>/dev/null || echo ""
}

echo "=== E2E Test Runner ==="
echo "  Pod:    e2e-pod"
echo "  Host:   ${HOST}"
echo "  Suites: ${SUITES[*]}"
echo ""

# Run hurl tests inside the runner container, sharing the pod network
podman run --rm \
    --pod e2e-pod \
    -v "${SCRIPT_DIR}:/e2e:z" \
    localhost/e2e-runner:latest \
    -c "
set -euo pipefail
cd /e2e

# Generate auth if tokens don't exist yet
if [[ ! -f auth/tokens/jwt-default.txt ]]; then
    echo '→ Generating auth fixtures…'
    bash auth/generate.sh
fi

# Read tokens
jwt_default=\$(cat auth/tokens/jwt-default.txt)
jwt_expired=\$(cat auth/tokens/jwt-expired.txt)
jwt_wrong_issuer=\$(cat auth/tokens/jwt-wrong-issuer.txt)
jwt_wrong_audience=\$(cat auth/tokens/jwt-wrong-audience.txt)
jwt_tampered=\$(cat auth/tokens/jwt-tampered.txt)
jwt_self_signed=\$(cat auth/tokens/jwt-self-signed.txt)
jwt_hospital_eu=\$(cat auth/tokens/jwt-hospital-eu.txt)
jwt_team_perf=\$(cat auth/tokens/jwt-team-perf.txt)
jwt_project_gdpr=\$(cat auth/tokens/jwt-project-gdpr.txt)

HOST='${HOST}'

for suite in ${SUITES[*]}; do
    echo ''
    echo \"=== Suite: \${suite} ===\"
    case \"\${suite}\" in
        happy)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/happy/*.hurl
            ;;
        fuzz)
            hurl --test --color --variable host=\${HOST} tests/fuzz/*.hurl
            ;;
        secu)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/secu/*.hurl
            ;;
        budget)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/budget/*.hurl
            ;;
        cache)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/cache/*.hurl
            ;;
        circuit-breaker)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/circuit-breaker/*.hurl
            ;;
        auth)
            hurl --test --color --variable host=\${HOST} \
                --variable jwt_default=\${jwt_default} \
                --variable jwt_expired=\${jwt_expired} \
                --variable jwt_wrong_issuer=\${jwt_wrong_issuer} \
                --variable jwt_wrong_audience=\${jwt_wrong_audience} \
                --variable jwt_tampered=\${jwt_tampered} \
                --variable jwt_self_signed=\${jwt_self_signed} \
                tests/auth/*.hurl
            ;;
        policies)
            hurl --test --color --variable host=\${HOST} \
                --variable jwt_hospital_eu=\${jwt_hospital_eu} \
                --variable jwt_team_perf=\${jwt_team_perf} \
                --variable jwt_project_gdpr=\${jwt_project_gdpr} \
                tests/policies/*.hurl
            ;;
        negative)
            hurl --test --color --variable host=\${HOST} --variable jwt=\${jwt_default} tests/negative/*.hurl
            ;;
        audit)
            bash tests/audit/run-audit-tests.sh
            ;;
        *)
            echo \"Unknown suite: \${suite}\"
            exit 1
            ;;
    esac
done

echo ''
echo '✓ All requested suites completed'
"
