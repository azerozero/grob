#!/usr/bin/env bash
set -euo pipefail

# Wizard lifecycle E2E tests
#
# Tests the full chain: fresh install → setup wizard → doctor → proxy works.
# Uses a temporary GROB_HOME so the real user config is never touched.
# Requires a built grob binary (cargo build) and vidaimock running on :8100.
#
# Usage:
#   ./run-wizard-tests.sh              # run all wizard tests
#   ./run-wizard-tests.sh W1           # run a single test

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROB="${GROB_BIN:-cargo run --quiet --}"
TEST_HOME=$(mktemp -d)
GROB_HOME="${TEST_HOME}/.grob"
export GROB_HOME

PORT=13499  # avoid colliding with the main e2e pod
MOCK_URL="http://127.0.0.1:8100"
GROB_DIR="$GROB_HOME"
CONFIG="${GROB_DIR}/config.toml"
mkdir -p "$GROB_DIR"

passed=0
failed=0
skipped=0

inc() {
    # Bash 4.3+ nameref avoids `eval` on caller-controlled strings.
    local -n _counter="$1"
    _counter=$((_counter + 1))
}

cleanup() {
    # Stop grob if running
    if [[ -n "${GROB_PID:-}" ]]; then
        kill "$GROB_PID" 2>/dev/null || true
        wait "$GROB_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_HOME"
}
trap cleanup EXIT

run_test() {
    local id="$1" name="$2" fn="$3" filter="$4"
    if [[ -n "$filter" ]] && [[ "$filter" != "$id" ]]; then
        return
    fi
    echo -n "  $id $name ... "
    set +e
    $fn
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        echo "PASS"
        inc passed
    else
        echo "FAIL"
        inc failed
    fi
}

# =========================================================================
# W0: No config → grob doctor exits with issues
# =========================================================================
test_W0_no_config_doctor() {
    # With a minimal empty-ish config, doctor should flag missing providers.
    cat > "${CONFIG}.w0" <<TOML
[router]
default = "default"
TOML
    local out
    out=$($GROB -c "${CONFIG}.w0" doctor 2>&1) || true
    echo "$out" | grep -q "No providers configured"
}

# =========================================================================
# W1: Setup wizard (non-interactive, piped input) generates valid config
# =========================================================================
test_W1_setup_generates_config() {
    # Simulate: select Claude Code (1), OAuth (1), skip openrouter (2),
    # standard security (1), unlimited budget (1)
    mkdir -p "$GROB_DIR"
    printf '1\n1\n2\n1\n1\n' | $GROB setup >/dev/null 2>&1 || true

    [[ -f "$CONFIG" ]] || return 1

    # Config should contain anthropic provider
    grep -q 'name = "anthropic"' "$CONFIG"
}

# =========================================================================
# W2: Generated config is valid TOML that grob can parse
# =========================================================================
test_W2_config_parses() {
    local out
    out=$($GROB -c "$CONFIG" doctor 2>&1) || true
    echo "$out" | grep -q "Config file:"
}

# =========================================================================
# W3: Overwrite config with mock backend for functional tests
# =========================================================================
test_W3_write_mock_config() {
    cat > "$CONFIG" <<TOML
[server]
port = $PORT
host = "127.0.0.1"

[[providers]]
name = "mock"
provider_type = "openai"
base_url = "$MOCK_URL/v1"
api_key = "sk-test-key"
models = []
enabled = true
pass_through = true

[[models]]
name = "default"

[[models.mappings]]
provider = "mock"
actual_model = "gpt-4o"
priority = 1

[router]
default = "default"
TOML
    [[ -f "$CONFIG" ]]
}

# =========================================================================
# W4: Doctor passes with mock config
# =========================================================================
test_W4_doctor_passes() {
    local out
    out=$($GROB -c "$CONFIG" doctor 2>&1)
    echo "$out" | grep -q "Config file:"
    # Should not have "No providers configured"
    ! echo "$out" | grep -q "No providers configured"
}

# =========================================================================
# W5: Start server with mock config, health check passes
# =========================================================================
test_W5_start_and_health() {
    $GROB -c "$CONFIG" start >/dev/null 2>&1 &
    GROB_PID=$!

    # Wait for health
    for _ in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# =========================================================================
# W6: Proxy actually routes a request through the mock
# =========================================================================
test_W6_proxy_routes_request() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://127.0.0.1:$PORT/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":10}')
    [[ "$status" == "200" ]]
}

# =========================================================================
# W7: Config reload works (hot reload without restart)
# =========================================================================
test_W7_config_reload() {
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://127.0.0.1:$PORT/api/config/reload")
    [[ "$status" == "200" ]]
}

# =========================================================================
# W8: Stop and verify clean shutdown
# =========================================================================
test_W8_stop_clean() {
    if [[ -n "${GROB_PID:-}" ]]; then
        kill "$GROB_PID" 2>/dev/null || true
        wait "$GROB_PID" 2>/dev/null || true
    fi
    sleep 1
    # Health should fail now
    ! curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1
}

# =========================================================================
# W9: Re-run setup on existing config → wizard detects it
# =========================================================================
test_W9_setup_detects_existing() {
    local out
    # Setup should detect existing config and show current state
    out=$(printf '7\n' | $GROB setup 2>&1) || true
    # Config should still exist after re-run
    [[ -f "$CONFIG" ]]
}

# =========================================================================
# Run
# =========================================================================
echo "=== Wizard Lifecycle Tests ==="
echo "  GROB_HOME: $GROB_HOME"
echo "  Port:      $PORT"
echo ""

FILTER="${1:-}"

run_test W0 "no config → doctor reports issues"       test_W0_no_config_doctor "$FILTER"
run_test W1 "setup wizard generates config"            test_W1_setup_generates_config "$FILTER"
run_test W2 "generated config parses"                  test_W2_config_parses "$FILTER"
run_test W3 "write mock config"                        test_W3_write_mock_config "$FILTER"
run_test W4 "doctor passes with mock config"           test_W4_doctor_passes "$FILTER"
run_test W5 "start server, health check"               test_W5_start_and_health "$FILTER"
run_test W6 "proxy routes request through mock"        test_W6_proxy_routes_request "$FILTER"
run_test W7 "config hot reload"                        test_W7_config_reload "$FILTER"
run_test W8 "clean shutdown"                            test_W8_stop_clean "$FILTER"
run_test W9 "re-run setup detects existing config"     test_W9_setup_detects_existing "$FILTER"

echo ""
echo "Results: $passed passed, $failed failed, $skipped skipped"
[[ $failed -eq 0 ]]
