#!/usr/bin/env bash
#
# Diff-based mutation testing for pull requests.
#
# Runs cargo-mutants on Rust files touched by the PR (vs. the base ref),
# capping wall-clock time at MUTATION_TIMEOUT_SECONDS so PR CI stays under
# the 30 min budget. Files outside the curated coverage list (router,
# dispatch, classify, dlp) are skipped — they were not part of the audited
# mutation scope.
#
# Usage: scripts/mutation-pr.sh [BASE_REF]
#   BASE_REF defaults to origin/main.
#
# Environment:
#   MUTATION_TIMEOUT_SECONDS  Hard wall-clock cap (default: 1500 = 25 min).
#   MUTATION_PER_MUTANT_TIMEOUT  cargo-mutants per-mutant timeout (default: 120).
#   GITHUB_OUTPUT             If set, writes status keys for the workflow.
#
# Exit codes:
#   0  Mutation testing converged within the time budget (clean run).
#   1  cargo-mutants reported surviving mutations or unexpected failure.
#   2  Time budget exhausted before convergence (PR is informational only).
#   3  No Rust files in scope — caller should skip the job.

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_REF="${1:-origin/main}"
readonly TIMEOUT_SECONDS="${MUTATION_TIMEOUT_SECONDS:-1500}"
readonly PER_MUTANT_TIMEOUT="${MUTATION_PER_MUTANT_TIMEOUT:-120}"

# Curated scope: files where we have invested in mutation coverage. Limiting
# the PR run to these paths keeps signal high (no false alarms from modules
# that have never been mutation-tested) and runtime bounded.
readonly -a SCOPE_PREFIXES=(
  "src/router/"
  "src/server/dispatch/"
  "src/routing/classify/"
  "src/features/dlp/"
)

log() { printf '[%s] %s\n' "${SCRIPT_NAME}" "$*" >&2; }

emit() {
  # Append "key=value" to GITHUB_OUTPUT when running inside Actions.
  local key="$1" value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "${key}" "${value}" >>"${GITHUB_OUTPUT}"
  fi
}

in_scope() {
  local file="$1" prefix
  for prefix in "${SCOPE_PREFIXES[@]}"; do
    [[ "${file}" == "${prefix}"* ]] && return 0
  done
  return 1
}

main() {
  log "Base ref: ${BASE_REF}"
  log "Wall-clock cap: ${TIMEOUT_SECONDS}s, per-mutant cap: ${PER_MUTANT_TIMEOUT}s"

  # Resolve the diff base. In CI we may need to fetch the base ref first.
  if ! git rev-parse --verify "${BASE_REF}" >/dev/null 2>&1; then
    log "Cannot resolve ${BASE_REF}; attempting fetch."
    git fetch --no-tags --depth=50 origin "${BASE_REF#origin/}" || true
  fi

  # `name-only` + `--diff-filter=ACMR` keeps Added/Copied/Modified/Renamed,
  # excludes Deleted (cargo-mutants can't mutate a file that was removed).
  local merge_base
  merge_base="$(git merge-base "${BASE_REF}" HEAD 2>/dev/null || echo "${BASE_REF}")"
  log "Merge base: ${merge_base}"

  # Filter by extension in shell rather than via pathspec — avoids relying
  # on `:(glob)` semantics that vary across git versions on different runners.
  # Path filter `-- src` keeps git's diff scoped to the source tree; the
  # `*.rs` suffix and `src/` prefix tests below ensure arbitrary nesting.
  local -a all_changed=()
  while IFS= read -r line; do
    [[ "${line}" == src/* && "${line}" == *.rs ]] || continue
    all_changed+=("${line}")
  done < <(git diff --name-only --diff-filter=ACMR "${merge_base}...HEAD" -- src || true)

  if [[ "${#all_changed[@]}" -eq 0 ]]; then
    log "No Rust source files changed vs. ${BASE_REF}."
    emit "status" "skipped-no-rust"
    exit 3
  fi

  log "Changed Rust files (${#all_changed[@]}):"
  printf '  - %s\n' "${all_changed[@]}" >&2

  local -a in_scope_files=()
  local f
  for f in "${all_changed[@]}"; do
    if in_scope "${f}"; then
      in_scope_files+=("${f}")
    fi
  done

  if [[ "${#in_scope_files[@]}" -eq 0 ]]; then
    log "No changed files fall within mutation-tested scope."
    emit "status" "skipped-out-of-scope"
    exit 3
  fi

  log "Files in mutation scope (${#in_scope_files[@]}):"
  printf '  - %s\n' "${in_scope_files[@]}" >&2

  # Build --file ARG for each in-scope file.
  local -a mutants_args=()
  for f in "${in_scope_files[@]}"; do
    mutants_args+=(--file "${f}")
  done

  local start_ts end_ts duration_s exit_code=0
  start_ts="$(date +%s)"

  # `timeout --foreground` so SIGTERM propagates to cargo-mutants and its
  # cargo subprocesses; `--preserve-status` so we can distinguish a real
  # cargo-mutants failure from the wall-clock kill.
  set +e
  timeout --foreground --preserve-status "${TIMEOUT_SECONDS}" \
    cargo mutants \
      --package grob \
      --timeout "${PER_MUTANT_TIMEOUT}" \
      -j 2 \
      --no-shuffle \
      --colors=never \
      "${mutants_args[@]}" \
      -- --lib
  exit_code=$?
  set -e

  end_ts="$(date +%s)"
  duration_s=$((end_ts - start_ts))
  log "cargo-mutants duration: ${duration_s}s, exit: ${exit_code}"

  # Parse a coarse summary from mutants.out/outcomes.json if produced.
  # cargo-mutants writes a single JSON document of shape {"outcomes": [...]}.
  # Each outcome carries a `summary` field with values CAUGHT, MISSED,
  # TIMEOUT, UNVIABLE, FAILURE, SUCCESS. We project on `summary` rather than
  # the top-level shape to stay forward-compatible.
  local total=0 caught=0 missed=0 timeout_n=0 unviable=0
  if [[ -r mutants.out/outcomes.json ]] && command -v jq >/dev/null 2>&1; then
    # `..` walks the entire tree to find every `summary` field, regardless
    # of whether outcomes are at the root or nested under `outcomes:`.
    total=$(jq '[.. | objects | select(has("summary"))] | length' mutants.out/outcomes.json 2>/dev/null || echo 0)
    caught=$(jq '[.. | objects | select(.summary == "CAUGHT")] | length' mutants.out/outcomes.json 2>/dev/null || echo 0)
    missed=$(jq '[.. | objects | select(.summary == "MISSED")] | length' mutants.out/outcomes.json 2>/dev/null || echo 0)
    timeout_n=$(jq '[.. | objects | select(.summary == "TIMEOUT")] | length' mutants.out/outcomes.json 2>/dev/null || echo 0)
    unviable=$(jq '[.. | objects | select(.summary == "UNVIABLE")] | length' mutants.out/outcomes.json 2>/dev/null || echo 0)
  fi

  emit "duration_s" "${duration_s}"
  emit "exit_code" "${exit_code}"
  emit "total" "${total}"
  emit "caught" "${caught}"
  emit "missed" "${missed}"
  emit "timeout" "${timeout_n}"
  emit "unviable" "${unviable}"

  # `timeout` exits 124 on SIGTERM, 137 on SIGKILL when --preserve-status is
  # absent; with --preserve-status, exit_code reflects cargo-mutants' last
  # state. We can't distinguish reliably — fall back on duration.
  if (( duration_s >= TIMEOUT_SECONDS - 5 )); then
    log "Wall-clock budget exhausted (${duration_s}s >= ${TIMEOUT_SECONDS}s)."
    emit "status" "timed-out"
    exit 2
  fi

  if (( exit_code == 0 )); then
    log "Mutation testing clean (caught=${caught}, total=${total})."
    emit "status" "clean"
    exit 0
  fi

  log "Mutation testing surfaced ${missed} missed mutant(s)."
  emit "status" "missed"
  exit 1
}

main "$@"
