#!/usr/bin/env bash
# cleancode-audit.sh — Static clean code analysis for Rust projects.
# Generates a Markdown plan of violations to fix.
#
# Usage: ./scripts/cleancode-audit.sh [src_dir] [output_file]
#   src_dir     — directory to scan (default: src/)
#   output_file — markdown output (default: cleancode-plan.md)
#
# Rules covered (19):
#   Structure:  file length, items after test module
#   Functions:  function length, parameter count
#   Naming:     magic numbers
#   DRY:        (basic — repeated error patterns)
#   Error:      unwrap, expect, panic/unreachable, swallowed errors, poisoned locks
#   Idioms:     dead_code, clippy suppression, wildcard imports, &String/&Vec params
#   Tests:      missing test modules
#   Cognitive:  nesting depth
#   Docs:       missing pub doc comments
#   Markers:    TODO/FIXME/HACK

# Note: not using set -e because grep returns exit 1 on no matches,
# which is expected and frequent in an analysis script.
set -u

SRC_DIR="${1:-src}"
OUTPUT="${2:-cleancode-plan.md}"

# --- Thresholds ---
FILE_LINES_FLAG=500
FILE_LINES_CRITICAL=1000
FN_LINES_FLAG=80
FN_LINES_CRITICAL=120
FN_PARAMS_FLAG=5
FN_PARAMS_CRITICAL=7
NESTING_CRITICAL=5
NESTING_MIN_LINES=20
CLONE_DENSITY_FLAG=10

# --- Colors for terminal ---
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Counters ---
critical_count=0
flag_count=0
info_count=0

# --- Output buffer ---
declare -a criticals=()
declare -a flags=()
declare -a infos=()

add_critical() { criticals+=("$1"); critical_count=$((critical_count + 1)); }
add_flag()     { flags+=("$1");     flag_count=$((flag_count + 1)); }
add_info()     { infos+=("$1");     info_count=$((info_count + 1)); }

# --- Helpers ---
# Check if a line number is inside a #[cfg(test)] module
is_in_test() {
    local file="$1" line="$2"
    awk -v ln="$line" '
        /#\[cfg\(test\)\]/ { test_start = NR }
        NR == ln { if (test_start > 0 && NR > test_start) print "test"; else print "prod" }
    ' "$file" 2>/dev/null
}

# Trim leading whitespace from a string
trim_leading() { echo "${1#"${1%%[![:space:]]*}"}"; }

# Collect all Rust source files (exclude target/)
mapfile -t rust_files < <(find "$SRC_DIR" -name '*.rs' -not -path '*/target/*' | sort)
total_files=${#rust_files[@]}
total_lines=0

echo -e "${CYAN}Scanning ${total_files} files...${NC}"

# ============================================================
# Rule 1: File length (god modules)
# ============================================================
for f in "${rust_files[@]}"; do
    lines=$(wc -l < "$f" | tr -d ' ')
    total_lines=$((total_lines + lines))
    if (( lines > FILE_LINES_CRITICAL )); then
        add_critical "### STRUCTURE: \`${f}\` is ${lines} lines (god module)\n\n- **Threshold**: >${FILE_LINES_CRITICAL} lines (critical)\n- **Fix**: Split into sub-modules (e.g., \`types.rs\`, \`transform.rs\`, \`helpers.rs\`)\n"
    elif (( lines > FILE_LINES_FLAG )); then
        add_flag "### STRUCTURE: \`${f}\` is ${lines} lines\n\n- **Threshold**: >${FILE_LINES_FLAG} lines (flag)\n- **Fix**: Consider extracting helper modules if the file has multiple distinct responsibilities\n"
    fi
done

# ============================================================
# Rule 2: Function length (long functions)
# ============================================================
fn_results_file=$(mktemp)
for f in "${rust_files[@]}"; do
    awk '
    /^[[:space:]]*(pub(\(crate\))? )?(async )?fn [a-zA-Z_]/ {
        fn_sig = $0
        gsub(/^[[:space:]]+/, "", fn_sig)
        fn_start = NR
        brace_depth = 0
        started = 0
        fn_name = fn_sig
        sub(/.*fn /, "", fn_name)
        sub(/[^a-zA-Z0-9_].*/, "", fn_name)
    }
    fn_start > 0 {
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") { brace_depth++; started = 1 }
            if (c == "}") brace_depth--
        }
        if (started && brace_depth == 0) {
            fn_len = NR - fn_start + 1
            if (fn_len > '"$FN_LINES_FLAG"')
                printf "%s:%d:%d:%s\n", FILENAME, fn_start, fn_len, fn_name
            fn_start = 0
        }
    }
    ' "$f" 2>/dev/null
done > "$fn_results_file"

while IFS=: read -r file line len name; do
    # Skip test functions — they are often long due to setup/assertions
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" == "test" ]]; then continue; fi
    if (( len > FN_LINES_CRITICAL )); then
        add_critical "### FUNCTIONS: \`${name}\` is ${len} lines in \`${file}:${line}\`\n\n- **Threshold**: >${FN_LINES_CRITICAL} lines (critical)\n- **Fix**: Extract helper methods to bring under ${FN_LINES_FLAG} lines\n"
    else
        add_flag "### FUNCTIONS: \`${name}\` is ${len} lines in \`${file}:${line}\`\n\n- **Threshold**: >${FN_LINES_FLAG} lines (flag)\n- **Fix**: Consider extracting sub-operations into focused helper functions\n"
    fi
done < "$fn_results_file"
rm -f "$fn_results_file"

# ============================================================
# Rule 3: Function parameter count (too_many_arguments)
# ============================================================
param_results_file=$(mktemp)
for f in "${rust_files[@]}"; do
    # Use awk to extract fn signatures, join multiline, count params
    awk '
    /^[[:space:]]*(pub(\(crate\))? )?(async )?fn [a-zA-Z_]/ {
        fn_sig = ""
        fn_line = NR
        fn_name = $0
        sub(/.*fn /, "", fn_name)
        sub(/[^a-zA-Z0-9_].*/, "", fn_name)
        depth = 0
        collecting = 1
    }
    collecting {
        fn_sig = fn_sig $0
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (c == "(") depth++
            if (c == ")") {
                depth--
                if (depth == 0) {
                    collecting = 0
                    # Remove &self/&mut self/self
                    gsub(/&mut self,?/, "", fn_sig)
                    gsub(/&self,?/, "", fn_sig)
                    gsub(/self,?/, "", fn_sig)
                    # Extract content between parens
                    sub(/.*\(/, "", fn_sig)
                    sub(/\).*/, "", fn_sig)
                    # Remove whitespace-only
                    gsub(/^[[:space:]]+$/, "", fn_sig)
                    if (fn_sig != "") {
                        # Count commas + 1 = param count
                        n = gsub(/,/, ",", fn_sig) + 1
                        if (n > '"$FN_PARAMS_FLAG"')
                            printf "%s:%d:%d:%s\n", FILENAME, fn_line, n, fn_name
                    }
                    break
                }
            }
        }
    }
    ' "$f" 2>/dev/null
done > "$param_results_file"

while IFS=: read -r file line count name; do
    if (( count >= FN_PARAMS_CRITICAL )); then
        add_critical "### FUNCTIONS: \`${name}\` has ${count} parameters in \`${file}:${line}\`\n\n- **Threshold**: >=${FN_PARAMS_CRITICAL} params (critical)\n- **Fix**: Group related params into a context/config struct\n"
    else
        add_flag "### FUNCTIONS: \`${name}\` has ${count} parameters in \`${file}:${line}\`\n\n- **Threshold**: >${FN_PARAMS_FLAG} params (flag)\n- **Fix**: Consider grouping related params into a struct\n"
    fi
done < "$param_results_file"
rm -f "$param_results_file"

# ============================================================
# Rule 4: #[allow(dead_code)] without justification
# ============================================================
while IFS=: read -r file line content; do
    # Check 5 lines above for a justifying comment
    start=$((line - 5))
    if (( start < 1 )); then start=1; fi
    has_reason=$(sed -n "${start},$((line - 1))p" "$file" 2>/dev/null | grep -cE '//.*([Rr]eason|[Dd]eserializ|[Ss]erde|[Pp]ublic API|[Uu]sed by|[Nn]eeded)') || has_reason=0
    if (( has_reason == 0 )); then
        trimmed=$(trim_leading "$content")
        add_flag "### RUST IDIOMS: Unjustified \`#[allow(dead_code)]\` in \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Remove the annotation (delete dead code) or add a \`// Reason: ...\` comment above\n"
    fi
done < <(grep -rn '#\[allow(dead_code)\]' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)

# ============================================================
# Rule 5: .unwrap() in non-test production code
# Improved: whitelist Mutex/RwLock, LazyLock, const/static patterns
# ============================================================
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        # Whitelist legitimate patterns
        if echo "$content" | grep -qE 'LazyLock|Regex::new|static\b|const\b|\.lock\(\)\.unwrap|\.read\(\)\.unwrap|\.write\(\)\.unwrap|unwrap_or_else\(|into_inner'; then
            continue
        fi
        trimmed=$(trim_leading "$content")
        add_flag "### ERROR HANDLING: \`.unwrap()\` in production code at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Replace with \`?\`, \`.expect(\"reason\")\`, or \`.unwrap_or_default()\`\n"
    fi
done < <(grep -rn '\.unwrap()' "$SRC_DIR" --include='*.rs' 2>/dev/null | grep -v '// unwrap: ' || true)

# ============================================================
# Rule 6: .expect() in handler/server code (potential panics)
# ============================================================
while IFS=: read -r file line content; do
    if echo "$file" | grep -qE 'server/|handler'; then
        in_test=$(is_in_test "$file" "$line")
        if [[ "$in_test" != "test" ]]; then
            trimmed=$(trim_leading "$content")
            add_info "### ERROR HANDLING: \`.expect()\` in server code at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Consider using \`?\` or \`.map_err()\` to avoid panics in request handlers\n"
        fi
    fi
done < <(grep -rn '\.expect(' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)

# ============================================================
# Rule 7: panic!/unreachable! in non-test code
# ============================================================
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        # Skip comments
        if echo "$content" | grep -qE '^\s*//'; then
            continue
        fi
        trimmed=$(trim_leading "$content")
        add_flag "### ERROR HANDLING: \`panic!\`/\`unreachable!\` in production code at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Return a \`Result\` or use \`.expect()\` with a meaningful message\n"
    fi
done < <(grep -rn -E '\b(panic!|unreachable!)\b' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)

# ============================================================
# Rule 8: Swallowed errors (let _ = expr returning Result)
# ============================================================
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        trimmed=$(trim_leading "$content")
        add_info "### ERROR HANDLING: Swallowed Result with \`let _ =\` at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Handle the error or add a comment explaining why it's safe to ignore\n"
    fi
done < <(grep -rn 'let _ =' "$SRC_DIR" --include='*.rs' 2>/dev/null | grep -vE '^\s*//' || true)

# ============================================================
# Rule 9: Poisoned lock recovery without logging
# ============================================================
while IFS=: read -r file line content; do
    # Check if there's a tracing/log call nearby
    nearby_log=$(awk -v ln="$line" '
        NR >= ln-2 && NR <= ln+2 { if (/tracing::|log::|warn!|error!/) found=1 }
        END { print found+0 }
    ' "$file" 2>/dev/null)
    if (( nearby_log == 0 )); then
        add_info "### ERROR HANDLING: Poisoned lock silently recovered at \`${file}:${line}\`\n\n- **Fix**: Add \`tracing::warn!(\"Lock poisoned, recovering\")\` before recovery\n"
    fi
done < <(grep -rn 'into_inner()' "$SRC_DIR" --include='*.rs' 2>/dev/null | grep -E 'unwrap_or_else' || true)

# ============================================================
# Rule 10: Magic numbers (improved filtering)
# ============================================================
magic_count=0
magic_examples=""
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        # Skip const/static, comments, common framework patterns
        if echo "$content" | grep -qE '^\s*(pub\s+)?(const|static)\b|^\s*//|Duration|timeout|port|capacity|status|version|\.len\(\)|max_|min_|default_|size|width|height|level|#\[|assert|"[^"]*"|serde|clap|derive'; then
            continue
        fi
        magic_count=$((magic_count + 1))
        if (( magic_count <= 5 )); then
            trimmed=$(trim_leading "$content")
            magic_examples="${magic_examples}  - \`${file}:${line}\`: \`${trimmed}\`\n"
        fi
    fi
done < <(grep -rn -E '\b[0-9]{3,}\b' "$SRC_DIR" --include='*.rs' 2>/dev/null | grep -vE 'const |static |test|assert|#\[|"[^"]*[0-9]|0x[0-9a-fA-F]|port|0o[0-7]|0b[01]' || true)
if (( magic_count > 3 )); then
    add_info "### NAMING: ${magic_count} potential magic numbers found in production code\n\n- **Examples**:\n${magic_examples}- **Fix**: Extract into named constants\n"
fi

# ============================================================
# Rule 11: .clone() density per file
# ============================================================
for f in "${rust_files[@]}"; do
    clone_count=$(grep -c '\.clone()' "$f" 2>/dev/null) || clone_count=0
    if (( clone_count > CLONE_DENSITY_FLAG )); then
        lines=$(wc -l < "$f" | tr -d ' ')
        density=$(( (clone_count * 1000) / lines ))
        add_info "### RUST IDIOMS: ${clone_count} \`.clone()\` calls in \`${f}\` (${lines} lines, ${density}/1000 density)\n\n- **Fix**: Review if any clones can be replaced with references or \`Cow<str>\`\n"
    fi
done

# ============================================================
# Rule 12: Nesting depth (improved — skip closing braces, comments, blank lines)
# ============================================================
for f in "${rust_files[@]}"; do
    deep_lines=$(awk '
    /^[[:space:]]*\/\// { next }
    /#\[cfg\(test\)\]/ { exit }
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*[\}\)\]\,]/ { next }
    /^[[:space:]]*\./ { next }
    {
        match($0, /^[[:space:]]*/);
        indent = RLENGTH;
        depth = int(indent / 4);
        if (depth >= '"$NESTING_CRITICAL"') count++
    }
    END { print count+0 }
    ' "$f" 2>/dev/null)
    if (( deep_lines > NESTING_MIN_LINES )); then
        add_flag "### COGNITIVE LOAD: ${deep_lines} deeply nested lines (depth>=${NESTING_CRITICAL}) in \`${f}\`\n\n- **Fix**: Use guard clauses, extract helper functions, or early returns to flatten nesting\n"
    fi
done

# ============================================================
# Rule 13: #[allow(clippy::*)] without justification
# ============================================================
while IFS=: read -r file line content; do
    start=$((line - 3))
    if (( start < 1 )); then start=1; fi
    has_reason=$(sed -n "${start},$((line - 1))p" "$file" 2>/dev/null | grep -cE '//.*([Rr]eason|[Bb]ecause|[Ii]ntentional|[Rr]equired|[Nn]ecessary)') || has_reason=0
    if (( has_reason == 0 )); then
        trimmed=$(trim_leading "$content")
        add_info "### RUST IDIOMS: Unjustified clippy suppression at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Add a \`// Reason: ...\` comment or fix the underlying lint\n"
    fi
done < <(grep -rn '#\[allow(clippy::' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)

# ============================================================
# Rule 14: Items after test module
# Improved: also detects impl blocks, constants, type aliases
# ============================================================
for f in "${rust_files[@]}"; do
    test_mod_line=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | tail -1 | cut -d: -f1 || true)
    if [[ -n "$test_mod_line" ]]; then
        after_test=$(awk -v start="$test_mod_line" '
        NR > start {
            if (/^(pub(\(crate\))? )?(async )?fn [a-zA-Z_]/ && !/test/) { found++; items = items NR": "$0"\n" }
            if (/^(pub(\(crate\))? )?impl\s/ && !/test/) { found++; items = items NR": "$0"\n" }
            if (/^(pub(\(crate\))? )?(const|static|type)\s/ && !/test/) { found++; items = items NR": "$0"\n" }
        }
        END { if (found > 0) print found }
        ' "$f" 2>/dev/null)
        if [[ -n "$after_test" ]]; then
            add_flag "### RUST IDIOMS: ${after_test} item(s) after test module in \`${f}\`\n\n- **Fix**: Move production code above \`#[cfg(test)] mod tests\`\n"
        fi
    fi
done

# ============================================================
# Rule 15: Test coverage gaps (files with >200 lines and no #[cfg(test)])
# ============================================================
for f in "${rust_files[@]}"; do
    # Skip mod.rs files that are just re-exports
    if [[ "$f" == */mod.rs ]]; then
        has_reexport=$(grep -c 'pub mod\|pub use' "$f" 2>/dev/null) || has_reexport=0
        actual_code=$(grep -cvE '^\s*(pub mod|pub use|mod |use |//|$)' "$f" 2>/dev/null) || actual_code=0
        if (( has_reexport > 0 && actual_code < 50 )); then
            continue
        fi
    fi
    lines=$(wc -l < "$f" | tr -d ' ')
    if (( lines > 200 )); then
        has_tests=$(grep -c '#\[cfg(test)\]' "$f" 2>/dev/null) || has_tests=0
        if (( has_tests == 0 )); then
            add_info "### TESTS: No tests in \`${f}\` (${lines} lines)\n\n- **Fix**: Add unit tests for key functions, especially error paths\n"
        fi
    fi
done

# ============================================================
# Rule 16: Wildcard imports (use foo::*;)
# ============================================================
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        # Skip prelude imports (acceptable pattern)
        if echo "$content" | grep -qE 'prelude::\*'; then
            continue
        fi
        trimmed=$(trim_leading "$content")
        add_flag "### RUST IDIOMS: Wildcard import at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Import specific items instead of \`*\` to avoid namespace pollution\n"
    fi
done < <(grep -rn 'use .*::\*;' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)

# ============================================================
# Rule 17: Missing doc comments on pub items
# ============================================================
pub_missing=0
pub_examples=""
for f in "${rust_files[@]}"; do
    # Find pub struct/enum/trait/fn without /// above
    while IFS=: read -r line content; do
        in_test=$(is_in_test "$f" "$line")
        if [[ "$in_test" == "test" ]]; then continue; fi

        prev=$((line - 1))
        has_doc=$(sed -n "${prev}p" "$f" 2>/dev/null | grep -c '///\|/\*\*\|#\[doc') || has_doc=0
        if (( has_doc == 0 )); then
            pub_missing=$((pub_missing + 1))
            if (( pub_missing <= 5 )); then
                trimmed=$(trim_leading "$content")
                pub_examples="${pub_examples}  - \`${f}:${line}\`: \`${trimmed}\`\n"
            fi
        fi
    done < <(grep -n -E '^\s*pub (struct|enum|trait|fn) ' "$f" 2>/dev/null | grep -vE 'pub\(crate\)' || true)
done
if (( pub_missing > 5 )); then
    add_flag "### DOCS: ${pub_missing} public items missing doc comments (\`///\`)\n\n- **Examples**:\n${pub_examples}- **Fix**: Add \`///\` documentation to public API surface\n"
elif (( pub_missing > 0 )); then
    add_info "### DOCS: ${pub_missing} public items missing doc comments (\`///\`)\n\n- **Examples**:\n${pub_examples}- **Fix**: Add \`///\` documentation to public API surface\n"
fi

# ============================================================
# Rule 18: TODO/FIXME/HACK markers
# ============================================================
marker_count=0
marker_examples=""
while IFS=: read -r file line content; do
    marker_count=$((marker_count + 1))
    if (( marker_count <= 5 )); then
        trimmed=$(trim_leading "$content")
        marker_examples="${marker_examples}  - \`${file}:${line}\`: \`${trimmed}\`\n"
    fi
done < <(grep -rn -E '\b(TODO|FIXME|HACK|XXX)\b' "$SRC_DIR" --include='*.rs' 2>/dev/null || true)
if (( marker_count > 0 )); then
    add_info "### MARKERS: ${marker_count} TODO/FIXME/HACK marker(s) found\n\n${marker_examples}- **Fix**: Resolve or create issues for tracked items, then remove markers\n"
fi

# ============================================================
# Rule 19: &String / &Vec<T> parameter anti-patterns
# ============================================================
while IFS=: read -r file line content; do
    in_test=$(is_in_test "$file" "$line")
    if [[ "$in_test" != "test" ]]; then
        trimmed=$(trim_leading "$content")
        add_flag "### RUST IDIOMS: \`&String\`/\`&Vec\` parameter at \`${file}:${line}\`\n\n- **What**: \`${trimmed}\`\n- **Fix**: Use \`&str\` instead of \`&String\`, \`&[T]\` instead of \`&Vec<T>\`\n"
    fi
done < <(grep -rn -E '&String\b|&Vec<' "$SRC_DIR" --include='*.rs' 2>/dev/null | grep -E 'fn |:\s*&' || true)

# ============================================================
# Generate Markdown Report
# ============================================================

# Calculate score (density-based)
# Score = 10 - penalty, where penalty scales with violations per 1000 lines
# Critical = 0.3 per KLOC, Flag = 0.05 per KLOC, floored at 1.0
score=$(LC_NUMERIC=C awk -v tl="$total_lines" -v cc="$critical_count" -v fc="$flag_count" '
    BEGIN {
        kloc = tl / 1000.0
        if (kloc < 1) kloc = 1
        penalty = (cc * 0.3 + fc * 0.05) / kloc
        s = 10.0 - penalty
        if (s < 1) s = 1
        printf "%.1f", s
    }')

cat > "$OUTPUT" <<HEADER
# Clean Code Audit Plan

**Generated**: $(date +%Y-%m-%d\ %H:%M)
**Source**: \`${SRC_DIR}/\` (${total_files} files, ${total_lines} lines)
**Score**: ${score}/10

| Severity | Count |
|----------|-------|
| Critical | ${critical_count} |
| Flag     | ${flag_count} |
| Info     | ${info_count} |

---

HEADER

if (( critical_count > 0 )); then
    echo "## Critical Violations (must fix)" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    for item in "${criticals[@]}"; do
        echo -e "$item" >> "$OUTPUT"
    done
fi

if (( flag_count > 0 )); then
    echo "## Flags (should fix)" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    for item in "${flags[@]}"; do
        echo -e "$item" >> "$OUTPUT"
    done
fi

if (( info_count > 0 )); then
    echo "## Info (consider)" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    for item in "${infos[@]}"; do
        echo -e "$item" >> "$OUTPUT"
    done
fi

cat >> "$OUTPUT" <<FOOTER

---

## Rules Checked (19)

| # | Rule | Severity | Category |
|---|------|----------|----------|
| 1 | File length (>500/1000 lines) | Flag/Critical | Structure |
| 2 | Function length (>80/120 lines) | Flag/Critical | Functions |
| 3 | Function parameter count (>5/7) | Flag/Critical | Functions |
| 4 | \`#[allow(dead_code)]\` unjustified | Flag | Rust Idioms |
| 5 | \`.unwrap()\` in production code | Flag | Error Handling |
| 6 | \`.expect()\` in server/handler code | Info | Error Handling |
| 7 | \`panic!\`/\`unreachable!\` in production | Flag | Error Handling |
| 8 | Swallowed errors (\`let _ =\`) | Info | Error Handling |
| 9 | Poisoned lock recovery (no log) | Info | Error Handling |
| 10 | Magic numbers (3+ digit literals) | Info | Naming |
| 11 | \`.clone()\` density per file | Info | Rust Idioms |
| 12 | Deep nesting (depth >= 5) | Flag | Cognitive Load |
| 13 | \`#[allow(clippy::*)]\` unjustified | Info | Rust Idioms |
| 14 | Items after \`#[cfg(test)]\` module | Flag | Rust Idioms |
| 15 | Missing test modules (>200 lines) | Info | Tests |
| 16 | Wildcard imports (\`use foo::*\`) | Flag | Rust Idioms |
| 17 | Missing \`///\` doc on pub items | Flag/Info | Documentation |
| 18 | TODO/FIXME/HACK markers | Info | Markers |
| 19 | \`&String\`/\`&Vec<T>\` parameters | Flag | Rust Idioms |

## How to Use This Plan

1. Fix all **Critical** violations first
2. Address **Flags** in priority order (structure > functions > error handling > idioms)
3. Review **Info** items where effort/benefit is favorable
4. Re-run: \`./scripts/cleancode-audit.sh\`

> Static analysis covers ~70% of clean code rules. For contextual analysis
> (naming quality, DRY violations, architectural judgment), use \`/cleancode\`.
FOOTER

# --- Terminal summary ---
echo ""
echo "========================================"
echo "  Clean Code Audit Complete"
echo "========================================"
echo -e "  Files scanned:  ${total_files}"
echo -e "  Total lines:    ${total_lines}"
echo -e "  ${RED}Critical:       ${critical_count}${NC}"
echo -e "  ${YELLOW}Flags:          ${flag_count}${NC}"
echo -e "  ${GREEN}Info:           ${info_count}${NC}"
echo -e "  ${CYAN}Score:          ${score}/10${NC}"
echo "========================================"
echo "  Plan written to: ${OUTPUT}"
echo "========================================"
