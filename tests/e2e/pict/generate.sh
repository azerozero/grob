#!/usr/bin/env bash
set -euo pipefail

# Generates the pairwise test matrix from grob.pict using the PICT tool.
#
# Output: pict/grob-pairwise.txt
#
# Dependencies: pict (https://github.com/microsoft/pict)
#   macOS:  brew install pict
#   Linux:  build from source or download release binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_FILE="${SCRIPT_DIR}/grob.pict"
OUTPUT_FILE="${SCRIPT_DIR}/grob-pairwise.txt"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
if ! command -v pict &>/dev/null; then
    echo "ERROR: pict is not installed." >&2
    echo "  macOS:  brew install pict" >&2
    echo "  Linux:  https://github.com/microsoft/pict/releases" >&2
    exit 1
fi

echo "→ pict $(pict 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "(version unknown)")"

# ---------------------------------------------------------------------------
# Generate the matrix
# ---------------------------------------------------------------------------
echo "→ Generating pairwise matrix from ${MODEL_FILE}…"

pict "${MODEL_FILE}" > "${OUTPUT_FILE}"

# Count data rows (total lines minus the header line)
total_lines=$(wc -l < "${OUTPUT_FILE}")
case_count=$(( total_lines - 1 ))

echo ""
echo "✓ Pairwise matrix written to ${OUTPUT_FILE}"
echo "  Test cases generated: ${case_count}"
echo ""
echo "First 5 rows:"
head -6 "${OUTPUT_FILE}" | column -t -s $'\t'
