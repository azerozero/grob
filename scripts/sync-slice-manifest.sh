#!/usr/bin/env bash
# Regenerate the LOC and file counts in docs/slices/MANIFEST.md.
#
# Those columns were maintained by hand and had drifted badly (media was
# listed at 1.8k while holding 5.6k, routing at 3.9k while holding 6.3k).
# A number that is wrong is worth less than no number, so it is generated.
#
# Usage:
#   scripts/sync-slice-manifest.sh          # rewrite the manifest
#   scripts/sync-slice-manifest.sh --check  # exit 1 if stale (for CI)

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/docs/slices/MANIFEST.md"
check_only=false
[[ "${1:-}" == "--check" ]] && check_only=true

python3 - "$manifest" "$check_only" <<'PY'
import os
import re
import sys

manifest, check_only = sys.argv[1], sys.argv[2] == "true"
root = os.path.dirname(os.path.dirname(os.path.dirname(manifest)))


def count(directory):
    lines = files = 0
    for base, _, names in os.walk(directory):
        for name in names:
            if name.endswith(".rs"):
                files += 1
                with open(os.path.join(base, name), errors="ignore") as handle:
                    lines += sum(1 for _ in handle)
    return lines, files


with open(manifest) as handle:
    original = handle.read()


def row(match):
    slice_name, link = match.group(1), match.group(2)
    directory = os.path.normpath(os.path.join(os.path.dirname(manifest), os.path.dirname(link)))
    if not os.path.isdir(directory):
        return match.group(0)
    lines, files = count(directory)
    size = f"{lines / 1000:.1f}k" if lines >= 1000 else str(lines)
    return f"| [`{slice_name}`]({link}) | {size} | {files} |"


updated = re.sub(r"\| \[`([^`]+)`\]\(([^)]+)\) \| [\d.]+k? \| \d+ \|", row, original)

if check_only:
    if updated != original:
        print("docs/slices/MANIFEST.md is stale. Run scripts/sync-slice-manifest.sh", file=sys.stderr)
        sys.exit(1)
    print("docs/slices/MANIFEST.md is up to date")
    sys.exit(0)

if updated == original:
    print("docs/slices/MANIFEST.md already up to date")
else:
    with open(manifest, "w") as handle:
        handle.write(updated)
    print("docs/slices/MANIFEST.md regenerated")
PY
