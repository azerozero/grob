#!/usr/bin/env python3
"""Syntax-check published SDK and shell examples without executing their code."""

import ast
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PAGES = {
    "docs/examples/sdk-python.md": {"python", "bash"},
    "docs/examples/sdk-node.md": {"javascript", "bash"},
    "docs/tutorials/getting-started.md": {"bash"},
    "docs/how-to/providers.md": {"bash"},
}


def check_examples():
    checked = 0
    for relative, expected in PAGES.items():
        path = ROOT / relative
        language = None
        body = []
        found = set()
        start = 0
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if language is None:
                if line.startswith("```"):
                    language = line[3:].strip()
                    start = line_number + 1
                    body = []
                continue
            if line.strip() != "```":
                body.append(line)
                continue
            if language in expected:
                label = f"{relative}:{start} ({language})"
                source = "\n".join(body) + "\n"
                if not source.strip():
                    raise ValueError(f"{label}: empty example")
                if language == "python":
                    ast.parse(source, filename=label)
                else:
                    command = (
                        ["node", "--check", "--input-type=module"]
                        if language == "javascript"
                        else ["bash", "-n"]
                    )
                    result = subprocess.run(
                        command, input=source, text=True, capture_output=True,
                        timeout=15, check=False,
                    )
                    if result.returncode:
                        raise ValueError(f"{label}: {result.stderr.strip()}")
                print(f"OK {label}")
                found.add(language)
                checked += 1
            language = None
        if language is not None:
            raise ValueError(f"{relative}:{start}: unclosed code fence")
        if missing := expected - found:
            raise ValueError(f"{relative}: missing example languages: {sorted(missing)}")
    print(f"Checked {checked} examples; no SDK imports or commands executed.")


if __name__ == "__main__":
    check_examples()
