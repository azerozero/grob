#!/usr/bin/env bash
set -euo pipefail

# Creates the 4-pane tmux layout and attaches.
# Called by run.sh (directly or via termtosvg).

SCENARIO="${1:?}"
VIEWER="${2:?}"
SESSION="grob-demo"

tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with top-left pane: grob logs
tmux new-session -d -s "$SESSION" -x 200 -y 50 \
    "echo -e '\033[1m\033[36m  grob server logs\033[0m'; echo ''; grob status 2>/dev/null; echo ''; tail -f ~/.grob/grob.log 2>/dev/null || watch -n1 'curl -sf http://127.0.0.1:13456/health | python3 -m json.tool 2>/dev/null'"

# Top-right: grob watch (TUI)
tmux split-window -h -t "$SESSION" \
    "sleep 1; grob watch 2>/dev/null || (echo -e '\033[33m  grob watch not available — showing health\033[0m'; watch -n2 'curl -sf http://127.0.0.1:13456/health | python3 -m json.tool 2>/dev/null')"

# Bottom-left: scenario script (agent → grob)
tmux split-window -v -t "$SESSION:0.0" \
    "bash $SCENARIO"

# Bottom-right: response viewer (grob → agent)
tmux split-window -v -t "$SESSION:0.1" \
    "bash $VIEWER"

# Balance panes
tmux select-layout -t "$SESSION" tiled

# Attach
tmux attach-session -t "$SESSION"
