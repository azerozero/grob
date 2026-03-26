#!/usr/bin/env bash
set -euo pipefail

# ╔════════════════════════════════════════════════════════════════╗
# ║  grob demo — "The proxy your AI doesn't know about"          ║
# ║                                                                ║
# ║  Left:  Claude Code running through grob proxy                ║
# ║  Right: grob watch — real-time DLP, routing, spend            ║
# ║                                                                ║
# ║  Everything is real. No simulation. No fake requests.         ║
# ║  Use Claude Code normally — grob intercepts silently.         ║
# ║                                                                ║
# ║  Usage:  ./demo/run.sh                                        ║
# ║          ./demo/run.sh --record   (SVG via termtosvg)         ║
# ╚════════════════════════════════════════════════════════════════╝

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="grob-demo"
RECORD=false
[ "${1:-}" = "--record" ] && RECORD=true

# ── Preflight ────────────────────────────────────────────────────────────
for cmd in grob tmux claude; do
    command -v "$cmd" &>/dev/null || { echo "Missing: $cmd"; exit 1; }
done

# ── Stop old demo / grob ─────────────────────────────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true
grob stop 2>/dev/null || true
sleep 1

# ── Left pane: intro → grob exec -- claude ───────────────────────────────
LEFT=$(mktemp /tmp/grob-demo-left.XXXX.sh)
cat > "$LEFT" << 'LEFTSCRIPT'
#!/usr/bin/env bash
export TERM=xterm-256color
clear

# ── Intro ────────────────────────────────────────────────────────────
printf '\n'
printf '\033[1;38;5;51m'
printf '  ╔══════════════════════════════════════════════════════════════╗\n'
printf '  ║                                                              ║\n'
printf '  ║   grob — the proxy your AI doesn'"'"'t know about              ║\n'
printf '  ║                                                              ║\n'
printf '  ║   What you'"'"'re about to see:                                 ║\n'
printf '  ║   • Claude Code running behind grob (invisible proxy)       ║\n'
printf '  ║   • DLP scanning every prompt & response in real-time       ║\n'
printf '  ║   • Secrets redacted before they reach the LLM              ║\n'
printf '  ║   • Spend tracked per request, per model, per tenant        ║\n'
printf '  ║   • Signed audit log (ECDSA-P256, hash-chained)            ║\n'
printf '  ║                                                              ║\n'
printf '  ║   The AI has no idea. That'"'"'s the point.                    ║\n'
printf '  ║                                                              ║\n'
printf '  ╚══════════════════════════════════════════════════════════════╝\n'
printf '\033[0m\n'

sleep 2

printf '\033[1;38;5;208m'
printf '  ┌──────────────────────────────────────────────────────────────┐\n'
printf '  │  🚨 March 24, 2026: LiteLLM supply chain attack (TeamPCP)   │\n'
printf '  │  500K+ data exfiltrations via compromised PyPI package       │\n'
printf '  │  SSH keys, AWS creds, K8s secrets — all harvested            │\n'
printf '  │                                                               │\n'
printf '  │  pip install litellm  →  pip install malware                  │\n'
printf '  │  brew install grob    →  17MB static binary. No PyPI.        │\n'
printf '  └──────────────────────────────────────────────────────────────┘\n'
printf '\033[0m\n'

sleep 3

printf '\033[1;38;5;46m  → Launching Claude Code behind grob...\033[0m\n'
printf '\033[38;5;245m    All traffic proxied. DLP active. Audit signing.\033[0m\n'
printf '\033[38;5;245m    Try pasting secrets — watch the right pane.\033[0m\n\n'

sleep 2

# ── Launch Claude Code through grob ──────────────────────────────────
# --no-stop keeps grob running after claude exits (for continued demo)
exec grob exec --no-stop -- claude
LEFTSCRIPT
chmod +x "$LEFT"

# ── Right pane: grob watch ───────────────────────────────────────────
RIGHT=$(mktemp /tmp/grob-demo-right.XXXX.sh)
cat > "$RIGHT" << 'RIGHTSCRIPT'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;38;5;51m'
printf '  ╔════════════════════════════════════════════╗\n'
printf '  ║  🛡️  GROB CONTROL ROOM                     ║\n'
printf '  ║  real-time interception monitor            ║\n'
printf '  ╚════════════════════════════════════════════╝\n'
printf '\033[0m\n'
printf '\033[38;5;245m  Waiting for grob to start...\033[0m\n'

# Wait for grob to be healthy
for i in $(seq 1 30); do
    curl -sf http://127.0.0.1:13456/health >/dev/null 2>&1 && break
    sleep 1
done

# Launch grob watch (the TUI)
exec grob watch
RIGHTSCRIPT
chmod +x "$RIGHT"

# ── Build tmux session ───────────────────────────────────────────────
launch() {
    tmux new-session -d -s "$SESSION" -x 200 -y 50 "bash $LEFT"
    tmux split-window -h -t "$SESSION:0.0" "bash $RIGHT"
    # 60/40 split — more room for Claude Code on the left
    tmux resize-pane -t "$SESSION:0.0" -x 120
    tmux select-pane -t "$SESSION:0.0"
    tmux attach-session -t "$SESSION"
}

echo ""
printf '\033[1;38;5;51m  grob demo\033[0m — Claude Code + grob watch side by side\n'
printf '\033[38;5;245m  Left:  Claude Code (behind grob proxy)\n'
printf '  Right: grob watch (real-time DLP, routing, spend)\n\n'
printf '  Try these in Claude Code:\n'
printf '    • "My AWS key is AKIAIOSFODNN7EXAMPLE"\n'
printf '    • "Store credit card 4532015112830366"\n'
printf '    • "Use token itk_AAAA...AAAA for internal API"\n'
printf '  Watch the right pane light up.\033[0m\n\n'

sleep 2

if $RECORD; then
    echo "→ Recording to $DEMO_DIR/grob-demo.svg"
    termtosvg "$DEMO_DIR/grob-demo.svg" -c "bash -c '$(declare -f launch); LEFT=$LEFT RIGHT=$RIGHT SESSION=$SESSION launch'"
else
    launch
fi
