#!/usr/bin/env bash
set -euo pipefail

# ╔════════════════════════════════════════════════════════════════╗
# ║  grob demo — "The proxy your AI doesn't know about"          ║
# ║                                                                ║
# ║  ┌──────────────────────┬──────────────────────┐              ║
# ║  │ 🎭 Claude Code       │ 🛡️ grob watch (TUI)  │              ║
# ║  │ (behind grob proxy)  │ DLP/routing/spend    │              ║
# ║  ├──────────────────────┼──────────────────────┤              ║
# ║  │ 📤 grob server logs  │ 📥 audit log (live)  │              ║
# ║  │ what happens inside  │ signed entries       │              ║
# ║  └──────────────────────┴──────────────────────┘              ║
# ║                                                                ║
# ║  Usage:  ./demo/run.sh                                        ║
# ║          ./demo/run.sh --record   (SVG via termtosvg)         ║
# ╚════════════════════════════════════════════════════════════════╝

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="grob-demo"
RECORD=false
[ "${1:-}" = "--record" ] && RECORD=true

for cmd in grob tmux claude; do
    command -v "$cmd" &>/dev/null || { echo "Missing: $cmd"; exit 1; }
done

tmux kill-session -t "$SESSION" 2>/dev/null || true
grob stop 2>/dev/null || true
sleep 1

# ── Pane 1 (top-left): Intro → Claude Code via grob ─────────────────
P1=$(mktemp /tmp/grob-demo-p1.XXXX.sh)
cat > "$P1" << 'EOF'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\n\033[1;38;5;51m'
printf '  ╔═══════════════════════════════════════════════════════════╗\n'
printf '  ║  grob — the proxy your AI doesn'"'"'t know about            ║\n'
printf '  ╠═══════════════════════════════════════════════════════════╣\n'
printf '  ║  🚨 March 24, 2026: LiteLLM PyPI supply chain attack     ║\n'
printf '  ║  500K+ exfiltrations. SSH, AWS, K8s creds harvested.     ║\n'
printf '  ║  pip install litellm = pip install malware               ║\n'
printf '  ║                                                           ║\n'
printf '  ║  brew install grob = 17MB static binary. No PyPI.       ║\n'
printf '  ╠═══════════════════════════════════════════════════════════╣\n'
printf '  ║  Try in Claude Code:                                      ║\n'
printf '  ║    • "My AWS key is AKIAIOSFODNN7EXAMPLE"                 ║\n'
printf '  ║    • "Card number 4532015112830366"                       ║\n'
printf '  ║    • "Token itk_AAAA...AAAA for internal API"            ║\n'
printf '  ║  Watch the other 3 panes light up.                       ║\n'
printf '  ╚═══════════════════════════════════════════════════════════╝\n'
printf '\033[0m\n'
printf '\033[1;38;5;46m  → Launching Claude Code behind grob...\033[0m\n\n'
sleep 3
exec grob exec --no-stop -- claude
EOF
chmod +x "$P1"

# ── Pane 2 (top-right): grob watch TUI ──────────────────────────────
P2=$(mktemp /tmp/grob-demo-p2.XXXX.sh)
cat > "$P2" << 'EOF'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;38;5;51m  🛡️  GROB WATCH — waiting for grob to start...\033[0m\n'
for i in $(seq 1 30); do
    curl -sf http://127.0.0.1:13456/health >/dev/null 2>&1 && break
    sleep 1
done
exec grob watch
EOF
chmod +x "$P2"

# ── Pane 3 (bottom-left): grob server logs ──────────────────────────
P3=$(mktemp /tmp/grob-demo-p3.XXXX.sh)
cat > "$P3" << 'EOF'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;38;5;208m  📤 GROB SERVER LOGS\033[0m\n'
printf '\033[38;5;245m  DLP actions, routing decisions, provider calls\033[0m\n\n'
# Wait for grob to create log file
LOG="$HOME/.grob/grob.log"
for i in $(seq 1 30); do
    [ -f "$LOG" ] && break
    sleep 1
done
if [ -f "$LOG" ]; then
    # Colorize DLP lines in red, routing in cyan, errors in yellow
    tail -f "$LOG" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -qi "dlp\|redact\|block\|canary"; then
            printf '\033[1;31m%s\033[0m\n' "$line"
        elif echo "$line" | grep -qi "route\|provider\|fallback"; then
            printf '\033[36m%s\033[0m\n' "$line"
        elif echo "$line" | grep -qi "error\|warn"; then
            printf '\033[33m%s\033[0m\n' "$line"
        else
            printf '\033[38;5;245m%s\033[0m\n' "$line"
        fi
    done
else
    printf '\033[38;5;245m  Waiting for grob log...\033[0m\n'
    while true; do [ -f "$LOG" ] && exec tail -f "$LOG"; sleep 2; done
fi
EOF
chmod +x "$P3"

# ── Pane 4 (bottom-right): audit log live ────────────────────────────
P4=$(mktemp /tmp/grob-demo-p4.XXXX.sh)
cat > "$P4" << 'EOF'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;38;5;46m  📥 AUDIT LOG — signed, hash-chained entries\033[0m\n'
printf '\033[38;5;245m  Each entry: ECDSA-P256 signed, classification NC/C1/C2/C3\033[0m\n\n'
# Find audit dir
for dir in "$HOME/.grob/audit" "/tmp/grob-audit"; do
    [ -d "$dir" ] && AUDIT_DIR="$dir" && break
done
if [ -z "${AUDIT_DIR:-}" ]; then
    printf '\033[38;5;245m  Waiting for audit directory...\033[0m\n'
    while true; do
        for dir in "$HOME/.grob/audit" "/tmp/grob-audit"; do
            [ -d "$dir" ] && AUDIT_DIR="$dir" && break 2
        done
        sleep 2
    done
fi
# Find or wait for the JSONL file
while true; do
    AUDIT_FILE=$(find "$AUDIT_DIR" -name "*.jsonl" 2>/dev/null | head -1)
    [ -n "$AUDIT_FILE" ] && break
    sleep 2
done
printf '\033[38;5;245m  Tailing %s\033[0m\n\n' "$AUDIT_FILE"
tail -f "$AUDIT_FILE" 2>/dev/null | while IFS= read -r line; do
    cls=$(echo "$line" | python3 -c "import json,sys; e=json.load(sys.stdin); print(e.get('classification','?'))" 2>/dev/null || echo "?")
    model=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('model_name','?')[:20])" 2>/dev/null || echo "?")
    dlp=$(echo "$line" | python3 -c "import json,sys; r=json.load(sys.stdin).get('dlp_rules_triggered',[]); print(' '.join(r) if r else '-')" 2>/dev/null || echo "-")
    ts=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('timestamp','?')[11:19])" 2>/dev/null || echo "?")
    if [ "$dlp" != "-" ]; then
        printf '\033[1;31m  %s  [%s]  %-20s  ⚠️  %s\033[0m\n' "$ts" "$cls" "$model" "$dlp"
    else
        printf '\033[32m  %s  [%s]  %-20s  ✓ clean\033[0m\n' "$ts" "$cls" "$model"
    fi
done
EOF
chmod +x "$P4"

# ── Build 4-pane tmux ────────────────────────────────────────────────
launch() {
    # Top-left: Claude Code
    tmux new-session -d -s "$SESSION" -x 200 -y 50 "bash $P1"
    # Top-right: grob watch
    tmux split-window -h -t "$SESSION:0.0" "bash $P2"
    # Bottom-left: server logs
    tmux split-window -v -t "$SESSION:0.0" "bash $P3"
    # Bottom-right: audit log
    tmux split-window -v -t "$SESSION:0.1" "bash $P4"
    # Focus Claude Code pane
    tmux select-pane -t "$SESSION:0.0"
    tmux attach-session -t "$SESSION"
}

printf '\033[1;38;5;51m  grob demo\033[0m — 4 panes, everything real\n'
printf '\033[38;5;245m'
printf '  ┌────────────────────┬────────────────────┐\n'
printf '  │ 🎭 Claude Code     │ 🛡️ grob watch      │\n'
printf '  │ (behind grob)      │ (TUI live)         │\n'
printf '  ├────────────────────┼────────────────────┤\n'
printf '  │ 📤 server logs     │ 📥 audit log       │\n'
printf '  │ (DLP, routing)     │ (signed entries)   │\n'
printf '  └────────────────────┴────────────────────┘\n'
printf '\033[0m\n'

sleep 1

if $RECORD; then
    echo "→ Recording to $DEMO_DIR/grob-demo.svg"
    termtosvg "$DEMO_DIR/grob-demo.svg" -c "bash -c '$(declare -f launch); P1=$P1 P2=$P2 P3=$P3 P4=$P4 SESSION=$SESSION launch'"
else
    launch
fi
