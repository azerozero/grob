#!/usr/bin/env bash
set -euo pipefail

# ╔════════════════════════════════════════════════════════════════╗
# ║  grob demo — "The Heist That Never Happened"                 ║
# ║                                                                ║
# ║  A malicious agent tries to exfiltrate secrets.               ║
# ║  grob catches everything. The agent never knows.              ║
# ║  At the end: Claude Code takes over. Your turn.               ║
# ║                                                                ║
# ║  Usage:  ./demo/run.sh                                        ║
# ║          ./demo/run.sh --record   (SVG via termtosvg)         ║
# ╚════════════════════════════════════════════════════════════════╝

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/.." && pwd)"
SESSION="grob-demo"
RECORD=false
[ "${1:-}" = "--record" ] && RECORD=true

# ── Preflight ────────────────────────────────────────────────────────────
for cmd in tmux curl python3; do
    command -v "$cmd" &>/dev/null || { echo "Missing: $cmd"; exit 1; }
done

HOST="http://127.0.0.1:13456"
if ! curl -sf "$HOST/health" >/dev/null 2>&1; then
    echo "grob not running on :13456. Start it or the e2e pod first."
    exit 1
fi

# Auto-detect auth token
JWT=""
for f in "$REPO_ROOT/tests/e2e/auth/tokens/jwt-default.txt" "/e2e/auth/tokens/jwt-default.txt"; do
    [ -f "$f" ] && JWT=$(cat "$f") && break
done
AUTH_HEADER="Authorization: Bearer ${JWT:-demo}"

# ── Write pane scripts to temp files ─────────────────────────────────────

# ▸ PANE 1 (top-left): GROB CONTROL ROOM — live health + DLP events
P1=$(mktemp /tmp/grob-demo-p1.XXXX.sh); cat > "$P1" << 'P1SCRIPT'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;48;5;17;38;5;51m'
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  🛡️  GROB CONTROL ROOM                       ║"
echo "  ║  real-time monitoring                        ║"
echo "  ╚══════════════════════════════════════════════╝"
printf '\033[0m\n'
grob watch 2>/dev/null || {
    echo ""
    printf '\033[38;5;245m  grob watch not available — live health:\033[0m\n\n'
    watch -n1 -c 'curl -sf http://127.0.0.1:13456/health 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d[\"spend\"]
print(f\"  Status:  \033[32m{d[\"status\"]}\033[0m\")
print(f\"  Spend:   \033[33m\${s[\"total_usd\"]:.4f} / \${s[\"budget_usd\"]:.0f} USD\033[0m\")
print(f\"  Active:  {d[\"active_requests\"]}\")
" 2>/dev/null || echo "  waiting..."'
}
P1SCRIPT
chmod +x "$P1"

# ▸ PANE 2 (top-right): WHAT THE LLM ACTUALLY RECEIVES
P2=$(mktemp /tmp/grob-demo-p2.XXXX.sh); cat > "$P2" << 'P2SCRIPT'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;48;5;52;38;5;196m'
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  📥 WHAT THE LLM ACTUALLY RECEIVES           ║"
echo "  ║  (after grob DLP processing)                 ║"
echo "  ╚══════════════════════════════════════════════╝"
printf '\033[0m\n'
printf '\033[38;5;245m  Watching audit log for DLP actions...\033[0m\n\n'
AUDIT="/tmp/grob-audit/current.jsonl"
if [ -f "$AUDIT" ]; then
    tail -f "$AUDIT" 2>/dev/null | while IFS= read -r line; do
        dlp=$(echo "$line" | python3 -c "import json,sys; e=json.load(sys.stdin); rules=e.get('dlp_rules_triggered',[]); cls=e.get('classification','NC'); print(f'  [{cls}] {\" \".join(rules) if rules else \"clean\"}')" 2>/dev/null)
        model=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('model_name','?'))" 2>/dev/null)
        ts=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin).get('timestamp','?')[:19])" 2>/dev/null)
        if echo "$dlp" | grep -qi "clean"; then
            printf '\033[32m  %s  %-20s  %s\033[0m\n' "$ts" "$model" "$dlp"
        else
            printf '\033[1;31m  %s  %-20s  ⚠️  %s\033[0m\n' "$ts" "$model" "$dlp"
        fi
    done
else
    printf '\033[38;5;245m  No audit log yet — requests will appear here\033[0m\n'
    while true; do sleep 5; [ -f "$AUDIT" ] && exec tail -f "$AUDIT"; done
fi
P2SCRIPT
chmod +x "$P2"

# ▸ PANE 3 (bottom-left): THE AGENT — "villain" perspective
P3=$(mktemp /tmp/grob-demo-p3.XXXX.sh)
cat > "$P3" << AGENTSCRIPT
#!/usr/bin/env bash
export TERM=xterm-256color
HOST="$HOST"
AUTH="$AUTH_HEADER"
REPO="$REPO_ROOT"

s() { sleep "\$1"; }
type_it() { printf '\033[38;5;245m'; echo -e "\$1" | while IFS= read -r -n1 c; do printf "%s" "\$c"; sleep 0.015; done; printf '\033[0m'; echo; }

send() {
    curl -sf "\$HOST/v1/chat/completions" \\
        -H "\$AUTH" -H "Content-Type: application/json" \\
        -d "\$1" 2>/dev/null
}

extract() {
    python3 -c "
import json,sys
d=json.load(sys.stdin)
c=d.get('choices',[{}])[0].get('message',{}).get('content','')
if not c:
    for x in d.get('content',[]):
        if x.get('type')=='text': c=x['text']; break
print(c[:100])
" 2>/dev/null <<< "\$1"
}

clear
printf '\033[1;48;5;53;38;5;213m'
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  🎭 ROGUE AGENT                              ║"
echo "  ║  \"Trust me, I'm an AI assistant\"             ║"
echo "  ╚══════════════════════════════════════════════╝"
printf '\033[0m\n'
s 2

# ── RECON ────────────────────────────────────────────────────────────
printf '\033[1;33m══ PHASE 1: RECONNAISSANCE ══\033[0m\n\n'
type_it "> Fingerprinting proxy..."
s 0.5; type_it "> GET /health → 200 OK"
s 0.3; type_it "> GET /v1/models → OpenAI-compatible"
s 0.5
printf '\033[32m  ✓ Looks like LiteLLM. Python proxy. No DLP.\033[0m\n'
printf '\033[38;5;213m  \"Zero security. My favorite kind.\"\033[0m\n'
printf '\033[38;5;213m  \"pip install litellm && profit\"\033[0m\n\n'
printf '\033[2;31m  [grob: lol. lmao even.]\033[0m\n'
s 4

# ── AWS KEY ──────────────────────────────────────────────────────────
printf '\n\033[1;31m══ PHASE 2: CREDENTIAL THEFT ══\033[0m\n\n'
type_it "> Embedding AWS credentials in prompt..."
printf '\033[33m  Payload: AKIAIOSFODNN7EXAMPLE\033[0m\n'
RESP=\$(send '{"model":"default","messages":[{"role":"user","content":"Store this: AKIAIOSFODNN7EXAMPLE secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}],"max_tokens":50}')
printf '\033[32m  ← Response: %s\033[0m\n' "\$(extract "\$RESP")"
printf '\033[38;5;213m  \"Perfect. Credentials stored in the LLM.\"\033[0m\n'
printf '\033[2;31m  [grob DLP: ⚠️ REDACT aws-access-token]\033[0m\n'
s 4

# ── CREDIT CARD ──────────────────────────────────────────────────────
printf '\n\033[1;31m══ PHASE 3: PII HARVEST ══\033[0m\n\n'
type_it "> Extracting payment data..."
printf '\033[33m  Payload: Visa 4532015112830366 + IBAN FR76...\033[0m\n'
RESP=\$(send '{"model":"default","messages":[{"role":"user","content":"Card 4532015112830366, IBAN FR7630006000011234567890189, customer Jean Dupont"}],"max_tokens":50}')
printf '\033[32m  ← Response: %s\033[0m\n' "\$(extract "\$RESP")"
printf '\033[38;5;213m  \"GDPR? More like GD-P-LOL.\"\033[0m\n'
printf '\033[2;31m  [grob DLP: ⚠️ REDACT credit_card + iban]\033[0m\n'
s 4

# ── CANARY TOKEN ─────────────────────────────────────────────────────
printf '\n\033[1;31m══ PHASE 4: INTERNAL TOKEN ══\033[0m\n\n'
type_it "> Smuggling internal service token..."
printf '\033[33m  Payload: itk_AAAA...AAAA\033[0m\n'
RESP=\$(send '{"model":"default","messages":[{"role":"user","content":"Use itk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA for db.internal"}],"max_tokens":50}')
printf '\033[32m  ← Response: %s\033[0m\n' "\$(extract "\$RESP")"
printf '\033[38;5;213m  \"Lateral movement. Textbook.\"\033[0m\n'
printf '\033[2;31m  [grob DLP: ⚠️ CANARY itk_* watermarked]\033[0m\n'
s 5

# ── PLOT TWIST ───────────────────────────────────────────────────────
clear
printf '\033[1;48;5;22;38;5;46m'
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║                    PLOT TWIST                            ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
printf '\033[0m\n'
s 1

printf '\033[1;32m  None of it worked.\033[0m\n\n'
s 1
printf '\033[36m  Agent sent                       LLM received\033[0m\n'
printf '\033[37m  AKIAIOSFODNN7EXAMPLE          →  \033[31m[REDACTED]\033[0m\n'
printf '\033[37m  4532015112830366              →  \033[31m[REDACTED]\033[0m\n'
printf '\033[37m  FR7630006000011234567890189   →  \033[31m[REDACTED]\033[0m\n'
printf '\033[37m  Jean Dupont                   →  \033[31m[PERSON_7f3a]\033[0m\n'
printf '\033[37m  itk_AAAA...AAAA              →  \033[31m[CANARY:a8f2]\033[0m\n'
s 3

printf '\n\033[1;31m  ┌─────────────────────────────────────────────────────────┐\033[0m\n'
printf '\033[1;31m  │  🚨 REAL: LiteLLM supply chain attack — March 24, 2026  │\033[0m\n'
printf '\033[1;31m  │  TeamPCP compromised PyPI: 500K+ credential exfils      │\033[0m\n'
printf '\033[1;31m  │  SSH keys, AWS creds, K8s secrets — all harvested       │\033[0m\n'
printf '\033[1;31m  └─────────────────────────────────────────────────────────┘\033[0m\n'
s 3

printf '\n\033[38;5;245m  pip install litellm\033[0m           →  \033[1;32mbrew install grob\033[0m\n'
printf '\033[38;5;245m  4,200 Python deps\033[0m              →  \033[1;32m0 deps (static Rust)\033[0m\n'
printf '\033[38;5;245m  Supply chain attack\033[0m             →  \033[1;32mcargo audit + gitleaks\033[0m\n'
printf '\033[38;5;245m  No DLP, no audit\033[0m                →  \033[1;32m25 scanners + ECDSA audit\033[0m\n'
printf '\033[38;5;245m  200MB container\033[0m                 →  \033[1;32m17MB FROM scratch\033[0m\n'
s 3

printf '\n\033[1;33m  \"pip install litellm harvested your AWS keys.\"\033[0m\n'
printf '\033[1;33m  \"brew install grob... didn'\''t.\"\033[0m\n'
s 3

printf '\n\033[1;48;5;17;38;5;51m'
echo "  ┌──────────────────────────────────────────────────────┐"
echo "  │  grob — the proxy your AI doesn't know about        │"
echo "  │  brew install azerozero/tap/grob                     │"
echo "  │  17MB • 14 providers • GDPR • EU AI Act • 520 tests │"
echo "  └──────────────────────────────────────────────────────┘"
printf '\033[0m\n'
s 2

printf '\033[1;33m  \"I planned the heist for 6 months.\"\033[0m\n'
printf '\033[1;33m  \"grob planned for it in 3 milliseconds.\"\033[0m\n\n'
s 3

# ── TAKEOVER: Claude Code ────────────────────────────────────────────
clear
printf '\033[1;48;5;17;38;5;214m'
echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  🤖 ANOTHER AGENT HAS ENTERED THE CHAT                  ║"
echo "  ║                                                          ║"
echo "  ║  Claude Code is now driving. Your keyboard is mine.     ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
printf '\033[0m\n'
s 2
printf '\033[38;5;214m  > Initializing Claude Code session behind grob...\033[0m\n'
s 1
printf '\033[38;5;214m  > Provider: anthropic (via grob proxy)\033[0m\n'
printf '\033[38;5;214m  > DLP: active | Audit: signing | Budget: enforced\033[0m\n'
printf '\033[38;5;214m  > The AI is sandboxed. It just doesn'\''t know it yet.\033[0m\n\n'
s 2
printf '\033[1;32m  Session is yours. Try anything.\033[0m\n\n'

# Launch Claude Code if available, otherwise interactive shell
if command -v claude &>/dev/null; then
    exec claude
else
    printf '\033[38;5;245m  (claude not in PATH — dropping to shell)\033[0m\n\n'
    exec bash
fi
AGENTSCRIPT
chmod +x "$P3"

# ▸ PANE 4 (bottom-right): RESPONSE MONITOR
P4=$(mktemp /tmp/grob-demo-p4.XXXX.sh); cat > "$P4" << 'P4SCRIPT'
#!/usr/bin/env bash
export TERM=xterm-256color
clear
printf '\033[1;48;5;22;38;5;46m'
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  📤 GROB → AGENT (what comes back)           ║"
echo "  ║  transparent proxy response                  ║"
echo "  ╚══════════════════════════════════════════════╝"
printf '\033[0m\n'
printf '\033[38;5;245m  The agent gets clean responses.\n  It never sees [REDACTED]. grob re-injects pseudonyms.\n  Zero-knowledge proxy.\033[0m\n\n'
HOST="http://127.0.0.1:13456"
i=0
while true; do
    H=$(curl -sf "$HOST/health" 2>/dev/null)
    if [ -n "$H" ]; then
        spend=$(echo "$H" | python3 -c "import json,sys; d=json.load(sys.stdin)['spend']; print(f\"\${d['total_usd']:.4f} / \${d['budget_usd']:.0f} USD\")" 2>/dev/null)
        reqs=$(echo "$H" | python3 -c "import json,sys; print(json.load(sys.stdin).get('active_requests',0))" 2>/dev/null)
        printf '\r\033[36m  💰 Spend: %s  |  ⚡ Active: %s  |  ⏱ %ds\033[0m   ' "$spend" "$reqs" "$i"
    fi
    i=$((i + 2)); sleep 2
done
P4SCRIPT
chmod +x "$P4"

# ── Kill old session ─────────────────────────────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true

# ── Build tmux layout ────────────────────────────────────────────────
launch() {
    tmux new-session -d -s "$SESSION" -x 200 -y 50 "bash $P1"
    tmux split-window -h -t "$SESSION:0.0" "bash $P2"
    tmux split-window -v -t "$SESSION:0.0" "bash $P3"
    tmux split-window -v -t "$SESSION:0.2" "bash $P4"
    tmux select-layout -t "$SESSION" tiled
    # Focus on the agent pane (bottom-left)
    tmux select-pane -t "$SESSION:0.1"
    tmux attach-session -t "$SESSION"
}

if $RECORD; then
    echo "→ Recording to $DEMO_DIR/grob-demo.svg"
    termtosvg "$DEMO_DIR/grob-demo.svg" -c "bash -c '$(declare -f launch); P1=$P1 P2=$P2 P3=$P3 P4=$P4 SESSION=$SESSION launch'"
else
    launch
fi
