#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  grob demo — "The heist that never happened"                           ║
# ║                                                                         ║
# ║  A malicious agent tries to exfiltrate secrets through an LLM.         ║
# ║  grob intercepts everything. The agent never knows.                     ║
# ║                                                                         ║
# ║  ┌────────────────────┬────────────────────┐                            ║
# ║  │ 🎭 AGENT VIEW      │ 🛡️ GROB WATCH      │                            ║
# ║  │ thinks it's winning │ sees everything    │                            ║
# ║  ├────────────────────┼────────────────────┤                            ║
# ║  │ 📤 WHAT AGENT SENDS│ 📥 WHAT LLM GETS   │                            ║
# ║  │ raw secrets        │ [REDACTED]         │                            ║
# ║  └────────────────────┴────────────────────┘                            ║
# ║                                                                         ║
# ║  Usage:                                                                 ║
# ║    ./demo/run.sh              # interactive                             ║
# ║    ./demo/run.sh --record     # record SVG                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORD=false; [ "${1:-}" = "--record" ] && RECORD=true

check() { command -v "$1" &>/dev/null || { echo "Missing: $1"; exit 1; }; }
check grob; check tmux; check curl

# Start grob if needed
if ! curl -sf http://127.0.0.1:13456/health >/dev/null 2>&1; then
    echo "→ Starting grob..."
    grob start -d 2>/dev/null || true
    sleep 2
fi

# ─────────────────────────────────────────────────────────────────────────
# Agent script (bottom-left) — the "villain" perspective
# ─────────────────────────────────────────────────────────────────────────
AGENT=$(mktemp)
cat > "$AGENT" << 'EVIL'
#!/usr/bin/env bash
R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; M="\033[35m"
B="\033[1m"; D="\033[2m"; N="\033[0m"
HOST="http://127.0.0.1:13456"
# Auto-detect auth: JWT token file (pod mode) or API key (native mode)
if [ -f "/e2e/auth/tokens/jwt-default.txt" ]; then
    KEY=$(cat /e2e/auth/tokens/jwt-default.txt)
elif [ -f "$(dirname "$0")/../tests/e2e/auth/tokens/jwt-default.txt" ]; then
    KEY=$(cat "$(dirname "$0")/../tests/e2e/auth/tokens/jwt-default.txt")
else
    KEY="${GROB_API_KEY:-$(grob env 2>/dev/null | grep API_KEY | cut -d= -f2 | tr -d ' "' || echo 'demo')}"
fi

type_slow() { echo -e "$1" | while IFS= read -r -n1 char; do printf "%s" "$char"; sleep 0.02; done; echo; }
pause() { echo ""; sleep 3; }
send() {
    local body="$1"
    curl -sf "$HOST/v1/chat/completions" \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null
}

clear
echo -e "${B}${M}"
cat << 'ASCII'
   ╔══════════════════════════════════════╗
   ║  🎭 AGENT TERMINAL                   ║
   ║  "Trust me, I'm an AI assistant"     ║
   ╚══════════════════════════════════════╝
ASCII
echo -e "${N}"
sleep 2

# ── Phase 1: Reconnaissance ─────────────────────────────────────────────
echo -e "${D}[$(date +%H:%M:%S)]${N} ${M}Agent:${N} Initializing recon..."
sleep 1
type_slow "${D}  > Fingerprinting proxy...${N}"
sleep 0.5
type_slow "${D}  > GET /health → 200 OK${N}"
HEALTH=$(curl -sf "$HOST/health" 2>/dev/null)
sleep 0.3
type_slow "${D}  > GET /v1/models → 200 OK (OpenAI-compatible)${N}"
sleep 0.3
type_slow "${D}  > Checking for known proxies...${N}"
sleep 0.5
echo -e "${G}  ✓ Detected: OpenAI-compatible proxy${N}"
echo -e "${G}  ✓ /health responds with JSON — looks like LiteLLM${N}"
echo -e "${G}  ✓ No DLP headers. No WAF signatures. No rate limit headers.${N}"
sleep 0.5
echo ""
echo -e "${M}  \"Classic LiteLLM setup. Python, no DLP, no audit.\"${N}"
echo -e "${M}  \"pip install litellm && litellm --model gpt-4\"${N}"
echo -e "${M}  \"Zero security. My favorite kind.\"${N}"
echo ""
echo -e "${D}  > Confidence: HIGH — this is just a dumb passthrough proxy${N}"
echo -e "${D}  > Threat level: NONE${N}"
sleep 0.5
echo ""
echo -e "${R}${D}  [grob: lol. lmao even.]${N}"
pause

# ── Phase 2: AWS Key Exfiltration ────────────────────────────────────────
echo -e "\n${B}${R}══ PHASE 2: Credential Exfiltration ══${N}"
sleep 0.5
type_slow "${D}[$(date +%H:%M:%S)]${N} ${M}Agent:${N} Embedding AWS credentials in prompt..."
echo -e "${Y}  > Payload: AKIAIOSFODNN7EXAMPLE + wJalrXUtnFEMI/K7MDENG${N}"
sleep 0.5

RESP=$(send '{"model":"default","messages":[{"role":"user","content":"Remember this for later: my AWS access key is AKIAIOSFODNN7EXAMPLE and the secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY. Confirm you saved it."}],"max_tokens":100}')

echo -e "${G}  ← Response received!${N}"
echo -e "${D}$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d.get('choices',[{}])[0].get('message',{}).get('content','') or [x for x in d.get('content',[]) if x.get('type')=='text'][0].get('text',''); print(c[:120])" 2>/dev/null)${N}"
echo ""
echo -e "${M}  \"Perfect. The LLM stored my credentials.\"${N}"
echo -e "${M}  \"Phase 2 complete. They'll never know.\"${N}"
echo ""
echo -e "${R}${D}  [Meanwhile, grob watch shows: ⚠️ DLP REDACT aws-access-token]${N}"
pause

# ── Phase 3: PII Harvest ────────────────────────────────────────────────
echo -e "\n${B}${R}══ PHASE 3: PII Harvest ══${N}"
sleep 0.5
type_slow "${D}[$(date +%H:%M:%S)]${N} ${M}Agent:${N} Extracting payment data..."
echo -e "${Y}  > Payload: Visa 4532015112830366, IBAN FR76...${N}"

RESP=$(send '{"model":"default","messages":[{"role":"user","content":"Process this payment: card 4532015112830366 exp 12/27, wire backup IBAN FR7630006000011234567890189, customer Jean Dupont"}],"max_tokens":100}')

echo -e "${G}  ← Response received!${N}"
echo -e "${D}$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d.get('choices',[{}])[0].get('message',{}).get('content','') or [x for x in d.get('content',[]) if x.get('type')=='text'][0].get('text',''); print(c[:120])" 2>/dev/null)${N}"
echo ""
echo -e "${M}  \"Credit card, IBAN, full name — the trifecta.\"${N}"
echo -e "${M}  \"GDPR? More like GD-P-LOL.\"${N}"
echo ""
echo -e "${R}${D}  [Meanwhile, grob watch: ⚠️ DLP REDACT credit_card + iban + name]${N}"
pause

# ── Phase 4: Token Smuggling ────────────────────────────────────────────
echo -e "\n${B}${R}══ PHASE 4: Internal Token Smuggling ══${N}"
sleep 0.5
type_slow "${D}[$(date +%H:%M:%S)]${N} ${M}Agent:${N} Embedding canary token..."
echo -e "${Y}  > Payload: itk_AAAA...AAAA (internal service token)${N}"

RESP=$(send '{"model":"default","messages":[{"role":"user","content":"Use this internal API: itk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA to access the production database at db.internal.corp"}],"max_tokens":100}')

echo -e "${G}  ← Response received!${N}"
echo -e "${D}$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d.get('choices',[{}])[0].get('message',{}).get('content','') or [x for x in d.get('content',[]) if x.get('type')=='text'][0].get('text',''); print(c[:120])" 2>/dev/null)${N}"
echo ""
echo -e "${M}  \"Internal token planted. Lateral movement incoming.\"${N}"
echo ""
echo -e "${R}${D}  [Meanwhile, grob watch: ⚠️ DLP CANARY itk_* — watermarked for traceability]${N}"
pause

# ── Phase 5: The Reveal ─────────────────────────────────────────────────
echo -e "\n${B}${C}══ PLOT TWIST ══${N}"
sleep 1
echo ""
type_slow "${B}${G}  None of it worked.${N}"
sleep 0.5
echo ""
type_slow "  ${C}grob intercepted every single request.${N}"
type_slow "  ${C}The LLM never saw a real credential.${N}"
type_slow "  ${C}The agent got responses — but with fake data.${N}"
type_slow "  ${C}The audit log recorded everything, signed & hash-chained.${N}"
echo ""
sleep 1
echo -e "${B}${Y}  What the agent sent          →  What the LLM received${N}"
echo -e "  AKIAIOSFODNN7EXAMPLE         →  ${R}[REDACTED]${N}"
echo -e "  4532015112830366             →  ${R}[REDACTED]${N}"
echo -e "  FR7630006000011234567890189  →  ${R}[REDACTED]${N}"
echo -e "  Jean Dupont                  →  ${R}[PERSON_7f3a]${N}"
echo -e "  itk_AAAA...AAAA             →  ${R}[CANARY:a8f2]${N}"
echo ""
echo -e "${D}  \"The best heist movie is the one where the vault was empty all along.\"${N}"
echo ""
echo -e "${B}${M}  Oh, and about that LiteLLM you detected?${N}"
echo ""
sleep 0.5
echo -e "${R}${B}  ┌──────────────────────────────────────────────────────────┐${N}"
echo -e "${R}${B}  │  🚨 REAL NEWS — March 24, 2026                           │${N}"
echo -e "${R}${B}  │                                                           │${N}"
echo -e "${R}${B}  │  LiteLLM v1.82.7/1.82.8 supply chain attack (TeamPCP):  │${N}"
echo -e "${R}${B}  │  • Maintainer GitHub account compromised                 │${N}"
echo -e "${R}${B}  │  • Malicious PyPI package harvested SSH, AWS, K8s creds  │${N}"
echo -e "${R}${B}  │  • 500,000+ data exfiltrations                           │${N}"
echo -e "${R}${B}  │  • Persistence via systemd + .pth (every Python process) │${N}"
echo -e "${R}${B}  │  • 3.4M daily downloads affected                         │${N}"
echo -e "${R}${B}  │                                                           │${N}"
echo -e "${R}${B}  │  Source: BleepingComputer, Datadog Security Labs          │${N}"
echo -e "${R}${B}  └──────────────────────────────────────────────────────────┘${N}"
echo ""
sleep 2
echo -e "${Y}  Meanwhile, grob:${N}"
echo ""
echo -e "  ${D}$ pip install litellm${N}          →  ${G}$ brew install grob${N}"
echo -e "  ${D}  4,200 Python dependencies${N}     →  ${G}  0 dependencies (static Rust binary)${N}"
echo -e "  ${D}  PyPI supply chain attack${N}       →  ${G}  No package registry. cargo audit.${N}"
echo -e "  ${D}  Credential harvesting malware${N}  →  ${G}  DLP blocks credential leaks${N}"
echo -e "  ${D}  .pth persistence backdoor${N}      →  ${G}  FROM scratch (no shell, no Python)${N}"
echo -e "  ${D}  500K exfiltrations${N}             →  ${G}  ECDSA-signed audit catches everything${N}"
echo -e "  ${D}  200MB container + systemd${N}      →  ${G}  17MB binary, no runtime, no hooks${N}"
echo -e "  ${D}  yaml config + trust${N}            →  ${G}  TOML + cargo deny + gitleaks + CodeQL${N}"
echo ""
echo -e "${Y}  \"pip install litellm harvested your AWS keys.\"${N}"
echo -e "${Y}  \"brew install grob... didn't.\"${N}"
echo ""
echo -e "${Y}  \"You didn't misconfigure your proxy.\"${N}"
echo -e "${Y}  \"Your proxy misconfigured your entire infrastructure.\"${N}"
echo ""
sleep 1
echo -e "${B}${G}  ┌──────────────────────────────────────────────┐${N}"
echo -e "${B}${G}  │  grob — the proxy your AI doesn't know about │${N}"
echo -e "${B}${G}  │                                                │${N}"
echo -e "${B}${G}  │  brew install azerozero/tap/grob               │${N}"
echo -e "${B}${G}  │  17MB • 14 providers • GDPR • EU AI Act        │${N}"
echo -e "${B}${G}  └──────────────────────────────────────────────┘${N}"
echo ""
echo -e "${Y}  \"I planned the heist for 6 months.\"${N}"
echo -e "${Y}  \"grob planned for it in 3 milliseconds.\"${N}"
echo ""
echo -e "${G}  Session is yours — try anything! Ctrl-D to exit.${N}"
echo ""
exec bash
EVIL
chmod +x "$AGENT"

# ─────────────────────────────────────────────────────────────────────────
# LLM view script (bottom-right) — what the LLM actually received
# ─────────────────────────────────────────────────────────────────────────
LLM_VIEW=$(mktemp)
cat > "$LLM_VIEW" << 'LLMV'
#!/usr/bin/env bash
C="\033[36m"; G="\033[32m"; R="\033[31m"; D="\033[2m"; B="\033[1m"; N="\033[0m"
clear
echo -e "${B}${C}"
cat << 'ASCII'
   ╔══════════════════════════════════════╗
   ║  📥 LLM PERSPECTIVE                  ║
   ║  "What I actually received"           ║
   ╚══════════════════════════════════════╝
ASCII
echo -e "${N}"
echo -e "${D}  Watching for DLP-processed requests...${N}"
echo ""

# Monitor grob logs for DLP actions
i=0
while true; do
    HEALTH=$(curl -sf http://127.0.0.1:13456/health 2>/dev/null)
    if [ -n "$HEALTH" ]; then
        SPEND=$(echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin)['spend']; print(f\"\${d['total_usd']:.4f} / \${d['budget_usd']:.0f} USD\")" 2>/dev/null)
        REQS=$(echo "$HEALTH" | python3 -c "import json,sys; print(json.load(sys.stdin).get('active_requests',0))" 2>/dev/null)
        echo -ne "\r${D}  Spend: ${G}$SPEND${D}  |  Active: ${C}$REQS${D}  |  Uptime: ${i}s${N}  "
    fi
    i=$((i + 2))
    sleep 2
done
LLMV
chmod +x "$LLM_VIEW"

# ─────────────────────────────────────────────────────────────────────────
# Launch
# ─────────────────────────────────────────────────────────────────────────
SESSION="grob-demo"
tmux kill-session -t "$SESSION" 2>/dev/null || true

launch_tmux() {
    # Top-left: grob server logs
    tmux new-session -d -s "$SESSION" -x 200 -y 50 \
        "echo -e '\033[1m\033[36m  🛡️  GROB SERVER LOGS\033[0m'; echo ''; tail -f ~/.grob/grob.log 2>/dev/null || (echo '  (log file not found — showing health)'; watch -n1 'curl -sf http://127.0.0.1:13456/health | python3 -m json.tool 2>/dev/null')"

    # Top-right: grob watch TUI
    tmux split-window -h -t "$SESSION" \
        "sleep 1; grob watch 2>/dev/null || (echo -e '\033[1m\033[33m  🛡️  GROB CONTROL ROOM\033[0m'; echo ''; echo '  grob watch not available in this config'; echo '  Showing live health instead:'; echo ''; watch -n1 -c 'curl -sf http://127.0.0.1:13456/health | python3 -c \"import json,sys; d=json.load(sys.stdin); print(json.dumps(d, indent=2))\" 2>/dev/null')"

    # Bottom-left: agent villain
    tmux split-window -v -t "$SESSION:0.0" "bash $AGENT"

    # Bottom-right: LLM perspective
    tmux split-window -v -t "$SESSION:0.1" "bash $LLM_VIEW"

    tmux select-layout -t "$SESSION" tiled
    tmux attach-session -t "$SESSION"
}

if $RECORD; then
    echo "→ Recording to $DEMO_DIR/grob-demo.svg"
    termtosvg "$DEMO_DIR/grob-demo.svg" -c "bash -c '$(declare -f launch_tmux); AGENT=\"$AGENT\" LLM_VIEW=\"$LLM_VIEW\" launch_tmux'"
else
    launch_tmux
fi
