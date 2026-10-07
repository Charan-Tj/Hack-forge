#!/usr/bin/env bash
# KavachForge — ONE-CLICK final-round runner.
#
#   ./run_final.sh <source.tar.gz | source-dir | git-url>                 # OUR model (phi4:14b via setup_model.sh)
#   ./run_final.sh <source> --endpoint http://host:8000/v1 --model NAME    # an organizer OpenAI-style endpoint instead
#
# Works on a bare Linux/macOS box with only python3. With the bundle
# (make_bundle.sh) semgrep installs from vendor/wheels/ without internet; the
# model is pulled by Ollama (internet) or taken from vendor/models/ (offline).
# Everything is printed; the report is always written, even if something fails.
#
# Tunables (env): MODEL=phi4:14b DEADLINE_MIN=20 MAX_FINDINGS=8 PRECISION=balanced BUDGET=auto NAME=final
set -u
cd "$(dirname "$0")"
SRC="${1:-}"; shift || true
ENDPOINT=""; MODEL="${MODEL:-phi4:14b}"
while [ $# -gt 0 ]; do case "$1" in
  --endpoint) ENDPOINT="$2"; shift 2;; --model) MODEL="$2"; shift 2;;
  http*) ENDPOINT="$1"; shift;; *) MODEL="$1"; shift;; esac; done
NAME="${NAME:-final}"
DEADLINE_MIN="${DEADLINE_MIN:-20}"
MAX_FINDINGS="${MAX_FINDINGS:-8}"
PRECISION="${PRECISION:-balanced}"
BUDGET="${BUDGET:-auto}"
PORT="${PORT:-8777}"

say()  { printf '\033[1;36m[kavach]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✖ %s\033[0m\n' "$*"; exit 1; }

[ -n "$SRC" ] || die "usage: ./run_final.sh <source.tar.gz|dir|git-url> [endpoint] [model]"
[ -e "$SRC" ] || case "$SRC" in http*|git@*) ;; *) die "not found: $SRC";; esac

# ---------------------------------------------------------------- 1. python
say "1/6 python"
PY=""
for c in python3.12 python3.11 python3.10 python3.9 python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)' 2>/dev/null; then PY="$c"; break; fi
done
[ -n "$PY" ] || die "python 3.8+ not found"
ok "$($PY --version 2>&1)"

# ---------------------------------------------------------------- 2. semgrep (optional, offline-capable)
say "2/6 analyzer"
if ! command -v semgrep >/dev/null 2>&1 && ! "$PY" -m semgrep --version >/dev/null 2>&1; then
  if [ -d vendor/wheels ]; then
    say "installing semgrep from the bundled wheelhouse (no internet needed)…"
    "$PY" -m pip install --user --no-index --find-links vendor/wheels semgrep >/tmp/kv_pip.log 2>&1 \
      || "$PY" -m pip install --no-index --find-links vendor/wheels semgrep >>/tmp/kv_pip.log 2>&1 \
      || warn "wheelhouse install failed (see /tmp/kv_pip.log)"
  fi
  if ! command -v semgrep >/dev/null 2>&1 && ! "$PY" -m semgrep --version >/dev/null 2>&1; then
    say "trying online pip install (60 s cap)…"
    timeout 60 "$PY" -m pip install --user -q semgrep >>/tmp/kv_pip.log 2>&1 || true
  fi
fi
export PATH="$HOME/.local/bin:$PATH"
if command -v semgrep >/dev/null 2>&1; then ok "semgrep $(semgrep --version 2>/dev/null | tail -1) + $(ls rules/semgrep/*.yml 2>/dev/null | wc -l | tr -d ' ') cached rule packs"
else warn "semgrep unavailable: using the 36 built-in patterns + model review (still produces a report)"; fi
command -v patch >/dev/null 2>&1 || command -v git >/dev/null 2>&1 || warn "no patch/git: pure-Python patch applier will be used"

# ---------------------------------------------------------------- 3. model
if [ -n "$ENDPOINT" ]; then
  say "3/6 organizer endpoint $ENDPOINT ($MODEL)"
  export OPENAI_BASE_URL="$ENDPOINT" OPENAI_API_KEY="${OPENAI_API_KEY:-x}"
  T0=$(date +%s)
  RESP=$(curl -s -m 180 "$ENDPOINT/completions" -H "Content-Type: application/json" \
          -d "{\"model\":\"$MODEL\",\"prompt\":\"// reply with the word OK\n\",\"max_tokens\":8,\"temperature\":0}" 2>/dev/null)
  LAT=$(( $(date +%s) - T0 ))
  if echo "$RESP" | grep -q '"choices"'; then
    ok "endpoint answers (${LAT}s for a tiny completion)"; PROVIDER=openai
    if [ "$BUDGET" = auto ]; then
      if [ "$LAT" -le 5 ]; then BUDGET=40; elif [ "$LAT" -le 20 ]; then BUDGET=24; elif [ "$LAT" -le 60 ]; then BUDGET=12; else BUDGET=6; fi
    fi
  else
    warn "endpoint did not answer (response: $(echo "$RESP" | head -c 100)) — switching to our own model"; ENDPOINT=""
  fi
fi
if [ -z "$ENDPOINT" ]; then
  say "3/6 our own model ($MODEL) via Ollama"
  READY=$(MODEL="$MODEL" ./setup_model.sh "$MODEL" | tail -1)
  if [ "$READY" != "none" ] && [ -n "$READY" ]; then
    PROVIDER=ollama; MODEL="$READY"; [ "$BUDGET" = auto ] && BUDGET=24
    ok "model ready: $MODEL"
  else
    warn "no model could be made ready: running the deterministic offline brain (findings + mechanical fixes only)"
    PROVIDER=offline; MODEL=""; [ "$BUDGET" = auto ] && BUDGET=0
  fi
fi
ok "provider=$PROVIDER budget=$BUDGET deadline=${DEADLINE_MIN}min max-findings=$MAX_FINDINGS precision=$PRECISION"

# ---------------------------------------------------------------- 4. doctor
say "4/6 self-check"
"$PY" -m kavachforge doctor >/tmp/kv_doctor.log 2>&1 && ok "doctor READY" || warn "doctor reported issues (see /tmp/kv_doctor.log) — continuing"

# ---------------------------------------------------------------- 5. run (report is always written)
say "5/6 run — artifacts/$NAME/"
mkdir -p artifacts
( "$PY" -m kavachforge serve --port "$PORT" >/dev/null 2>&1 & echo $! > /tmp/kv_serve.pid ) 2>/dev/null
MODELARG=""; [ -n "$MODEL" ] && MODELARG="--model $MODEL"
set +e
"$PY" -m kavachforge onboard "$SRC" --name "$NAME" --mode universal --run \
   --provider "$PROVIDER" $MODELARG --yes --budget "$BUDGET" --max-findings "$MAX_FINDINGS" \
   --deadline-min "$DEADLINE_MIN" --precision "$PRECISION" 2>&1 | tee "artifacts/${NAME}_console.log"
RC=${PIPESTATUS[0]}
set -e 2>/dev/null; set +e

# ---------------------------------------------------------------- 6. deliverables
say "6/6 deliverables"
if [ -f "artifacts/$NAME/report.md" ]; then
  ok "report   : artifacts/$NAME/report.md  (+ report.csv)"
  ok "dashboard: http://localhost:$PORT/$NAME/dashboard.html"
  ok "patches  : $(ls artifacts/$NAME/pr/*/fix.patch 2>/dev/null | wc -l | tr -d ' ') verified patch file(s) under artifacts/$NAME/pr/"
  echo; sed -n '1,40p' "artifacts/$NAME/report.md"
  echo; say "to apply verified patches to the live app:  ./apply_patches.sh <app-source-dir> [restart.sh]"
else
  warn "no report written (exit $RC) — see artifacts/${NAME}_console.log"
fi
exit 0
