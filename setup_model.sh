#!/usr/bin/env bash
# Download + run OUR OWN model on this machine (no organizer model needed).
#
#   ./setup_model.sh                 # auto-pick a model for this machine's RAM, install Ollama, pull, serve
#   ./setup_model.sh phi4:14b        # force a model
#
# Offline: if vendor/ollama/ holds the Ollama Linux tarball and vendor/models/
# holds a pre-pulled models directory (make_bundle.sh --with-model), nothing
# is downloaded. Prints the model name it made ready on the LAST line.
set -u
cd "$(dirname "$0")"
say()  { printf '\033[1;36m[model]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m  ✔ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*" >&2; }

export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
export OLLAMA_MODELS="${OLLAMA_MODELS:-$HOME/.ollama/models}"

# ---- 1. the team's model: phi4:14b (Microsoft, MIT, 9.1 GB). Falls back to
#         phi4-mini:3.8b only if this machine cannot hold the 14B.
#         Override with an argument or MODEL env.
MODEL="${1:-${MODEL:-phi4:14b}}"
if [ "$(uname)" = Darwin ]; then RAM_GB=$(( $(sysctl -n hw.memsize) / 1073741824 ));
else RAM_GB=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1048576 )); fi
GPU=""; command -v nvidia-smi >/dev/null 2>&1 && GPU=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
if [ "$MODEL" = "phi4:14b" ] && [ "$RAM_GB" -lt 12 ] && [ "${GPU:-0}" -lt 11000 ] 2>/dev/null; then
  warn "only ${RAM_GB} GB RAM: phi4:14b needs ~11 GB -> using phi4-mini:3.8b instead"
  MODEL="phi4-mini:3.8b"
fi
say "machine: ${RAM_GB} GB RAM${GPU:+, GPU ${GPU} MiB} -> model $MODEL"

# ---- 2. ollama binary (installed, bundled, or downloaded)
if ! command -v ollama >/dev/null 2>&1; then
  if ls vendor/ollama/ollama-linux-*.tgz >/dev/null 2>&1; then
    say "installing Ollama from the bundle…"
    mkdir -p "$HOME/.local/ollama" && tar -xzf vendor/ollama/ollama-linux-*.tgz -C "$HOME/.local/ollama" \
      && export PATH="$HOME/.local/ollama/bin:$PATH" && ok "ollama (bundled)"
  elif [ -x vendor/ollama/ollama ]; then
    export PATH="$PWD/vendor/ollama:$PATH"; ok "ollama (bundled binary)"
  else
    say "downloading Ollama (needs internet)…"
    if [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1; then
      curl -fsSL https://ollama.com/install.sh | sh >/tmp/kv_ollama_install.log 2>&1 || warn "install script failed (see /tmp/kv_ollama_install.log)"
    else
      ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; *) A=amd64;; esac
      mkdir -p "$HOME/.local/ollama" && curl -fsSL "https://ollama.com/download/ollama-linux-$A.tgz" | tar -xz -C "$HOME/.local/ollama" \
        && export PATH="$HOME/.local/ollama/bin:$PATH"
    fi
  fi
fi
command -v ollama >/dev/null 2>&1 || { warn "ollama not available; KavachForge will run with the deterministic offline brain"; echo "none"; exit 0; }
ok "ollama $(ollama --version 2>/dev/null | grep -o '[0-9][0-9.]*' | head -1)"

# ---- 3. bundled model blobs (offline)
if [ -d vendor/models/manifests ] && [ ! -d "$OLLAMA_MODELS/manifests" ]; then
  say "installing bundled model files…"; mkdir -p "$OLLAMA_MODELS"; cp -R vendor/models/. "$OLLAMA_MODELS"/ && ok "model files copied"
fi

# ---- 4. serve
if ! curl -s -m 2 "$OLLAMA_HOST/api/version" >/dev/null 2>&1; then
  say "starting ollama serve…"
  (setsid nohup ollama serve >/tmp/kv_ollama.log 2>&1 </dev/null &)
  for i in $(seq 1 30); do curl -s -m 2 "$OLLAMA_HOST/api/version" >/dev/null 2>&1 && break; sleep 1; done
fi
curl -s -m 2 "$OLLAMA_HOST/api/version" >/dev/null 2>&1 && ok "ollama serving at $OLLAMA_HOST" || { warn "ollama did not start (see /tmp/kv_ollama.log)"; echo "none"; exit 0; }

# ---- 5. pull (skipped when already present / bundled)
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL"; then
  ok "model present: $MODEL"
else
  say "pulling $MODEL (one-time download, progress below)…"
  ollama pull "$MODEL" 1>&2 && ok "pulled $MODEL" || {
    warn "pull failed (no internet?) — trying any model already on this machine"
    MODEL=$(ollama list 2>/dev/null | awk 'NR>1{print $1}' | head -1)
    [ -n "$MODEL" ] && ok "using $MODEL" || { warn "no model available"; echo "none"; exit 0; }
  }
fi

# ---- 6. warm up (first call loads weights; measure it)
say "loading $MODEL into memory (first call, can take 1-3 min)…"
T0=$(date +%s)
curl -s -m 600 "$OLLAMA_HOST/api/generate" -d "{\"model\":\"$MODEL\",\"prompt\":\"OK\",\"stream\":false,\"options\":{\"num_predict\":2}}" >/dev/null 2>&1
ok "model warm (${MODEL}, first call $(( $(date +%s) - T0 ))s)"
echo "$MODEL"
