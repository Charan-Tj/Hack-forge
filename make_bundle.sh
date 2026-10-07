#!/usr/bin/env bash
# Build the self-contained zip to upload to the jury box.
#
#   ./make_bundle.sh                       # -> kavachforge-final.zip (with offline semgrep wheels)
#   ./make_bundle.sh --with-model          # also embed Ollama (linux amd64) + the phi4:14b model files (~11 GB)
#   ./make_bundle.sh --no-wheels           # smaller zip; semgrep needs internet on the box
#
# Wheels are fetched for Linux x86_64 and aarch64, CPython 3.9-3.12 (~250 MB),
# so `run_final.sh` can `pip install --no-index` semgrep with no network.
set -eu
cd "$(dirname "$0")"
OUT="kavachforge-final.zip"
MODEL="${MODEL:-phi4:14b}"
if [ "${1:-}" = "--with-model" ]; then
  mkdir -p vendor/ollama vendor/models
  [ -f vendor/ollama/ollama-linux-amd64.tgz ] || curl -fL -o vendor/ollama/ollama-linux-amd64.tgz https://ollama.com/download/ollama-linux-amd64.tgz
  ollama pull "$MODEL" && cp -R "${OLLAMA_MODELS:-$HOME/.ollama/models}/." vendor/models/
  echo "embedded ollama + $MODEL ($(du -sh vendor | cut -f1))"
  shift
fi
if [ "${1:-}" != "--no-wheels" ]; then
  mkdir -p vendor/wheels
  for plat in manylinux2014_x86_64 manylinux2014_aarch64; do
    for pv in 3.9 3.10 3.11 3.12; do
      echo "wheels: $plat py$pv"
      python3 -m pip download -q semgrep --dest vendor/wheels --only-binary=:all: \
        --platform "$plat" --python-version "$pv" --implementation cp || echo "  (skipped $plat py$pv)"
    done
  done
  du -sh vendor/wheels
fi
rm -f "$OUT"
zip -qr "$OUT" . -x '.git/*' 'artifacts/*' 'cache/*' 'targets/_onboarded/*' '*/__pycache__/*' '*.pyc' \
    'research_notes/*' 'reports/*' '*.o' '*.out'
ls -la "$OUT"
echo
echo "On the jury box:"
echo "  unzip kavachforge-final.zip -d kavachforge && cd kavachforge"
echo "  ./run_final.sh <source.tar.gz> http://192.168.1.103:8000/v1 codellama-7b"
