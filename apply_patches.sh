#!/usr/bin/env bash
# Apply KavachForge's VERIFIED patches to the live application source, then restart it.
#
#   ./apply_patches.sh <app-source-dir> [restart.sh] [artifacts-name]
#
# Only patches under artifacts/<name>/pr/*/fix.patch exist, and those are only
# written for patches that passed all gates. Each is applied with --dry-run
# first; a patch that does not apply is skipped and reported, never forced.
set -u
cd "$(dirname "$0")"
APP="${1:-}"; RESTART="${2:-}"; NAME="${3:-final}"
[ -d "$APP" ] || { echo "usage: ./apply_patches.sh <app-source-dir> [restart.sh] [name]"; exit 1; }
n=0; ok=0
for p in artifacts/"$NAME"/pr/*/fix.patch; do
  [ -f "$p" ] || continue
  n=$((n+1))
  # strip the generated regression/proof test from the patch (keep only the fix)
  fix=$(mktemp); awk '/^--- a\/tests\/kv_proof_|^--- \/dev\/null/{skip=1} skip&&/^--- a\//&&!/kv_proof_/{skip=0} !skip' "$p" > "$fix"
  if patch -p1 -N --dry-run -d "$APP" -i "$fix" >/dev/null 2>&1; then
    patch -p1 -N -d "$APP" -i "$fix" >/dev/null 2>&1 && { echo "applied : $p"; ok=$((ok+1)); } || echo "FAILED  : $p"
  elif command -v git >/dev/null 2>&1 && git -C "$APP" apply --check "$PWD/$fix" >/dev/null 2>&1; then
    git -C "$APP" apply "$PWD/$fix" && { echo "applied : $p (git apply)"; ok=$((ok+1)); } || echo "FAILED  : $p"
  else
    echo "SKIPPED : $p (does not apply cleanly to $APP — apply by hand from the PR.md next to it)"
  fi
  rm -f "$fix"
done
echo "$ok / $n patch(es) applied to $APP"
if [ -n "$RESTART" ] && [ -x "$RESTART" ]; then
  echo "restarting the app: $RESTART"; "$RESTART"
elif [ -n "$RESTART" ]; then
  echo "restart script not executable: $RESTART (run it manually)"
fi
