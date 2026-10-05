# KavachForge — Run Anywhere (day-of cheat sheet)

Keep this open during the finale. Two ways to run; pick whichever the laptop supports.

## Option A — Docker (most reliable, works on any OS)
Needs only Docker Desktop installed and running.

```bash
cd kavachforge
./kavach --docker demo        # builds image on first run (~2 min), then runs
./kavach --docker serve       # open http://localhost:8777
```

That's it. The image carries clang + libFuzzer + AddressSanitizer, so the
coverage-guided engine runs identically on any judge's machine.

## Option B — Native (no Docker)
Needs: Python 3.9+, `patch`, and a C compiler with AddressSanitizer.

```bash
# macOS:   xcode-select --install     (clang) ; gcc also fine via brew
# Ubuntu:  sudo apt-get install -y clang llvm libclang-rt-dev patch
#          (or: sudo apt-get install -y gcc patch)
cd kavachforge
./kavach doctor               # confirms the toolchain is ready
./kavach demo
./kavach serve                # http://localhost:8777
```

## The safe demo (no internet, no API key, identical every time)
```bash
./kavach replay               # deterministic offline run of all targets
```
Use this if the venue Wi-Fi is flaky or you don't want any live dependency.
It still shows discovery → classification → **Verified patch** → clean control.

## Showing a live LLM (optional, if network is available)
```bash
export ANTHROPIC_API_KEY=sk-...        # or OPENAI_API_KEY=...
./kavach run tinyimg                   # seeds + patch come from the model
```
Falls back to the offline brain automatically if the call fails — the demo
cannot break.

## If something goes wrong (90-second recovery)
1. `./kavach doctor` — tells you exactly what's missing.
2. No toolchain? → use **Option A (Docker)**.
3. No Docker *and* no compiler? → run on the presenter's machine; artifacts in
   `artifacts/` are pre-generated and `./kavach serve` still shows them.
4. Wi-Fi down? → `./kavach replay` (offline, deterministic).
5. Start clean: `./kavach clean && ./kavach demo`.

## What to point the judges at
- The terminal: each stage prints, ending in **PATCH VERIFIED** for two bugs and
  **NO VERIFIED CRASH** for the clean control (no false positive).
- The dashboard (`./kavach serve`): risk ledger, the four green gates, the unified
  diff, the PoV hexdump, and the sanitizer report — the full evidence chain.
- `artifacts/<target>/evidence.json`: the auditable record.

## One-liners
```bash
./kavach demo                 # everything
./kavach run recordcfg        # single target, full loop
./kavach replay               # offline deterministic
./kavach --docker demo        # containerized
make demo | make docker-demo  # same via Makefile
```
