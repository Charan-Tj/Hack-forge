# KavachForge — Showcase Runbook (keep open at the finale)

## 60 seconds before the judges arrive
```bash
cd kavachforge
./kavach doctor          # must say READY
./kavach selftest        # must say OK
./kavach showcase --fresh
```
Open **http://localhost:8777** in a browser on the big screen *before* the run finishes
— the index and each dashboard update live. Leave the terminal visible next to it.

## Option A — Docker (identical on any OS; coverage-guided libFuzzer engine)
Needs only Docker Desktop running.
```bash
./kavach --docker showcase        # first run builds the image (~2 min)
```
The container maps port 8777 and writes `artifacts/` to the host, so the dashboard
URL is the same.

## Option B — Native (no Docker)
Needs Python 3.9+, `patch`, and a C compiler with AddressSanitizer.
```bash
# macOS:   xcode-select --install
# Ubuntu:  sudo apt-get install -y clang llvm libclang-rt-dev patch   # libFuzzer engine
#          (gcc + patch alone also works: standalone engine)
./kavach doctor && ./kavach showcase --fresh
```

## If the venue network is down or you have no API key
Nothing changes — the offline brain and the prompt cache take over automatically.
For a 100% deterministic run (identical numbers every time):
```bash
./kavach replay
```

## Showing a live model (optional)
```bash
export ANTHROPIC_API_KEY=sk-...   # or OPENAI_API_KEY=...
./kavach showcase --fresh
```
Dashboards will say `model: anthropic / ...` and the patch card `source: live`.
If the endpoint fails mid-run it falls back to cache/offline — the run completes.

## What to say while it runs (4 minutes)
1. **Signals** — point at "Input signals": a real developer diff for `tinyimg`, a real
   SARIF scan for `recordcfg`. "We start from what teams already have."
2. **Risk ledger** — the parser is top: changed lines + copy/index sink + reachable from
   the fuzz entry + scanner alert. Deterministic and explainable, before any LLM.
3. **Discovery** — crash in ~0.1s; "46 raw crashes → 1 finding" is signature-level dedup.
4. **Evidence** — PoV hash, repro command, CWE-787 + severity, root-cause line.
5. **Repair** — minimal guard at the root cause; policy forbids touching tests/harness/flags;
   if the model's first try is bad, the rejection reason is fed back (self-reflection).
6. **Proof** — four gates go green: apply → rebuild → PoV blocked → tests pass → **VERIFIED**.
7. **Control** — `cleanjson`: 10M+ execs, **no finding invented**. "We don't hallucinate bugs."
8. **Boundary** — manifest hash, run log, LLM budget; human approves, nothing auto-deploys.

## Likely judge questions (short answers)
- *Real repos?* Yes: any libFuzzer/OSS-Fuzz-style harness; `--diff git --sarif file`.
- *Why not just an LLM?* It hallucinates findings and "fixes" that hide tests. We gate on
  executable proof.
- *Scale?* Stateless per target, filesystem coordination; parallelize by running tasks on
  separate runners. Roadmap: CI/PR integration, CodeQL reachability, Java/Python.
- *Air-gapped?* Yes — local Ollama model or offline brain; no network needed.

## 90-second recovery
1. `./kavach doctor` tells you what's missing.
2. No compiler → `./kavach --docker showcase`. No Docker either → `./kavach serve`
   shows the last good artifacts.
3. Anything odd → `./kavach clean && ./kavach replay`.
