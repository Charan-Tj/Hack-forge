# KavachForge

**Evidence-gated vulnerability discovery and repair — a compact, production-grade cyber-reasoning system.**

Built for the **AI Kavach** track of **Terrier Cyber Quest 2026**.

> *Kavach means shield — defensive by design.*

KavachForge turns a suspicious code change or a scanner alert into an **auditable decision backed by executable evidence**. For a C/C++ target it ingests a real `git diff` / SARIF scan, ranks risky paths, generates structure-aware fuzzing seeds, reproduces a crash, proposes a **minimal source patch**, and then **proves the patch holds** — it must build, block the exact proof-of-vulnerability, and keep the regression tests green — before anything is reported.

```
 git diff / SARIF ─▶ risk ranking ─▶ LLM seeds + fuzzing ─▶ reproduce & dedup
                  ─▶ LLM patch (self-reflect) ─▶ build + PoV-replay + tests ─▶ signed evidence
```

### Two hard gates (the whole point)
- **No finding without a reproducible proof-of-vulnerability (PoV).** Every crash is re-run in a fresh process before it counts; duplicates are collapsed by normalized stack signature (e.g. **46 raw crashes → 1 finding**).
- **No "fix" until it is proven.** A patch is `Verified` only after it **applies**, **rebuilds**, makes the **PoV no longer crash**, and **passes the regression suite** — all in a clean, disposable worktree.

This is the AIxCC pattern (LLM + fuzzing + deterministic validation), deliberately narrowed so the full loop is credible and reliable live.

---

## Showcase in one command

```bash
./kavach showcase          # dashboard goes live at http://localhost:8777, then every target runs
```

Open the URL first; the index and each target's dashboard **update live** as stages complete and gates turn green. With Docker (identical toolchain on any laptop, coverage-guided libFuzzer engine):

```bash
./kavach --docker showcase
```

Other entry points:

```bash
./kavach doctor            # environment check (toolchain, patch, keys)
./kavach selftest          # 23 built-in unit tests
./kavach demo              # run all targets without the server
./kavach run tinyimg       # one target
./kavach replay            # deterministic offline run: no network, no key
./kavach serve             # just serve existing dashboards
```

**Requirements (native):** Python 3.9+, a C compiler with AddressSanitizer (`clang`+compiler-rt *or* `gcc`/Apple clang+libasan), and `patch`. **Or** Docker only.

---

## What judges see

Three bundled targets, run every time:

| Target | Input signal | Bug | Result |
|---|---|---|---|
| `tinyimg` | a developer **diff** (`changes/add-channel-table.diff`) | stack OOB write behind a `TIMG` magic gate — **CWE-787** | PoV in ~0.1s, 40+ raw crashes → 1 finding, **patch Verified** |
| `recordcfg` | a **SARIF** scan (`scan/clang-tidy.sarif`) | heap OOB write via unchecked TLV length — **CWE-787** | PoV in ~0.1s, **patch Verified** |
| `cleanjson` | — | *no bug* (control) | 10M+ execs (libFuzzer), **nothing invented** |

Each target produces a tamper-evident **evidence bundle** in `artifacts/<target>/`:
- `evidence.json` — risk ledger, ingestion sources, PoV hash, normalized stack signature, CWE + severity, duplicates collapsed, the unified diff, every gate outcome, LLM budget.
- `dashboard.html` — the visual evidence chain (stage strip, raw→unique, gates, diff, PoV hexdump, sanitizer report).
- `manifest.json` — sha256 of every artifact + a bundle hash.
- `run.log` — the full console transcript.
- `llm_log/` — every prompt and response.

---

## Why the demo cannot break (resilience layers)

1. **Live model** (Anthropic / OpenAI / local Ollama) for seeds and patches, with a hard call budget.
2. **Prompt cache** — prompts are normalized (no PIDs/addresses), so a rerun is free and a cached run completes **even if the model endpoint dies mid-demo**.
3. **Offline heuristic brain** — no key, no cache, no network: structure-aware seeds and a bounds-guard repair, deterministic (`./kavach replay`).
4. **Two fuzzing engines from one harness** — coverage-guided libFuzzer (Docker / any clang+compiler-rt), or a standalone ASan engine that runs wherever libasan exists (macOS included).

All four layers were exercised end-to-end during development; the self-tests cover transports, policy, dedup and repair synthesis.

---

## How it maps to the AI Kavach judging criteria

| Criterion | Where KavachForge earns it |
|---|---|
| Innovation & relevance | Diff-to-sink prioritization + LLM↔fuzzer seed sharing + **evidence gates**. The novelty is *proof*, not a model that merely claims to find bugs. |
| Feasibility | Narrow, controlled target class; mature deterministic tools do the hard parts; runs on a laptop in seconds. |
| Illustration | Live dashboard: stage strip, risk ledger, gates, diff, PoV — judges watch it happen. |
| Technical depth | libFuzzer/ASan, stack-signature dedup, CWE mapping, SARIF/diff ingestion, policy-checked self-reflecting repair, three-gate validation, hashed evidence manifest. |
| Lightweight / resource use | **Zero pip dependencies**, single orchestrator process, LLM budget cap, ≤ 1 minute per target. |

---

## Models (optional)

```bash
export ANTHROPIC_API_KEY=...              # or OPENAI_API_KEY
./kavach showcase                         # live model for seeds + patch
export KAVACH_LLM_PROVIDER=ollama KAVACH_LLM_MODEL=llama3.1   # fully local model
./kavach run tinyimg --provider offline   # force the heuristic brain
```

Provider-agnostic, `urllib` only. Budget default: 6 calls/target (`--budget`).

---

## Point it at your own target

Drop a JSON task in `tasks/` (paths relative to `root`). Existing OSS-Fuzz-style harnesses (`LLVMFuzzerTestOneInput`) work unchanged.

```json
{
  "name": "mylib",
  "root": "targets/mylib",
  "sources": ["src/parser.c"],
  "include_dirs": ["src"],
  "harness": "harness/fuzz_parser.c",
  "test_sources": ["src/parser.c", "tests/test_parser.c"],
  "patch_scope": ["src/parser.c"],
  "magic": "MLIB",
  "diff": "git",                       # or a .diff file; or omit
  "sarif": "scan/results.sarif",       # optional
  "budgets": {"time_budget_s": 45}
}
```

`./kavach run mylib --diff git --sarif scan.sarif` overrides from the CLI. `--uplift` adds a measured A/B: time-to-crash from an empty corpus vs. with structure-aware seeds (reported honestly for the engine in use).

---

## Architecture

```
kavachforge/
  pipeline.py     orchestrator; publishes evidence after every stage (live dashboards)
  ingest.py       unified-diff (file or live git) and SARIF 2.1 ingestion
  risk.py         diff-to-sink risk ledger (function-level, deterministic, pre-LLM)
  discovery.py    build + seeds (LLM/heuristic) + fuzzing (libFuzzer | standalone), uplift A/B
  verifier.py     reproduce, normalize stack signature, dedup, CWE classify
  patcher.py      LLM repair + self-reflection + static policy + heuristic repair brain
  validator.py    clean-worktree three-gate proof (apply/build/PoV/tests)
  report.py       evidence.json + live HTML dashboard + showcase index
  llm.py          provider-agnostic transport (anthropic/openai/ollama/offline), cache, budget
  toolchain.py    engine detection + build recipes
  engine/kv_standalone_main.c   one-shot ASan driver for the portable engine
  tests/          23 stdlib unit tests  (./kavach selftest)
targets/          2 vulnerable demo parsers + 1 clean control, each with harness, tests, sample diff/SARIF
tasks/            task definitions
```

---

## Safety & governance
- Fuzzing and validation run with CPU-time and hard RSS limits; untrusted inputs execute only against the supplied local target. No scanning of external systems.
- The original repository is never mutated — patches are proven on a copy.
- Model output is untrusted text: only a fixed command template is ever executed, never model-generated shell.
- API keys come from the environment and are never written to logs or evidence.
- **Humans approve every patch.** KavachForge recommends; it does not deploy.

## Design basis
Inspired by public AIxCC results (DARPA AI Cyber Challenge) and the open-source CRS literature — independently implemented and narrowed for the finale. See `pitch/NOTES.md` for the judge demo script and references.
