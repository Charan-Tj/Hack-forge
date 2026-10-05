# KavachForge

**Evidence-gated vulnerability discovery and repair — a compact cyber-reasoning system.**

Built for the **AI Kavach** track of **Terrier Cyber Quest 2026**.

> *Kavach means shield — defensive by design.*

KavachForge turns a suspicious code change or a scanner alert into an **auditable decision backed by executable evidence**. For a C/C++ target it ranks risky paths, generates structure-aware fuzzing seeds, reproduces a crash, proposes a **minimal source patch**, and then **proves the patch holds** — it must build, block the exact proof-of-vulnerability, and keep the regression tests green — before anything is reported.

```
 diff / alert ─▶ risk ranking ─▶ LLM seeds + fuzzing ─▶ reproduce & dedup
              ─▶ LLM patch (self-reflect) ─▶ build + PoV-replay + tests ─▶ evidence
```

### Two hard gates (the whole point)
- **No finding without a reproducible proof-of-vulnerability (PoV).** Crashes are re-run on a fresh process before they count.
- **No "fix" until it is proven.** A patch is `Verified` only after it **applies**, **rebuilds**, makes the **PoV no longer crash**, and **passes the regression suite** — all in a clean, disposable worktree.

This is the AIxCC pattern (LLM + fuzzing + deterministic validation), deliberately narrowed so the full loop is credible and reliable in a live finale.

---

## Quick start (any machine)

```bash
./kavach doctor      # check the environment
./kavach demo        # run all 3 bundled targets end-to-end
./kavach serve       # open the dashboards at http://localhost:8777
```

No API key? No internet? It still runs a full, **deterministic** demo:

```bash
./kavach replay      # offline heuristic brain, fixed RNG — identical every time
```

With Docker (gets the premium coverage-guided libFuzzer engine, identical anywhere):

```bash
./kavach --docker demo
./kavach --docker serve
```

**Requirements (native):** Python 3.9+, a C compiler with AddressSanitizer (`clang`+compiler-rt *or* `gcc`+libasan), and `patch`. **Or** just Docker — nothing else.

---

## What you'll see

`./kavach demo` runs three targets:

| Target | Bug | Result |
|---|---|---|
| `tinyimg` | stack out-of-bounds write behind a `TIMG` magic gate (**CWE-787**) | PoV found, **patch Verified** |
| `recordcfg` | heap out-of-bounds write via unchecked TLV length (**CWE-787/120**) | PoV found, **patch Verified** |
| `cleanjson` | *no bug* — control target | **no finding invented** |

Each run writes an **evidence bundle** to `artifacts/<target>/`:
- `evidence.json` — machine-readable: risk ledger, PoV hash, normalized stack signature, CWE + severity, the unified diff, every gate outcome.
- `dashboard.html` — a self-contained visual report of the whole evidence chain.

---

## How it maps to the AI Kavach judging criteria

| Criterion | Where KavachForge earns it |
|---|---|
| Innovation & relevance | Diff-to-sink prioritization + LLM↔fuzzer seed sharing + **evidence gates** — the novelty is *proof*, not a model that merely claims to find bugs |
| Feasibility | Narrow, controlled target class; mature deterministic tools do the hard parts (compile, sanitize, fuzz, test); runs on a laptop |
| Illustration | Live pipeline output + the HTML evidence dashboard (risk ledger, gates, diff, PoV) |
| Technical depth | libFuzzer/ASan, stack-signature dedup, CWE mapping, policy-checked repair, three-gate validation — all inspectable in `evidence.json` |
| Lightweight / resource use | **Zero pip dependencies** (standard library only), single orchestrator process, hard LLM budget cap |

---

## Commands

```
./kavach run <task>      full loop on one task (live model if a key is set)
./kavach replay [task]   deterministic offline run (no network / no key)
./kavach demo            run all bundled targets
./kavach doctor          environment check
./kavach serve           serve dashboards over HTTP (port 8777)
./kavach list            list bundled tasks
./kavach clean           remove artifacts/
```

Add `--docker` before any command to run inside the image.

### Models (optional)
KavachForge is provider-agnostic and uses only `urllib` — no SDKs.

```bash
export ANTHROPIC_API_KEY=...      # or OPENAI_API_KEY
./kavach run tinyimg              # uses the live model for seeds + patch
# force a local model instead:
export KAVACH_LLM_PROVIDER=ollama KAVACH_LLM_MODEL=llama3.1
```

With no key, `KAVACH_LLM_PROVIDER=offline` (the default) uses a deterministic
heuristic brain, so the demo never depends on the network. The LLM call budget
is capped (default 6 calls/target) and every prompt/response is logged under
`artifacts/<task>/llm_log/`.

---

## Point it at your own target

Drop a JSON task in `tasks/` (paths are relative to `root`):

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
  "diff_changed": ["src/parser.c"],
  "static_alerts": [{"file": "src/parser.c", "line": 42, "rule": "CWE-787 ..."}],
  "budgets": {"time_budget_s": 45}
}
```

The harness is a standard libFuzzer entry point (`LLVMFuzzerTestOneInput`), so
existing OSS-Fuzz-style harnesses work unchanged.

---

## Architecture

```
kavachforge/
  pipeline.py     orchestrator (the closed loop)
  risk.py         diff-to-sink risk ledger (deterministic, pre-LLM)
  discovery.py    build + seeds (LLM/heuristic) + fuzzing (libFuzzer | standalone)
  verifier.py     reproduce, normalize stack signature, dedup, CWE classify
  patcher.py      LLM repair + self-reflection + static policy + heuristic brain
  validator.py    clean-worktree three-gate proof (apply/build/PoV/tests)
  report.py       evidence.json + self-contained HTML dashboard
  llm.py          provider-agnostic transport (anthropic/openai/ollama/offline)
  toolchain.py    engine detection + build recipes
  engine/kv_standalone_main.c   one-shot ASan driver for the portable engine
targets/          2 vulnerable demo parsers + 1 clean control (sources+harness+tests)
tasks/            task definitions
```

### Discovery engines (one harness, two backends)
- **libfuzzer** — `clang -fsanitize=fuzzer,address`, coverage-guided. Primary; guaranteed in the Docker image.
- **standalone** — any `-fsanitize=address` compiler + KavachForge's own mutational loop. Runs where the libFuzzer runtime is absent. A finding reproduces identically either way.

---

## Safety & governance
- All build, fuzzing and validation run with resource/time limits; untrusted inputs execute only against the supplied local target.
- The original repository is never mutated — patches are proven on a copy.
- Model output is treated as untrusted text; only a fixed command template is executed, never model-generated shell.
- API keys are read from the environment and redacted from logs.
- **Humans approve every patch.** KavachForge recommends; it does not deploy.

---

## Design basis
Inspired by public AIxCC results (DARPA AI Cyber Challenge) and the open-source
CRS literature — independently implemented and narrowed for the finale. See
`pitch/NOTES.md` for references and the judge demo script.
