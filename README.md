# KavachForge

**Evidence-gated vulnerability discovery and repair — a compact, production-grade cyber-reasoning system.**

Built for the **AI Kavach** track of **Terrier Cyber Quest 2026**.

> *Kavach means shield — defensive by design.*

KavachForge turns a suspicious code change or a scanner alert into an **auditable decision backed by executable evidence**. For a C/C++ target it ingests a real `git diff` / SARIF scan, ranks risky paths, generates structure-aware fuzzing seeds, reproduces a crash, proposes a **minimal source patch**, and then **proves the patch holds** — it must build, block the exact proof-of-vulnerability, and keep the regression tests green — before anything is reported.

```
 git diff / SARIF ─▶ risk ranking ─▶ LLM seeds + fuzzing ─▶ reproduce & dedup
                  ─▶ LLM patch (self-reflect) ─▶ build + PoV-replay + tests ─▶ signed evidence
```

### The evidence gates (the whole point)
Nothing is a finding without a reproducible PoV (re-run in a fresh process; duplicates collapsed by normalized stack signature — e.g. **47 raw crashes → 1 finding**). A patch is `Verified` only after **six** executable gates pass in a clean, disposable worktree:

| Gate | Proves |
|---|---|
| G0 | the patch applies |
| G1 | the target rebuilds |
| G2 | the exact PoV no longer crashes |
| G3 | the existing regression suite still passes |
| **G4** | a regression test generated from the PoV crashes the unpatched tree and passes the patched tree |
| **G5** | **behaviour preserved** — the whole corpus replayed through a behaviour probe produces byte-identical results on every previously-valid input (catches the >40% of patches that pass "PoC + tests" but silently change behaviour) |

Several candidate patches are generated per finding (different strategies), all run through the gates, and the survivor **closest to the root cause** is chosen.

This is the AIxCC pattern (LLM + fuzzing + deterministic validation), deliberately narrowed so the full loop is credible and reliable live.

---

## Engines & reproducibility
- **libFuzzer** (clang + compiler-rt; the Docker image and Linux): coverage-guided, millions of exec/s.
- **standalone-greybox** (any gcc/clang with AddressSanitizer, e.g. macOS): a SanitizerCoverage edge bitmap + an auto-extracted literal dictionary make it genuinely coverage-guided — it can crack magic/length gates unaided, not just blind-mutate. Slower (one process per input) but portable everywhere.
- `./kavach replay` forces the standalone engine for byte-identical, deterministic runs.
- The CI workflow **builds and smoke-tests the Docker image on every push** and publishes it to GHCR.

## Real-world target
`./kavach run cjson` runs the whole loop on **cJSON 1.7.18** (a 3,100-line production JSON parser, MIT, vendored under `targets/cjson/`) — a clean run of ~1.9M executions with zero false positives, the honest answer to "does it work on real code?"

## What's in it
- **Discovery:** coverage-guided libFuzzer (or a portable standalone ASan engine), seeded by structure-aware byte seeds **and model-written generator programs** that solve checksum/digest gates a fuzzer cannot (see the `sigpkt` target: seeded 0.1s vs. nothing in 20s unaided).
- **Triage:** fresh-run reproduction, normalized stack-signature dedup, CWE + severity (read/write aware).
- **Repair:** a **patch ensemble** (model strategies + a deterministic brain) ranked by root-cause proximity, with a static policy gate and self-reflection.
- **Proof:** six gates G0–G5, a generated+proven regression test, and a tamper-evident evidence bundle (sha256 manifest, run log, prompt log).
- **Delivery:** a merge-ready PR bundle per fix, a **GitHub Actions workflow** (`kavach ci`) that comments on PRs and opens an automatic fix-PR, and **automatic harness synthesis** (`kavach harness`) for unfuzzed C sources.
- **Live:** `showcase` (watch gates go green) and `watch` (a judge breaks a target, it heals itself).

## Guides
- **docs/OFFLINE_MODELS.md** — run with no internet: local models by laptop size, `kavach prefetch`, demo-day checklist
- **[docs/RUN_AND_TEST.md](docs/RUN_AND_TEST.md)** — install on any OS, every command, what each prints, the three levels of testing, troubleshooting.
- **[docs/JUDGE_DEMO.md](docs/JUDGE_DEMO.md)** — the timed presentation script, the live self-healing closer, likely questions, fallbacks.

## The "break it yourself" demo (self-healing, live)

```bash
./kavach watch cleanjson        # dashboard goes live; baseline run shows the target is clean
```

Now hand the keyboard to a judge: open `targets/cleanjson/src/cleanjson.c`, delete the
bounds check (`if (idx >= size) break;`), save. Within seconds KavachForge:

1. notices the edit via live `git diff` and ranks exactly that function (changed lines cited),
2. finds the fault (~0.1 s), classifies it (CWE-125, Out-of-bounds Read),
3. synthesizes the fix — the very line they deleted — and proves it through gates G0–G3,
4. **generates a regression test from the proof-of-vulnerability and proves the test itself**
   (G4: it crashes the unpatched code and passes the patched code),
5. writes a merge-ready pull request: `PR.md` + one `fix.patch` carrying fix *and* test.

`./kavach reset cleanjson` restores the original. Nothing leaves the local target directory.

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
./kavach selftest          # 27 built-in unit tests
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

### Bring your own repository — one command

The finale hands teams unfamiliar open-source repositories. `kavach onboard` turns any C/C++ repo into a task with no hand-written config:

```bash
./kavach onboard https://github.com/DaveGamble/cJSON --run          # clone, scan, build-fix, run
./kavach onboard ./some/checkout --provider anthropic --run         # a model wires non-trivial APIs
./kavach onboard <url> --ref v1.7.7 --harness read --time 120       # tag, harness choice, budget
```

What it does, in order — every decision is printed, nothing is guessed silently:

| step | what happens |
|---|---|
| fetch | shallow clone into `targets/_onboarded/<name>` (git-ignored), or use a local path in place |
| scan | library sources vs. tests/examples/tools/benchmarks; header dirs; every shipped `LLVMFuzzerTestOneInput` |
| compile pass | each file must compile here; files that export `main` (checked with `nm`, so an `#ifdef`'d test main does not count) are dropped |
| build-fix | link the harness and repair iteratively: duplicate symbol → drop the re-definer; undefined reference → add `-lm/-lpthread/-ldl/-lz` or re-add a skipped helper that defines it; missing generated headers → try `cmake`/`./configure` |
| harness | if the repo ships none: rank public parser-shaped entry points (static and internal helpers never qualify), template a harness for buffer-first signatures, or hand a member function / context-first API to the model (C or C++, `extern "C"` added) |
| sanity | the discovery binary must run cleanly on `""`, `"x"`, `"{}"` … — a harness that faults on trivial input is flagged **SUSPICIOUS** before any finding is trusted |
| emit | `tasks/<name>.json` (one per harness), seeds from any `corpus/`/`seeds/` dir, `diff: git` wired for risk ranking; header-only libraries get a generated translation unit and the header as patch scope |

Validated on repos the project had never seen: **parson, sds, jsmn (header-only), cJSON (shipped harness, straight from GitHub), tinyxml2 (C++, model-written harness)** — and honestly refused on **libpng** offline (callback-based API; needs a model). A planted off-by-one in parson was found in 0.1 s, classified CWE-787, repaired at the allocation (root cause) and proven through all six gates with no hand-written configuration.

### Any stack — the universal track

If the repo is not a C/C++ library (Node, Python, Go, Java, PHP, Ruby, Rust, C#, …) — or if the
C track cannot build a harness — `kavach onboard` routes it to the **universal track**: the same
find → patch → prove discipline with different oracles, because those stacks have no sanitizer
crash to anchor on.

| stage | fuzz track (C/C++) | universal track (any stack) |
|---|---|---|
| discover | libFuzzer / standalone + ASan | semgrep (16 rule packs, cached locally — offline) or 26 built-in patterns when semgrep is absent |
| evidence | PoV input that crashes | exact lines, CWE, severity, analyzer message; one finding per weakness per function |
| repair | heuristic + model ensemble | mechanical hardening (cookie flags, `safe_load`, TLS verify…) + model ensemble (SEARCH/REPLACE edits, tolerant of small-model output) |
| G0–G2 | apply · rebuild · PoV blocked | apply · syntax (`node --check`, `py_compile`, `php -l`, `gofmt`…) · **re-scan: finding gone, nothing new** |
| G3 | repo tests | repo tests — no *new* failure vs. baseline (`npm test`, `pytest`, `go test`, `mvn`, `cargo`); honestly skipped when the suite needs a DB |
| G4/G5 | regression test proven + behaviour differential | model-written **proof test** that fails unpatched / passes patched — claimed only when it discriminates |
| approval | `--approve critical` pauses before auth/session/crypto/payment/config files | same; `--approve all` before every patch; `--yes` for unattended |

```bash
./kavach onboard https://github.com/OWASP/NodeGoat --run --provider ollama   # Node app, local model
./kavach run nodegoat --approve all                                          # choose every patch yourself
```

On OWASP NodeGoat (never seen before): 26 analyzer results → 11 unique findings (eval injection,
hard-coded credentials, open redirect, session config, template XSS…); the eval injection in
`handleContributionsUpdate` is patched by the local 7B model (two strategies offered, human
approval requested because it is a request handler) and passes G0–G2; the test suite is
reported *not runnable here* (needs MongoDB) rather than faked.

### Fully offline

`./kavach prefetch` caches the rule packs and pulls a local model; after that nothing needs
the network. See **docs/OFFLINE_MODELS.md** for which model fits which laptop.

### Or write the task by hand

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
  tests/          27 stdlib unit tests  (./kavach selftest)
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
