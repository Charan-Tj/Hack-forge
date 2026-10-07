# KavachForge — How to Run and How to Test

This is the complete operator guide: installing on any machine, every command, what
each one should print, how the testing works at three levels, and what to do when
something looks wrong. For the judge presentation itself, see `docs/JUDGE_DEMO.md`.

---

## 1. What you need

KavachForge has **zero Python dependencies** (standard library only). You need one of:

| Option | Needs | Engine you get |
|---|---|---|
| **A. Docker** (recommended for portability) | Docker Desktop / Engine running | coverage-guided **libFuzzer** + ASan (identical on every OS) |
| **B. Native Linux** | Python 3.9+, `patch`, `clang llvm libclang-rt-dev` | libFuzzer + ASan |
| **C. Native macOS** | Python 3.9+, `patch`, Xcode CLT (`xcode-select --install`) | standalone ASan engine (Apple clang has no libFuzzer runtime) |
| **D. Native, gcc only** | Python 3.9+, `patch`, `gcc` with libasan | standalone ASan engine |

Both engines run the same harness and produce the same findings; libFuzzer is faster
(millions of executions per run) and is what the Docker image ships.

### Install commands

```bash
# Ubuntu / Debian (libFuzzer engine)
sudo apt-get update && sudo apt-get install -y clang llvm libclang-rt-dev patch git python3

# Ubuntu / Debian (minimal, standalone engine)
sudo apt-get install -y gcc patch git python3

# macOS
xcode-select --install            # provides clang with AddressSanitizer + patch
python3 --version                 # 3.9+ (ships with Xcode CLT, or brew install python)

# Any OS with Docker: nothing else to install
```

---

## 2. Get the code

```bash
git clone https://github.com/SajalDevX/kavachforge.git
cd kavachforge
chmod +x kavach
```

---

## 3. First run (3 commands)

```bash
./kavach doctor        # 1. environment check -> must end with "doctor: READY"
./kavach selftest      # 2. unit tests        -> must end with "OK"
./kavach showcase      # 3. the full run with live dashboard at http://localhost:8777
```

With Docker instead of a native toolchain, prefix any command with `--docker`:

```bash
./kavach --docker doctor
./kavach --docker showcase      # first run builds the image (~2 min), later runs are instant
```

### What `doctor` should print

```
▶ [1] Environment check
  ✔ python 3.x.y
  ✔ patch found
  ✔ toolchain: clang libFuzzer + AddressSanitizer (coverage-guided)   <- or "gcc + AddressSanitizer (standalone)"
  docker: /usr/bin/docker  (optional)
  ✔ doctor: READY
```

If it prints `ISSUES FOUND`, the line above it says exactly what is missing.

---

## 4. Every command

| Command | What it does |
|---|---|
| `./kavach showcase [task] [--fresh] [--port N]` | Starts the live dashboard **first**, then runs every bundled target (or one). Index + per-target dashboards update after each stage. Stays serving until Ctrl-C. |
| `./kavach watch <task>` | **Live self-healing mode.** Makes the target a git baseline, runs it once, then re-runs the full loop every time a file under the target is saved (risk ranking driven by the live `git diff`). |
| `./kavach reset <task>` | Restores a watched target to its baseline (`git checkout` + clean). |
| `./kavach onboard <url-or-dir> [--run]` | **Bring your own repo.** Clone, scan, build-fix, find or write a harness, emit a task (§7a). |
| `./kavach run <task>` | Full loop on one target, no server. |
| `./kavach demo` | All three targets, no server. |
| `./kavach replay [task]` | Deterministic offline run: forces the heuristic brain, no network, no key. Same numbers every time. |
| `./kavach serve [--port N]` | Serve existing `artifacts/` dashboards only. |
| `./kavach doctor` | Environment check. |
| `./kavach selftest [-v]` | 43 unit tests (stdlib `unittest`). |
| `./kavach list` | List bundled targets, plus onboarded/synthesized ones. |
| `./kavach clean` | Delete `artifacts/`. |

### Useful flags (run / demo / showcase / watch)

| Flag | Meaning |
|---|---|
| `--provider anthropic\|openai\|ollama\|offline` | Which model to use. Default: auto (key present → that provider; else offline). |
| `--model <id>` | Model id for the provider. |
| `--budget N` | Max live LLM calls per target (default 6). |
| `--engine libfuzzer\|standalone` | Force an engine (falls back if unavailable). |
| `--uplift` | Also measure time-to-crash from an *empty* corpus vs. with structure-aware seeds (honest A/B). |
| `--diff git\|<file.diff>` | Drive risk ranking from a live `git diff` of the target, or a diff file. |
| `--sarif <file>` | Ingest static-analysis results (SARIF 2.1) as risk signals. |
| `--keep` | Keep the patch worktrees for inspection. |

### Universal web-app behaviour probe (optional G5)

Universal tasks may define an HTTP behaviour probe. Every requested host and port
must be explicitly listed in `allowed_targets`; probe traffic is sequential and
limited to 5 requests per second by default. Set `rate_limit` lower if the local
service needs more time between requests.

```json
{
  "allowed_targets": ["localhost:4000"],
  "http_probe": {
    "base_url": "http://localhost:4000",
    "login": {"path": "/login", "user": "user1", "password": "User1_123"},
    "routes": ["/dashboard", "/contributions", "/allocations/2", "/profile", "/benefits"],
    "rate_limit": 5,
    "restart_cmd": ["npm", "start"],
    "restart_timeout": 60
  }
}
```

G5 first records a baseline using a fresh cookie session, extracts the hidden
`_csrf` token, logs in, and replays the listed routes. Before the patched probe,
`restart_cmd` must actually restart the service from the patched worktree; if it
is absent, G5 is reported as `skipped (restart_cmd not configured)` rather than
claiming that the patched app was tested. Status changes, error pages, and
normalized response-body changes reject the candidate.

### Using a live model (optional)

```bash
export ANTHROPIC_API_KEY=sk-...        # or OPENAI_API_KEY=...
./kavach showcase --fresh
# fully local model:
export KAVACH_LLM_PROVIDER=ollama KAVACH_LLM_MODEL=llama3.1   # Ollama at localhost:11434
```

Without a key everything still runs (offline brain). Every prompt and response is written
to `artifacts/<task>/llm_log/`, and responses are cached in `cache/llm/` so a rerun
costs nothing — and completes even if the endpoint goes down mid-run.

---

## 5. What a successful run looks like

For `tinyimg` and `recordcfg` (the two vulnerable targets):

```
▶ [1] Risk prioritization (diff → sink)
  ✔ ranked 1 function(s); top = tinyimg_parse (score 10)
▶ [2] Build target & generate seeds
  ✔ built discovery binary (libfuzzer engine)
  ✔ 10 seeds ready (offline-heuristic); magic gate: TIMG
▶ [3] Hybrid discovery (seeds + fuzzing)
  ✔ first crash via libfuzzer after 0.1s; harvested 46 raw crash(es), 5 execs
▶ [4] Reproduce, deduplicate & classify
  ✔ KV-TINYIM-001  CWE-787 (Out-of-bounds Write (stack), High)  at tinyimg.c:46  [7 duplicate(s) collapsed]
▶ [5] Repair & verify — KV-TINYIM-001
  ✔ G0 patch applies — patching file src/tinyimg.c
  ✔ G1 rebuild — clean build
  ✔ G2 PoV blocked — no crash on PoV
  ✔ G3 tests — ALL TESTS PASSED
  ✔ G4 regression test — crashes unpatched: yes | passes patched: yes
  ✔ PATCH VERIFIED — builds, blocks PoV, tests pass
  ✔ REGRESSION TEST PROVEN — regress_kv_tinyim_001.c
  ✔ PR bundle: pr/KV-TINYIM-001
▶ [6] Evidence bundle
  ✔ findings: 1   verified patches: 1   unverified alerts: 0
  ✔ manifest : bundle sha256 ...
```

For `cleanjson` (the control target, no bug):

```
  ⚠ no crash within budget (13s, 10,294,649 execs) — clean target?
  ✔ findings: 0   verified patches: 0   unverified alerts: 0
```

That "no finding" result is correct and important: it proves the system does not invent
bugs.

### The artifacts

Every run writes `artifacts/<task>/`:

| File | Contents |
|---|---|
| `dashboard.html` | Visual evidence chain (stage strip, risk ledger, finding cards, gates, diff, PoV, sanitizer report, deliverable links). |
| `evidence.json` | The same, machine-readable: ingestion sources, risk ledger, discovery stats, findings, patch, gate outcomes, metrics, LLM budget. |
| `manifest.json` | sha256 of every artifact + a bundle hash (tamper-evident). |
| `run.log` | Full console transcript. |
| `crashes/` | Raw crash inputs harvested (`crash-*`); the PoV for each finding is one of these. |
| `regress/regress_<id>.c` | The regression test generated from the PoV. |
| `pr/<id>/PR.md`, `pr/<id>/fix.patch` | Merge-ready pull request: write-up + one patch carrying the fix and the test. |
| `llm_log/` | Every prompt/response (live, cached, or error). |

Apply a PR bundle to a copy of the target to confirm it is real:

```bash
cp -r targets/recordcfg /tmp/t && cd /tmp/t
patch -p1 < ~/kavachforge/artifacts/recordcfg/pr/KV-RECORD-001/fix.patch
# -> patches src/recordcfg.c and creates tests/regress_kv_record_001.c
```

---

## 6. How testing works (three levels)

### Level 1 — unit tests of KavachForge itself
```bash
./kavach selftest -v
```
27 tests covering: CWE mapping (incl. read/write direction), diff and SARIF ingestion,
risk scoring, stack-signature normalization/dedup, patch policy (scope, tampering,
removal-only), heuristic repair synthesis for all three bug shapes, regression-test
generation, LLM transport parsing for each provider, budget and cache behaviour,
prompt normalization. Expected: `Ran 27 tests ... OK`.

### Level 2 — each target's own regression suite
Each target ships `tests/test_<name>.c`. These are the tests that gate **G3** must keep
green after a patch. Run one by hand:
```bash
clang -g -fsanitize=address -Itargets/tinyimg/src \
  targets/tinyimg/src/tinyimg.c targets/tinyimg/tests/test_tinyimg.c -o /tmp/t && /tmp/t
# -> "ALL TESTS PASSED"
```
Every run also executes this suite on the *unpatched* tree and reports
`baseline regression tests: PASS`.

### Level 3 — the executable proof gates (what makes a result trustworthy)
These are not opinions; each is a command whose exit code is recorded in `evidence.json`:

| Gate | Proves |
|---|---|
| reproduce (verifier) | the crash happens again in a fresh process → it is a real finding |
| **G0** | the patch applies cleanly to a clean copy |
| **G1** | the patched target rebuilds |
| **G2** | the exact proof-of-vulnerability input no longer crashes |
| **G3** | the target's regression suite still passes |
| **G4** | the generated regression test crashes the unpatched tree **and** passes the patched tree |

A finding is reported only after reproduce; a patch is `Verified` only after G0–G3; G4 proves
the shipped test. Anything that fails a gate is shown as `Rejected` with the failing gate —
never hidden.

### End-to-end smoke test (deterministic)
```bash
./kavach clean && ./kavach replay
```
Expected summary:
```
tinyimg      raw=N  unique=1 verified=1 first_pov=0.xs
recordcfg    raw=N  unique=1 verified=1 first_pov=0.xs
cleanjson    raw=0  unique=0 verified=0 first_pov=n/a
```

### Testing the self-healing mode
```bash
./kavach watch cleanjson            # terminal 1 — wait for "watching for edits…"
# terminal 2 / editor:
#   open targets/cleanjson/src/cleanjson.c, delete the line:  if (idx >= size) break;
#   save -> terminal 1 shows the full loop ending in PATCH VERIFIED + REGRESSION TEST PROVEN
./kavach reset cleanjson            # restore
```

---

## 7. Bring your own target

### 7a. The one-command way (what you will do at the finale)

```bash
./kavach onboard https://github.com/<org>/<repo>            # or a local directory
./kavach onboard https://github.com/<org>/<repo> --run      # ...and run the loop
./kavach onboard <repo> --provider anthropic --run          # model writes the harness when
                                                            # the API is not a plain parse(buf,len)
```

Options: `--name` (task name), `--ref` (branch/tag), `--harness <substring>` (pick one of
several shipped harnesses), `--time <s>` (fuzzing budget), `--all-harnesses` (with `--run`).

Read the output top to bottom — it is the audit trail:

```
→ scan: 2 library source(s), 1 harness(es), 12 header dir(s), 73 skipped
→ build-fix: harness fuzzing/cjson_read_fuzzer.c
→   links with 2 source file(s)
  harness  : fuzzing/cjson_read_fuzzer.c  (shipped by the repo)
  sources  : 2 kept
  → dropped xmltest.cpp — defines main() - a program, not library code
  → harness ...: sanity OK (clean on trivial inputs)
✔ 1 task(s) written; 2 source file(s) kept, 0 dropped
✔ task     : tasks/cjson-oss.json
```

Exit codes: 0 onboarded, 2 could not build a harness (the last line says why — usually
"no fuzzable entry point" for callback-style APIs, which `--provider` fixes), 1 bad input.

Tested on real repos (all offline unless noted): parson ✔, sds ✔, jsmn (header-only) ✔ with
a model, cJSON ✔ (its own `fuzzing/` harness), tinyxml2 (C++) ✔ with a model, libpng ✖
offline (honest refusal: no byte-buffer entry point). Clones live in
`targets/_onboarded/` (git-ignored); a generated harness lives in `<repo>/.kavach/`.

### 7b. Any stack (universal track)

`kavach onboard` picks the track automatically: C/C++ library → fuzz track; anything else
(or a C repo whose harness cannot be built) → universal track. Force it with `--mode universal`.

```bash
./kavach onboard https://github.com/OWASP/NodeGoat --run --yes            # unattended
./kavach onboard ./myapp --run --approve all                               # approve each patch
./kavach run myapp --provider ollama --deps                                # install deps so G3 (tests) can run
```

Flags: `--approve critical|all|auto` (default critical), `--yes` (never prompt),
`--scanner auto|semgrep|builtin`, `--max-findings N` (default 12), `--deps`,
`--deadline-min M` (hard time box; report always written), `--no-review`.
Input can be a git URL, a directory, or a `.tar.gz`/`.zip` of the source.
Every run also writes `artifacts/<name>/report.md` + `report.csv` (S.No · title · severity ·
location · steps taken) containing only SUBMIT findings — see docs/JUDGE_DEMO.md §7.
Read the gates exactly as in the fuzz track; "not runnable here" / "not claimed" are honest
skips, never passes in disguise.

### 7c. Offline

`./kavach prefetch` once with network (rule packs + local model), then everything runs
air-gapped. Details and model sizes: docs/OFFLINE_MODELS.md.

### 7d. By hand

Any libFuzzer / OSS-Fuzz-style harness (`LLVMFuzzerTestOneInput`) works. Add
`tasks/<name>.json`:

```json
{
  "name": "mylib",
  "description": "what it parses",
  "root": "targets/mylib",
  "sources": ["src/parser.c"],
  "include_dirs": ["src"],
  "harness": "harness/fuzz_parser.c",
  "test_sources": ["src/parser.c", "tests/test_parser.c"],
  "patch_scope": ["src/parser.c"],
  "magic": "MLIB",
  "diff": "git",
  "sarif": "scan/results.sarif",
  "budgets": {"time_budget_s": 45, "rng_seed": 1337}
}
```
Then `./kavach run mylib` (or `watch mylib`). `patch_scope` is the only thing the repair
may edit — harness, tests and flags are off-limits by policy.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `doctor` says no toolchain | Install clang+compiler-rt or gcc+libasan (section 1), or use `--docker`. |
| `patch NOT found` | `apt-get install patch` / Xcode CLT. |
| Build fails with `libclang_rt.fuzzer ... not found` | compiler-rt missing: `apt-get install libclang-rt-<ver>-dev`, or the engine auto-falls back to standalone if gcc exists. |
| Dashboard doesn't update | It polls `evidence.json` every 1.5 s while a run is live; hard-refresh once. Make sure you opened the URL printed by `showcase`. |
| Port 8777 busy | `--port 8800`. |
| Want identical numbers every time | `./kavach replay` (offline, fixed RNG). |
| Model call fails | It falls back to cache → offline brain automatically; check `artifacts/<task>/llm_log/` for the error. |
| `watch` doesn't react | Make sure you edited a file under the target's `root` and saved; `git -C targets/<task> diff` must show the change. |
| macOS: `clang: not found` in doctor | Normal — `/usr/bin/gcc` (Apple clang) is used; the standalone engine runs. |

---

## 9. Safety notes

- All compilation, fuzzing and validation run against the local supplied target only, with
  CPU-time and hard RSS limits. Nothing on the network is ever scanned.
- The original target is never modified by a run (patches are proven on a copy);
  `watch` creates a git baseline so your own edits are always reversible with `reset`.
- Model output is treated as untrusted text; only a fixed command template is executed.
- API keys are read from the environment and never written to logs or evidence.
- Every patch is a recommendation for human review. KavachForge does not deploy.

---

## 10. v1.3 features & commands

| Command | What it does |
|---|---|
| `./kavach ci [--base REF] [--all] [--fail-on any\|unverified\|none]` | Pull-request check: runs on the targets a change touched (via `git diff REF...HEAD`), writes `artifacts/ci-summary.md` (PR comment), emits repo-root fix patches to `artifacts/ci-fix/`, and sets the exit code. |
| `./kavach harness <src-or-target> [--run] [--provider ...]` | Discovers a fuzzable entry point in an unfuzzed C source, synthesizes + validates a libFuzzer harness and a task, then (with `--run`) runs the loop. |

**GitHub Actions:** `.github/workflows/kavachforge.yml` installs the toolchain, runs `doctor` + `selftest`, runs `kavach ci`, uploads the evidence bundles, comments the summary on the PR, and opens a `kavachforge/fix-*` PR when a verified fix exists. Set the repo secret `ANTHROPIC_API_KEY` to use a live model; otherwise it runs offline. For the auto fix-PR, enable *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests*.

**New gates in the loop:** G4 (regression test generated from the PoV, proven on both trees) and G5 (behaviour preservation — the corpus is replayed through a behaviour `probe` on the unpatched vs patched tree; any changed result on a previously-valid input rejects the patch). Each finding now runs a **patch ensemble**: multiple candidates, all gated, the one closest to the root cause wins (shown in `evidence.json` under `candidates`).

**New targets:** `sigpkt` (FNV-1a digest-gated — shows the seed-generator cracking a gate the fuzzer can't; run `./kavach run sigpkt --uplift`), and `urlparse` (unfuzzed — use `./kavach harness urlparse --run`).
