# KavachForge — Pitch & Judge Demo

## One sentence
KavachForge turns a suspicious code change into a **verified security decision**:
it finds a reproducible crash, patches the root cause, and *proves* the fix holds —
with an auditable evidence trail, not model confidence.

## The core idea (say this first)
> "The novelty isn't an LLM that claims to find bugs. It's a constrained
> AI + fuzzing workflow that turns model suggestions into **reproducible,
> auditable cyber-defence actions**. Nothing is a finding without a
> proof-of-vulnerability; nothing is a fix until it builds, blocks that PoV,
> and passes the tests."

## Live demo script (~4 minutes)
1. **Mission (15s):** "From alert to evidence." Show the pipeline line in the README.
2. **Risk (30s):** `./kavach run tinyimg` — point at the **risk ledger**: the parser
   is ranked top because it's changed, reaches a copy/index sink, and is reachable
   from the fuzz entry. This is deterministic and explainable (pre-LLM).
3. **Discovery (30s):** an LLM/structure-aware **seed clears the `TIMG` magic gate**
   and the sanitizer fires a stack-buffer-overflow. Note: blind mutation would waste
   time on the 4-byte gate; the seed reaches the deep branch immediately.
4. **Evidence (45s):** open the report — PoV hash, reproduce command, normalized
   stack signature, CWE-787 + severity, root-cause line.
5. **Repair (45s):** show the **minimal unified diff** (a bounds guard at the root
   cause) and the policy check (no test/harness/flag edits). If live, mention the
   self-reflection retry loop.
6. **Proof (45s):** the four gates go green live — **apply → rebuild → PoV blocked →
   tests pass → VERIFIED**.
7. **No false positives (30s):** `./kavach run cleanjson` — the control target. After
   a full bounded fuzzing run it reports **no finding**. "It doesn't invent bugs."
8. **Close (15s):** human-in-the-loop — "ready for analyst review, not auto-deploy."

Fallback if anything is flaky: `./kavach replay` (offline, deterministic).

## Why we'll win (the differentiators)
- **Evidence gates** — most teams stop at "the model found/fixed it." We *prove* it.
- **Zero-dependency & offline-capable** — standard library only; a deterministic
  replay means the demo literally cannot fail on venue Wi-Fi.
- **Portable** — one Docker command reproduces the exact toolchain on any judge's
  laptop; a standalone engine even runs without the libFuzzer runtime.
- **Auditable** — `evidence.json` + dashboard: risk, PoV, stack signature, CWE,
  diff, and every gate outcome.
- **Honest** — a control target proves no-false-positive behavior; rejected patches
  are shown as rejected.

## Metrics we hit (from one `showcase` run, libFuzzer engine)
- 2 unique, reproducible crashes — **~45 raw crashes each collapsed to 1 finding** by
  normalized stack signature (distinct signatures across targets)
- time-to-first-PoV: ~0.1 s per target
- 2 verified minimal patches (apply + build + PoV blocked + tests pass)
- control target: **10M+ coverage-guided execs, 0 findings** (no false positive)
- 0 unverified alerts reported; 100% audit trail (evidence.json, manifest.json, run.log,
  llm_log/); LLM calls within budget (≤6/target); 23/23 self-tests
- resilience exercised: live model → cached rerun (0 calls) → model endpoint dead
  (still Verified from cache) → no cache/no model (still Verified, offline brain)

## Scope & honesty (pre-empt the hard question)
- Target class for the finale: Docker-buildable C/C++ with a libFuzzer harness.
- Not claimed: zero-days across arbitrary repos, multi-language, auto-deploy,
  semantic correctness beyond the supplied tests. Roadmap below.

## Roadmap (post-finale)
1. Coverage: Java/Python + more sanitizers.
2. Accuracy: CodeQL/Semgrep/SARIF ingestion + call-graph reachability.
3. Operations: CI / pull-request integration, isolated runners.
4. Deployment: air-gapped model endpoint, signed evidence bundles.

## References (design inspiration; independently implemented)
- DARPA AI Cyber Challenge (AIxCC) scoring overview — darpa.mil
- Trail of Bits, Buttercup CRS (open source) — github.com/trailofbits/buttercup
- Team Atlanta Atlantis CRS — github.com/Team-Atlanta
- OSS-CRS: liberating AIxCC cyber-reasoning systems (research paper)
- Terrier Cyber Quest 2026 / AI Kavach track

## v1.2 — the closer (self-healing + self-testing)
- `./kavach watch <target>`: a judge deletes a bounds check live; the system detects the
  edit from `git diff`, finds the fault, re-synthesizes the exact line, proves the patch
  (G0–G3), **generates a regression test from the PoV and proves it** (G4: fails
  unpatched, passes patched), and writes a merge-ready PR (`PR.md` + `fix.patch`).
- Line to land: "Finding and fixing is table stakes. We make sure the bug can never
  come back — and we prove that too."
