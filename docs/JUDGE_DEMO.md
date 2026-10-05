# KavachForge — Judge Demo Guide

How to present KavachForge at the AI Kavach finale: setup, a timed walkthrough with
what to run, show and say, the live self-healing closer, likely questions, and fallbacks.
Operating details are in `docs/RUN_AND_TEST.md`.

---

## 0. The message

The track asks for a cyber-reasoning system that finds a vulnerability, patches it, and
proves the fix holds. KavachForge does that and adds one more proof: it turns the
proof-of-vulnerability into a permanent regression test, proves the test itself, and
produces a merge-ready pull request for a human to approve.

Three rules to repeat during the demo:
1. No finding without a reproducible crash.
2. No fix until it builds, blocks that crash, and passes the tests.
3. No fix without a proven regression guard.

Judging weights (20% each): innovation & relevance, feasibility, illustration, technical
depth, presentation. Each segment below targets one.

---

## 1. Setup (10 minutes before)

```bash
cd kavachforge
./kavach doctor      # READY
./kavach selftest    # OK
./kavach clean
```

- Projector: browser at `http://localhost:8777` (open it as soon as `showcase` prints the URL).
- Laptop: terminal with a large font.
- Engine: Docker available → `./kavach --docker showcase --fresh` (build the image earlier
  with `./kavach --docker doctor`). No Docker → `./kavach showcase --fresh`.
- Model: with `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` exported, seeds and patches come from
  a live model; do one dry run beforehand so the cache is warm. Without a key, the offline
  brain runs — say so if asked.
- Keep a second terminal ready for the closer.

---

## 2. Walkthrough (about 6 minutes)

### A. Problem (30 s)
"Code changes outpace security review. Scanners flag but don't prove. Language models can
write fixes but can also invent findings or hide a failing test. We put an evidence gate
between an AI suggestion and any action."

### B. Start (15 s)
```bash
./kavach showcase --fresh
```
Open the URL on the projector. Three target cards move from queued → running → result.
"Two targets have seeded memory-safety bugs; the third is a clean control."

### C. Inputs and risk ranking (45 s) — innovation, technical depth
Open `tinyimg`. Show *Input signals* and the *Risk ledger*.
"Ranking starts from signals teams already have: this one from a real developer diff (the
score cites the changed lines), the next from a real SARIF scan file. The score is
deterministic and explainable — changed in diff, contains a risky copy/index operation,
reachable from the fuzz entry point, scanner alert. No model has been consulted yet."

### D. Discovery and dedup (45 s) — technical depth
Point at the tiles: *raw crashes → unique*, *time to first PoV*, *fuzz execs*.
"Structure-aware seeds pass the format's header gate so fuzzing reaches the deep branch in
a fraction of a second. Dozens of raw crashes are collapsed into one finding by a
normalized stack signature — one report per real bug."

### E. Evidence (45 s) — illustration
Open the finding card: PoV hash and size, reproduce command, CWE and severity, crash site,
sanitizer report, hex dump.
"Everything here is a command you can re-run. Nothing is a model's opinion."

### F. Repair and proof (60 s) — feasibility, technical depth
Show the diff and the gates.
"A minimal guard at the root cause. Policy forbids touching tests, the harness or build
flags; if a model's first try breaks policy the reason is fed back and it tries again. Then
four gates run in a clean copy: apply, rebuild, the exact crash input no longer crashes,
the regression suite still passes. Only then is it Verified. Gate five proves the generated
regression test: it fails on the old code and passes on the fixed code."
Click *PR.md*: "A merge-ready pull request — fix, test, evidence — for a human to approve."

### G. Control (30 s) — honesty
Open `cleanjson`: millions of executions, no finding.
"It does not invent bugs. Zero unverified alerts, by construction."

### H. Boundary (15 s)
"Manifest hashes, run log, every model prompt logged, a hard budget on model calls, and a
human approves every patch. The system recommends; it never deploys."

---

## 3. The closer — live self-healing (2 minutes)

```bash
./kavach watch cleanjson
```
Wait for `watching for edits…` (the baseline run shows the control is clean). Then hand
the laptop to a judge:

1. Open `targets/cleanjson/src/cleanjson.c`.
2. Delete the line `if (idx >= size) break;` and save.
3. Within seconds the terminal and dashboard show: change detected from the live git diff →
   the edited function ranked → crash found → classified (CWE-125) → the deleted line
   re-synthesized → gates G0–G4 green → regression test proven → PR bundle written.
4. Open `artifacts/cleanjson/pr/KV-CLEANJ-001/PR.md` on the projector.
5. `./kavach reset cleanjson` restores the file. Repeat if asked.

Say: "It did not just patch the bug. It wrote the test that keeps this bug from coming
back, proved that test works, and wrote the PR. A person still clicks merge."

If a judge edits something that is not a memory-safety bug, the run reports no verified
crash — point out that this is the no-false-positive guarantee working.

---

## 4. Likely questions

- **Does it work on real projects?** Yes: any libFuzzer / OSS-Fuzz-style harness, with
  `--diff git` and `--sarif <file>`. The bundled targets are small so the full loop fits
  in a live session.
- **Why not just ask a model?** It can invent findings and hide failures. We gate on
  executable proof: reproduce, rebuild, replay, tests, and the regression guard.
- **What if the model is wrong?** Policy rejects out-of-scope or tampering patches; the
  rejection reason is fed back for one more attempt; a failing gate shows as Rejected.
- **What if the network dies?** Responses are cached with normalized prompts, and an
  offline deterministic brain runs with no key at all. The demo completes either way.
- **Air-gapped deployment?** Yes — a local model via Ollama, or no model.
- **Scale?** Stateless per target, filesystem coordination, one process; run targets on
  separate runners. Roadmap: CI pull-request integration, call-graph reachability,
  more languages.
- **What it is not:** not a claim of complete coverage, not multi-language yet, not
  autonomous deployment.

---

## 5. Fallbacks

| Problem | Do |
|---|---|
| No toolchain on the laptop | `./kavach --docker showcase` |
| No Docker and no compiler | `./kavach serve` shows the last good artifacts; narrate from them |
| Network down / no key | nothing changes; or `./kavach replay` for identical numbers |
| Anything odd mid-demo | `./kavach clean && ./kavach replay` (about one minute) |
| Port busy | `--port 8800` |

Numbers from a reference run (libFuzzer engine): time to first PoV ≈ 0.1 s; ~45 raw
crashes → 1 finding per target; 2 patches Verified with G4 proven; control target 10M+
execs with 0 findings; 27/27 unit tests.

---

## 6. v1.3 extra segments (pick per audience)

**Seed generator vs. a gate a fuzzer can't crack (~45s).**
`./kavach run sigpkt --uplift`. sigpkt's header carries an FNV-1a digest. Point at the uplift line: **seeded ≈ 0.1s, unseeded = no crash in 20s**. Say: "The model writes a small program that computes the digest and generates valid inputs. Coverage-guided fuzzing alone cannot solve a 32-bit keyed checksum — this is the honest, measured difference the LLM makes."

**Harness synthesis on an unfuzzed library (~45s).**
`./kavach harness urlparse --run`. Say: "This C file shipped with no harness. KavachForge finds the parser entry point, writes a libFuzzer harness, validates that it compiles and runs cleanly, then finds and fixes two out-of-bounds writes." (Addresses the PRD's one explicit non-goal.)

**Patch ensemble + behaviour gate (point at any finding card).**
"It doesn't write one patch — it writes several (validate-at-read, guard-at-use, clamp), runs all of them through every gate, and picks the one closest to the root cause. Gate G5 replays hundreds of valid inputs through a behaviour probe; a patch that silently changes any of them is rejected. Published research found 40% of patches that pass 'PoC + tests' are still wrong — G5 is exactly that check."

**Bring-your-own-repo (the finale format) (~2 minutes).**
Ask the judges for any C/C++ GitHub URL — or use one you have cloned. Run
`./kavach onboard <url> --run` (add `--provider anthropic` if a key is set). Narrate the
scan/build-fix lines as they appear: "It found the library files, dropped the test program
because the object exports main, found the repo's own fuzzer — or wrote one — and checked
that the harness does not fault on trivial input before trusting any finding." Then the
normal loop runs. Rehearsed offline on parson, sds, cJSON; with a model on jsmn and tinyxml2.
If a repo cannot be onboarded, the last line says exactly why — read it out loud; honesty
about a callback-style API is worth more than a fake success.

**Any-stack repo with a local model, fully offline (~4 minutes).**
Wi-Fi off. `./kavach onboard <their repo> --run --provider ollama`. Narrate: "No C here, so
the fuzzer has no oracle; KavachForge switches to the universal track: 16 cached rule packs,
26 results, 11 unique findings ranked by CWE severity." When it pauses — **APPROVAL REQUIRED,
touches a critical area** — pick a candidate out loud: "It never patches a request handler,
auth or crypto file without a human; and it offers alternatives, not one answer." Then read the
gates: syntax, re-scan (finding gone, nothing new), tests (or honest 'not runnable: needs
MongoDB'), proof test (claimed only if it discriminates). Close with: "The model is a 7B coder
running on this laptop; everything you saw works with the network cable unplugged."

**CI integration (if you have network + the repo open).**
Open a PR that deletes a bounds check → the KavachForge Action comments a summary table, fails the check, and opens a `kavachforge/fix-*` PR with the fix + regression test. Say: "This is the whole loop wired into a real pull-request workflow."
