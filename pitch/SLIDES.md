# KavachForge — 5-Slide Outline (finale presentation)

**Slide 1 — From alert to evidence**
- Problem: code changes outpace secure review; scanners flag, they don't prove; LLMs can hallucinate findings and "fixes" that just hide a failing test.
- Need: an evidence gate between AI suggestion and action.

**Slide 2 — KavachForge**
- One line: a cyber-reasoning system that *finds → proves → patches → verifies*.
- Closed loop diagram: diff → risk → seeds+fuzz → reproduce+dedup → patch → build+PoV-replay+tests → evidence.

**Slide 3 — Why it's different**
- Diff-to-Sink prioritization (explainable, pre-LLM).
- LLM ↔ fuzzer seed sharing clears format gates fast.
- **Evidence gates**: no finding without a PoV; no fix until it builds, blocks the PoV, and passes tests.
- Zero dependencies, offline-deterministic, one-command Docker.

**Slide 4 — Prototype & metrics**
- C/C++ + Docker + libFuzzer/ASan + provider-agnostic LLM.
- Live: 2 verified CWE-787 patches + 1 clean control (no false positive).
- 0 unverified alerts, time-to-first-PoV in seconds, ≤6 LLM calls/target, 100% audit trail.

**Slide 5 — Defence impact & boundary**
- Faster, trustworthy secure updates with a full audit trail.
- Private/air-gapped model path; human approves every patch — recommend, don't deploy.
- Roadmap: more languages, CodeQL/SARIF, CI integration, signed evidence bundles.

> A polished PowerPoint can be generated from this outline on request.
