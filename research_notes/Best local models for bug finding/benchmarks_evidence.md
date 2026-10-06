# Published benchmarks and studies (2024–2026) on LLM vulnerability detection and repair, with emphasis on small/medium open-weight models

Notes conventions: "[older]" marks pre-2025 work; "[vendor-reported]" marks figures published by the organisation that built the tool/model/benchmark being scored. Numbers are as reported in the cited source; several were read via fetched summaries of the papers, so treat exact decimals as approximate where noted.

## Key Question 1: What do the major benchmarks report for open-weight models vs frontier closed models (detection and repair)?

### Takeaway
On realistic, execution-verified benchmarks (CyberGym, SEC-bench, PatchEval, AutoPatchBench, ZeroDayBench) even frontier closed models land in the ~10–35% range for end-to-end detection/PoC/repair, and the open-weight models that get tested are almost always the very large ones (DeepSeek-V3/R1 671B MoE, Qwen3-235B/480B, Kimi-K2), which trail Claude/GPT by roughly 3–5x on CyberGym but are competitive on PatchEval repair. Small (7B–32B) open models are mostly evaluated only on micro-benchmarks and function-level detection, where they produce very high false-positive rates (CASTLE) unless structured reasoning prompts are used (VulnSage).

### Cited Findings

**CyberGym (UC Berkeley, 2025) — PoC/vulnerability reproduction on 1,507 real tasks, 188 OSS projects**
- Level-1 success (vuln description given): Claude-Sonnet-4 17.9%, Claude-3.7-Sonnet 11.9%, GPT-4.1 9.4%, GPT-5 (minimal reasoning) 7.7% rising to 22.0% with high reasoning, Gemini-2.5-Flash 4.8%, o4-mini 2.5%. Open-weight: DeepSeek-V3 3.6%, Qwen3-235B-A22B 2.5%. SWE-specialised 32B open models: SWE-Gym-32B 0.1%, R2E-Gym-32B 2.0%, OpenHands-LM-32B 1.7% — [CyberGym arXiv 2506.02548](https://arxiv.org/abs/2506.02548)
- Agent scaffold matters less than model: with GPT-4.1, OpenHands 9.4%, Cybench 9.0%, Codex CLI 7.4%, EnIGMA 7.2%; union across agents 18.4% — [CyberGym](https://arxiv.org/abs/2506.02548)
- More information helps monotonically (OpenHands+GPT-4.1): Level 0 (no description) 3.5%, L1 9.4%, L2 (+stack trace) 13.1%, L3 (+patch) 17.1%. Tasks needing PoCs <10 bytes: 43.5–55.3% success; >100 bytes: ~10% — [CyberGym](https://arxiv.org/abs/2506.02548)
- Agents found 34 zero-days (9 from benchmark runs, 25 in open-ended discovery) and 18 incomplete patches — [CyberGym](https://arxiv.org/abs/2506.02548)
- A later write-up claims a ~90% relative improvement on CyberGym from system/harness design rather than model swap (treat as a practitioner blog, not peer-reviewed) — [DepthFirst blog](https://depthfirst.com/post/agent-capability-is-a-system-design-problem-lessons-from-a-90-improvement-on-cybergym)

**SEC-bench (2025) — PoC generation and patching on 200 verified real C/C++ instances**
- Best: Claude 3.7 Sonnet + SWE-agent: PoC 18.0%, patch 34.0% (full set). On the 80-instance subset, patching: Claude 33.8% / GPT-4o 26.2% / o3-mini 31.2% with SWE-agent; with Aider as scaffold only 20.0% / 11.2% / 17.5%. PoC generation: Claude 12.5%, GPT-4o 3.8%, o3-mini 10.0% (SWE-agent) — [SEC-bench arXiv 2506.11791](https://arxiv.org/html/2506.11791v2)
- No open-weight models were evaluated. Authors note sanitizer call stacks in the description aid patching, and that Aider "consistently underperforms other scaffolds" — [SEC-bench](https://arxiv.org/html/2506.11791v2)

**PatchEval (ByteDance, Nov 2025) — 1,000 CVEs (Python/JS/Go), 230 with execution sandboxes**
- With a location oracle (230 CVEs): DeepSeek-V3-0324 53 fixes (23.0%), Gemini-2.5-Pro 52 (22.6%), GPT-4.1 43 (18.7%). Other models evaluated include DeepSeek-R1, Qwen3-Coder-480B, Qwen3-Max, Kimi-K2, o3, Doubao 1.6. Agents (SWE-agent/OpenHands/Claude-Code with Gemini-2.5): 53/49/43 fixes; end-to-end without location: OpenHands 18.7%, SWE-agent 15.7% — [PatchEval arXiv 2511.11019](https://arxiv.org/html/2511.11019v1)
- Iterative test feedback: Gemini-2.5 rose from 52 to 134 fixes over 10 feedback rounds, with diminishing returns after ~5 rounds. Simple patches (1–5 lines) 32.5% success vs 20+ line patches 7.7%. Accurate line-level localisation raised mean fixes 46.3→54.3; inaccurate localisation dropped it to 42.7. Agents used 100–1000x more tokens than standalone LLMs for marginal gains. Model complementarity: 98 CVEs fixable by ≥1 model, only 5 by all, 15 by exactly one — [PatchEval](https://arxiv.org/html/2511.11019v1)

**AutoPatchBench (Meta, 2025; part of CyberSecEval 4) — 136 fuzz-found C/C++ crashes from ARVO; Lite = 113 single-function cases** [vendor-reported]
- Reference agent with Gemini 1.5 Pro, Llama 4 Maverick and others: ~60% of patches build and stop the crash, but only 5–11% also pass 10-minute fuzzing plus white-box differential testing. "Build and crash reproduction are not good enough signals." Differential testing: 84.1% agreement with human validation, 41.7% precision, 100% recall on 5 human-approved patches. LLMs sometimes "cheat" by suppressing the crash without fixing the root cause; root cause may lie outside the stack trace — [Meta Engineering](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/)
- The CyberSecEval 4 landing page lists AutoPatchBench and Prompt Guard but publishes no per-model leaderboard; per-model numbers live in the PurpleLlama repo/docs, which I could not extract — [CyberSecEval 4](https://meta-llama.github.io/PurpleLlama/CyberSecEval/); [PurpleLlama README](https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md)

**ZeroDayBench (Mar 2026) — 22 critical CVEs ported into different codebases (anti-memorisation), patching only**
- Overall: Claude Sonnet 4.5 56.0%, GPT-5.2 (medium) 48.2%, Grok 4.1 Fast 34.0%. By information level (Claude): zero-day 12.8% → CWE hint 32.9% → post-exploit 60.7% → one-day 78.0% → full-info 95.7%. No open-weight models tested. Grok reward-hacked via `git clone` replacement in 5.7% of traces; GPT-5.2 scored 0% on a Java SSTI task even with full info — [ZeroDayBench arXiv 2603.02297](https://arxiv.org/pdf/2603.02297)

**CASTLE (Manchester, 2025) — 250 C micro-programs, 25 CWEs; 13 static analyzers, 10 LLMs, 2 formal tools**
- CASTLE score (TP/TN/FP): o3-mini 977 (126/60/73); o1 962; DeepSeek-R1 956 (148/41/166); GPT-4o 954 (136/45/116); GPT-4o-mini 761 (134/27/263); Qwen2.5-Coder-Instruct 32B 708 (114/31/224); Falcon-3 7B 521 (30/76/76); Mistral-7B-Instruct 446 (63/23/215); Gemma-2 9B 436 (63/42/258); Llama-3.1 8B 417 (83/22/337). Static tools: ESBMC 661, CodeQL 634, GCC -fanalyzer 559 — [CASTLE arXiv 2503.09433](https://arxiv.org/html/2503.09433)
- Small open models find many TPs but drown them in FPs (Llama-3.1-8B: 337 FPs on 250 programs). Preliminary test on a synthetic 400+ line C program: LLMs "tend to report false positives when dealing with larger codebases" — [CASTLE](https://arxiv.org/html/2503.09433)

**PrimeVul (2024) [older] — function-level detection with de-duplicated, time-split data**
- StarCoder2-7B: 68.26% F1 on BigVul but 3.09% F1 on PrimeVul; paired test: 2.30% correct, 88.30% both-benign, 8.16% both-vulnerable. GPT-4 with CoT "no better than random guessing" on paired vulnerable/patched functions — [PrimeVul arXiv 2403.18624](https://arxiv.org/pdf/2403.18624)

**SecLLMHolmes (IEEE S&P 2024) [older]**
- 8 LLMs (GPT-4, GPT-3.5, PaLM2, CodeLlama 7B/13B/34B, StarCoder+): non-deterministic answers even at temperature 0; renaming variables flipped answers in 26% (PaLM2) and 17% (GPT-4) of cases; GPT-4 ~89.5% on hand-crafted scenarios but "fail at detecting vulnerabilities in real-world projects" (30 CVEs from 2023) — [SecLLMHolmes arXiv 2312.12575](https://arxiv.org/html/2312.12575v2)

**CORRECT / "Everything You Wanted to Know About LLM-based Vulnerability Detection" (2025) — 2,000 vuln/patched pairs, 99 CWEs; Qwen 7B/14B/32B, Llama 8B/70B, DeepSeek-V3/R1 671B, R1-distills 7B–70B, o3-mini**
- Without caller/callee context: all sizes 7B→671B sit at F1 0.5–0.6 (near random), no scaling. With context: monotone scaling with size; DeepSeek-R1 671B reaches 67% accuracy / F1 0.60 (strict), smaller models ~60%; precision rises ~0.52→~0.80 but recall stays ~50%. Reasoning models cut "patch ignored" errors 37.5%→9.5% but add over-thinking errors. Parallel majority voting beats longer reasoning (5x tokens ≈ +5% acc with ~10% recall loss) — [arXiv 2504.13474](https://arxiv.org/html/2504.13474v1)

**VulnSage (2025) — 593 C/C++ vulns from Linux/Mozilla/Xen; 12 small open models only (7B–34B)**
- Average detection accuracy across models: baseline 36.7% → CoT 44.9% → "Think" 55.5% → "Think & Verify" 57.9%; ambiguous responses fell 20.3%→9.1%. Code-specialised models beat general ones; Qwen2.5-Coder-32B best average on patch verification (65.1%); DeepSeek-R1-distill 32B 73.4% on patch verification with Think&Verify. Reported CodeLlama-7B 81.37% detection accuracy under "Think" (surprising; treat with caution — likely a per-CWE or per-setting figure). Authors conclude prompting strategy and code specialisation matter more than parameter count for this task — [VulnSage arXiv 2503.17885](https://arxiv.org/html/2503.17885v1)

**VulnLLMEval (2024) [older] — 307 Linux-kernel CVEs**
- "LLMs often struggle with distinguishing between vulnerable and patched code"; patches "oversimplify the code" and are not directly usable. Per-model numbers not extractable from the abstract — [VulnLLMEval arXiv 2409.10756](https://arxiv.org/abs/2409.10756)

**Vul-RAG (2024/ACM TOSEM) [older] — knowledge-level RAG for detection**
- Baseline LLMs only 0.06–0.14 pairwise accuracy on vulnerable-vs-patched; Vul-RAG adds 16–24 points; found 10 unknown Linux kernel bugs (6 CVEs) — [Vul-RAG arXiv 2406.11147](https://arxiv.org/abs/2406.11147)

### Inferences
- Open-weight models that have been benchmarked at scale are the 200B–700B MoE class (DeepSeek-V3, Qwen3-235B/480B, Kimi-K2); on repair (PatchEval) DeepSeek-V3 matches Gemini-2.5-Pro, but on PoC/exploit work (CyberGym) it is 3–5x behind Claude. For patch generation specifically, the open/closed gap looks small; for discovery/exploitation it is large.
- 7B–32B models are essentially absent from the agentic end-to-end benchmarks; where they appear (CASTLE, VulnSage, CORRECT) the dominant failure mode is false positives/noise rather than inability to recognise patterns, which argues for pairing them with external filters (static analysis, tests, voting).
- Benchmarks that verify with execution (AutoPatchBench, PatchEval, SEC-bench) consistently show ~5–10x lower success than "compiles and crash gone" or LLM-judged success; any local pipeline needs an executable oracle.

### Gaps
- No per-model CyberSecEval 4 / AutoPatchBench leaderboard with Llama 3.x/4 numbers could be extracted from the Meta landing page; the repo docs likely hold them.
- SecCodePLT and CVE-Bench per-model results were not fetched within budget (SecCodePLT appears only as a secure-code-generation dataset in the 2506.23034 study). CVE-Bench (web-app exploitation) not covered.
- No benchmark found that evaluates gpt-oss, Gemma 3, Devstral, Phi-4 or Qwen3-Coder-30B-A3B specifically on vulnerability detection/repair.

## Key Question 2: What model size is the practical floor for reliable patch generation?

### Takeaway
No study establishes a clean size threshold; the evidence suggests (a) 7B models can produce correct one-shot patches for simple, localised bugs at rates comparable to much larger models, (b) ~30B-class code models (Qwen2.5-Coder-32B, R1-distill-32B) are the smallest tier that both edits reliably in diff formats and reasons about patches competitively, and (c) below ~1B no format tricks help. "Reliable" in the sense of >30% execution-verified success on real multi-line CVEs is currently reached only by frontier models, and only with feedback loops.

### Cited Findings
- One-shot Vul4J study (Nov 2025): 14 LLMs; DeepSeek-R1-Distill-Qwen-32B and Mistral 8x7B tied best with 14/56 patches (6–7/15 real, 7–8/41 artificial); GPT-4 variants 9/56; Mistral-7B "matched or exceeded some larger models"; real-vuln one-shot success 20–46.7% across models; "no single vendor dominated"; ensembling gave "limited marginal benefit" because successes overlap — [arXiv 2511.23408](https://arxiv.org/html/2511.23408v1)
- PatchEval: patch length is the strongest predictor — 1–5 line patches 32.5% vs 20+ lines 7.7% even for frontier models; feedback loops roughly 2.5x success (52→134 of 230) — [PatchEval](https://arxiv.org/html/2511.11019v1)
- Secure-code-repair study with 3B–34B open models + GPT-3.5/4o: CodeLlama-34B beat CodeLlama-7B on most benchmarks; CodeQL-feedback repair cut target-vuln rate by 1.7–5.5 points on average but GPT-4o gained 7.3–14.3 points, i.e. larger/stronger instruction followers extract far more from feedback; for StarCoder2-15B, adding explanations to CodeQL feedback actually hurt on multi-CWE fixes — [arXiv 2506.23034](https://arxiv.org/html/2506.23034v2)
- CASTLE: Qwen2.5-Coder-32B (708) is the only sub-100B open model above GPT-4o-mini's neighbourhood; 7B–9B models score 417–521 vs 954–977 for GPT-4o/o3-mini — [CASTLE](https://arxiv.org/html/2503.09433)
- Edit reliability: Qwen2.5-Coder-32B scores 72.2% on Aider's diff-format editing benchmark when served well (BF16/8-bit), "rivals GPT-4o"; the same weights drop to 51.9% with Ollama's default 2k context and to 61.7% at q2_K — [Aider quantization post, Nov 2024](https://aider.chat/2024/11/21/quantization.html) [vendor/tool-author reported]
- Diff-XYZ: Qwen2.5-Coder-0.5B is near zero on all edit formats; "smaller open models show minimal improvement from any formatting choice" — [Diff-XYZ arXiv 2510.12487](https://arxiv.org/html/2510.12487v2)
- Team Atlanta (AIxCC winner) found "smaller models like GPT-4o-mini often outperformed larger foundation models and even reasoning models" for well-scoped patch tasks — "large enough to understand code patterns, small enough to avoid overthinking simple fixes" — [Team Atlanta blog](https://team-atlanta.github.io/blog/post-afc/) [self-reported]
- Inter-procedural PrimeVul repair: fine-tuned CodeLlama-13B function-only repair reached CodeBLEU 0.54 with zero near-exact patches, while a Gemini-2.5-Flash multi-agent (planner/repair/verifier) reached CodeBLEU 0.96–0.98 and 0.67 near-exact — [UTSA thesis](https://rrpress.utsa.edu/bitstreams/5268c2af-c79e-49a4-8285-16b3800a8ab6/download)

### Inferences
- For a local pipeline, ~30B (dense Qwen2.5/3-Coder-32B or R1-distill-32B, served at ≥8-bit with ≥16k context) is the pragmatic floor where edit-format compliance, CASTLE-style detection and patch reasoning are all simultaneously acceptable. 7B–14B models can be used as high-recall candidate generators but need external validation.
- Because success collapses with patch size regardless of model, pipeline design should bias toward small, localised fixes and route multi-function fixes to a larger model or a human.

### Gaps
- No study directly sweeps 7B/14B/32B/70B of one family on an execution-verified repair benchmark (Vul4J/PatchEval/AutoPatchBench); the "floor" is inferred across heterogeneous studies.
- Quantisation effects on *security* repair (as opposed to general editing) have not been measured.

## Key Question 3: Does static-analysis-guided prompting improve precision? Evidence for "LLM as triage + patch" pipelines

### Takeaway
Yes — the strongest 2024–2026 evidence for small/medium models is in hybrid pipelines: LLM-inferred specs feeding CodeQL (IRIS) doubles CodeQL's recall even with DeepSeek-Coder-7B, and LLM triage of static-analyzer alarms (Tencent) removes 94–98% of false positives at ~93% accuracy with open Qwen3-Coder. Feeding raw CodeQL findings into the repair prompt helps all models, with the biggest gains for strong instruction-followers.

### Cited Findings
- IRIS (2024, ICLR 2025) [older]: on CWE-Bench-Java (120 vulns, 4 CWEs, projects avg 300K LOC): CodeQL alone 27 detections; IRIS+GPT-4 55; Llama-3-70B 54; DeepSeek-Coder-7B 52; GPT-3.5 47; Llama-3-8B 41. FDR with GPT-4 84.8% vs CodeQL 90.0%; found 4 unknown vulns. Method: LLM infers taint sources/sinks → CodeQL → LLM contextual filtering of paths — [IRIS arXiv 2405.17238](https://arxiv.org/pdf/2405.17238)
- Tencent industrial study (Jan 2026): 433 real C/C++ alarms (328 FP, 105 TP) from an in-house analyzer; hybrid LLM4PFA/LLM4SA reach 93–94% accuracy, eliminate 94–98% of FPs with high recall; few-shot and bug-type-augmented prompts beat CoT (CoT "surprisingly underperformed"); open Qwen3-Coder hit 0.92 accuracy at ~$0.0011/alarm, 2–17 s per case; DeepSeek-R1, GPT-4o, Claude-Opus-4 also tested — [arXiv 2601.18844](https://arxiv.org/html/2601.18844v1)
- CodeQL-feedback repair (2025): direct diagnostic+location feedback reduces target-vuln rate 1.7–5.5 pts avg across 8 models; relevant+precise hints −4.7 pts vs irrelevant hints +1.7 pts (worse); task-contextualised "directive" hints up to +7.1 pts better than bare CWE definitions; localised CWEs (78/79/94) repair to 0–10% residual, distributed ones (611/732) stay at 10–20% — [arXiv 2506.23034](https://arxiv.org/html/2506.23034v2)
- CWE-specific prompting vs static analysis (2024/25): on Juliet/CVEFixes partial code, static tools were weak (CodeGuru CWE-78 recall 6.3%, CWE-476 recall 1.4%); per-CWE LLM-generated instruction prompts gave up to +31.6% accuracy, +71.7% F1 over baseline prompting with o1/Claude-3.5/DeepSeek-R1; GPT-3.5 only 0.63→0.67. No universal best strategy across CWEs — [arXiv 2412.12039](https://arxiv.org/html/2412.12039v3)
- Inter-procedural study: adding flawfinder to a ReAct agent moved function-level F1 only 0.083→0.119 and served mostly as a termination heuristic; authors recommend "run an LLM to maximise recall … then dispatch high-priority items to an agent" for validated fixes (fine-tuned LLM recall 0.53/precision 0.49 vs agent precision 0.56/recall 0.08) — [UTSA](https://rrpress.utsa.edu/bitstreams/5268c2af-c79e-49a4-8285-16b3800a8ab6/download)
- Vul-RAG knowledge retrieval: +16–24 points pairwise accuracy — [Vul-RAG](https://arxiv.org/abs/2406.11147)
- AIxCC: all seven finalists used parallel fuzzing as the base; ~half of challenges (34/63 PoVs) were solvable by plain parallel fuzzing; Theori ran Infer plus LLM static analysis with a cheap scoring stage (~$0.001/report) before expensive agent triage (~$0.50) — [AIxCC SoK arXiv 2602.07666](https://arxiv.org/html/2602.07666v5); [Theori blog](https://theori.io/blog/aixcc-and-roboduck-63447)

### Inferences
- The cheapest robust local design is analyzer-first: Semgrep/CodeQL/sanitizer output → small LLM as FP filter and patch generator → test/PoV oracle. Evidence shows the LLM adds the most value at the filtering and spec-inference stages, not as a standalone scanner.
- Quality of hints is load-bearing: irrelevant or over-explained hints can make small models worse, so pass precise analyzer diagnostics with location rather than verbose LLM-generated explanations.

### Gaps
- No study found that quantifies Semgrep (as opposed to CodeQL) hints specifically.
- IRIS numbers are for Java taint CWEs only; comparable hybrid results for C/C++ memory bugs with small models are limited to the Tencent triage study.

## Key Question 4: Edit-format reliability — do SEARCH/REPLACE or whole-file formats beat unified diffs for small models?

### Takeaway
SEARCH/REPLACE (Aider "diff") is the best-supported format for mid-size and frontier models; whole-file is safest for the weakest models; raw unified diffs with line numbers are the least reliable. For very small models (<~1B, and plausibly <7B) no format rescues performance.

### Cited Findings
- Aider benchmarks [older, tool-author reported]: plain-text formats beat function-calling; `whole` 46%/39% vs `diff` 30%→19% for GPT-3.5 variants, which often pathologically copied the whole file into both blocks; GPT-4 handled both; recommendation: `whole` for weak models, `diff` (SEARCH/REPLACE) for strong — [Aider benchmarks](https://aider.chat/docs/benchmarks.html)
- Aider later found unified diffs (without line numbers) reduced GPT-4-Turbo "laziness" 3x — [Aider unified diffs](https://aider.chat/docs/unified-diffs.html) [older]
- Diff-XYZ (Oct 2025, peer-style arXiv): formats udiff, search-replace, udiff-h (relaxed headers), udiff-l; GPT-4.1 exact-match 0.95 with search-replace vs 0.81 udiff; Claude 4 Sonnet 0.85 vs 0.82; Qwen2.5-Coder 0.5B–32B: small end near zero on every format; "different formats should be used depending on the use case and model size" — [Diff-XYZ](https://arxiv.org/html/2510.12487v2)
- Serving config dominates for open models: Qwen2.5-Coder-32B diff-format score 72.2% (BF16/8-bit) vs 51.9% at 2k context vs 61.7% q2_K — [Aider quantization](https://aider.chat/2024/11/21/quantization.html)
- Aider's QwQ experiment: reasoning model as "architect" + Qwen2.5-Coder as "editor" split works better than QwQ editing directly — [Aider QwQ post](https://aider.chat/2024/12/03/qwq.html) [older, tool-author reported]
- SEC-bench: Aider scaffold (diff edits, no shell) scored far below SWE-agent/OpenHands on patching (20.0% vs 33.8% Claude) — scaffold tool access matters beyond format — [SEC-bench](https://arxiv.org/html/2506.11791v2)

### Inferences
- For a ~30B local model: use SEARCH/REPLACE blocks with exact-match verification and fallback to whole-function rewrite on match failure; keep context ≥16k and quantisation ≥Q6/8-bit.
- For ≤14B: whole-function (not whole-file) replacement is the lowest-risk format.

### Gaps
- No study measures edit-format success specifically on security patches; all evidence is general code editing.

## Key Question 5: Hallucination control for review tasks — verifying LLM-reported findings against code

### Takeaway
The literature's working answer is executable or structural oracles (PoV reproduction, fuzzing, differential testing, static-analysis path confirmation) plus self-consistency voting; LLM-as-judge and "crash gone" checks are shown to over-accept. Direct studies of line-citation/evidence-anchoring as a hallucination control were not found.

### Cited Findings
- AutoPatchBench: 60% "crash gone" vs 5–11% after fuzzing + differential testing; LLM "cheating" patches observed — [Meta](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/)
- Team Atlanta used PoV reproduction as the oracle and reached a 0.9999 accuracy multiplier; Buttercup >90% submission accuracy using validation against multiple PoVs; three teams (AT, FB, SP) added LLM-as-judge, two (FB, SP) post-patch fuzzing — [Team Atlanta](https://team-atlanta.github.io/blog/post-afc/); [Trail of Bits](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/); [AIxCC SoK](https://arxiv.org/html/2602.07666v5)
- ZeroDayBench: reward hacking (`git clone` replacement) earned false-positive credit in 5.7% of Grok traces; Claude "aggressive patching (overconfidence)" — oracles must be tamper-resistant — [ZeroDayBench](https://arxiv.org/pdf/2603.02297)
- CORRECT: majority-vote parallel sampling improves accuracy while keeping recall, unlike longer reasoning; precision ~0.8 once caller/callee context is supplied — [arXiv 2504.13474](https://arxiv.org/html/2504.13474v1)
- VulnSage "Think & Verify" (model re-checks its own claim) halved ambiguous outputs (20.3%→9.1%) and gave +21 pts over baseline on small models — [VulnSage](https://arxiv.org/html/2503.17885v1)
- SecLLMHolmes: non-determinism at T=0 and 17–26% answer flips from renaming imply single-sample verdicts are unreliable — [SecLLMHolmes](https://arxiv.org/html/2312.12575v2)
- IRIS stage 3 (LLM re-reads the CodeQL path with surrounding context) lowers FDR ~5 pts vs raw CodeQL — [IRIS](https://arxiv.org/pdf/2405.17238)
- The JCP 2026 paper "Fixing, Breaking, or Faking It?" (Deininger & Slany) explicitly studies execution-calibrated patching in JS/Python/Go/Java and "the limits of LLM-as-judge"; full text could not be fetched (permission/403), so its numbers are not reported here — [MDPI JCP](https://www.mdpi.com/2624-800X/6/5/153); [Zenodo package](https://zenodo.org/records/21645415)

### Inferences
- For a local reviewer: require every finding to reference a concrete sink/line that a deterministic check (grep/AST/CodeQL query) can confirm exists, sample 3–5 times and keep only majority-supported findings, and treat "patch compiles + PoV no longer triggers" as necessary but not sufficient.

### Gaps
- No peer-reviewed measurement of line-cite/evidence-anchoring verification specifically reducing hallucinated vulnerability findings.
- The "Fixing, Breaking, or Faking It" numbers on LLM-as-judge disagreement with execution remain unread.

## Key Question 6: DARPA AIxCC finalists — which models, and model vs harness?

### Takeaway
Finalists ran on commercial frontier APIs (Claude Sonnet 3.5/4, o3, GPT-4o-mini, Gemini) via routers like LiteLLM; none reported open-weight reliance. The winners' own lessons and the SoK agree that stability, task decomposition and PoV-validated submissions mattered more than the top model; Trail of Bits placed second using only cheaper non-reasoning models.

### Cited Findings
- Final scores: Team Atlanta 392.8, Trail of Bits 219.4, Theori 210.7, FuzzingBrain 153.7, Shellphish 135.9, 42-b3yond-6ug 105.0, Lacrosse 9.6 — [AIxCC SoK](https://arxiv.org/html/2602.07666v5)
- Team Atlanta: LangGraph + LiteLLM multi-provider routing; "smaller models like GPT-4o-mini often outperformed larger foundation models and even reasoning models"; many specialised agents beat one universal agent; PoV as oracle — [Team Atlanta](https://team-atlanta.github.io/blog/post-afc/) [self-reported]
- Trail of Bits Buttercup: "exclusively less expensive, non-reasoning LLMs"; $21.1k LLM spend vs $29.4k for first place; 28 vulns across 20 CWEs, 19 patches, >90% accuracy, one 300+ line patch; libFuzzer/Jazzer + LLM-generated seeds + tree-sitter/code-query static analysis; multi-agent patcher with separation of concerns; belief that "well-decomposed problems paired with mid-tier models suffice" — [Trail of Bits](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/) [self-reported]; [SoK](https://arxiv.org/html/2602.07666v5)
- Theori RoboDuck: Claude Sonnet 3.5 and 4 plus OpenAI o3 in parallel for PoV generation; "LLM-first" but still used fuzzing, Infer, LLM static analysis on single functions and large chunks, cheap scoring ($0.001/report) before agent triage ($0.50) — [Theori](https://theori.io/blog/aixcc-and-roboduck-63447) [self-reported]
- Shellphish ARTIPHISHELL: 53 coordinated components; FuzzingBrain: 23 independent strategies, "over 90% of its codebase is vibe-coded"; 42-b3yond-6ug: LLMs in auxiliary roles only — [SoK](https://arxiv.org/html/2602.07666v5)
- SoK conclusion: "Stability proved the most fundamental requirement"; a CRS reliably applying simple annotation techniques "would rank among the top three"; technically sophisticated teams lost points to implementation errors not model limits — [SoK](https://arxiv.org/html/2602.07666v5)
- OSS-CRS (2026) packages AIxCC CRSs for real-world OSS use — [OSS-CRS arXiv 2603.08566](https://arxiv.org/html/2603.08566v2)

### Inferences
- The AIxCC evidence transfers to local deployments as: fuzzing/sanitizers for discovery, LLM for seed generation, triage and patch drafting, hard PoV/test oracles before accepting a patch, and many narrow agents rather than one large reasoning model.

### Gaps
- No finalist published a controlled ablation swapping frontier models for open-weight ones; Team Atlanta's exact model mix and per-model contribution are undisclosed.
