# Best open-weight coding LLMs for local code editing / automated program repair (2025–2026, laptop-class ≤35B)

Research date: 2026-10-06. Scope: open-weight, offline-runnable models ≤~35B dense or MoE with small active params, runnable via Ollama / llama.cpp on an Apple Silicon MacBook (16–32 GB). All figures are tagged **[vendor]** (self-reported on model card / release blog), **[independent]** (third-party measurement), or **[aggregator]** (secondary blog re-quoting; treat with caution).

Important caveat on secondary sources: several 2026 "best Ollama models" blogs contain benchmark columns that contradict primary sources (e.g. one lists Qwen2.5-Coder-32B at "73.7% Aider polyglot" whereas the official Aider polyglot leaderboard lists it at 16.4%; another lists Devstral Small at "75.1% SWE-bench Verified" vs Mistral's own 68.0%). Where I used such blogs I only trusted their **Ollama tag / download-size** columns (which one claims to verify against ollama.com) and not their benchmark columns, and I flag this below.

---

## Key Question 1: Which open-weight models lead code-editing / repair benchmarks at ≤35B params in 2025–2026? (numbers + sources)

### Takeaway
At ≤35B, the 2026 leaders on SWE-bench Verified (the closest proxy for automated program repair) are Qwen3.6-27B (77.2% [vendor], Apr 2026, Chinese) and, among non-Chinese models, Mistral's Devstral Small 2 (24B, 65.8–68.0% [vendor], Dec 2025) and OpenAI's gpt-oss-20b (60.7% at high reasoning [vendor], Aug 2025). On the Aider polyglot *edit* benchmark, small open models remain weak: gpt-oss-20b scores 34.2% [vendor] and the official Aider leaderboard (last entries Aug 2025) shows no small open model above ~40%.

### Cited Findings

**Master comparison table (≤35B or small-active MoE; sorted roughly by SWE-bench Verified)**

| Model (release) | Org / country | Params (total/active) | SWE-bench Verified | Other coding benchmarks | Licence | Ollama tag (download) |
|---|---|---|---|---|---|---|
| Qwen3.6-27B (Apr 2026) | Alibaba Qwen / **China** | 27B dense | 77.2% [vendor] | SWE-bench Multilingual 71.3, SWE-bench Pro 53.5, Terminal-Bench 2.0 59.3, LiveCodeBench v6 83.9 [vendor] | Apache-2.0 | `qwen3.6:27b` (17 GB Q4_K_M) |
| Qwen3.6-35B-A3B (2026) | Alibaba Qwen / **China** | 35B / 3B MoE | 73.4% [vendor, as quoted by independent gist] | community SWE-bench subset 53/100 vs 59/100 for prior version [independent] | (not confirmed) | `qwen3.6:35b` (24 GB) |
| Qwen3-Coder-Next (Feb 2026) | Alibaba Qwen / **China** | 80B / 3B MoE | 70.6–71.3% [vendor] | SWE-bench Multilingual 62.8, SWE-bench Pro 42.7, LiveCodeBench 58.9, EvalPlus 86.6, Terminal-Bench 2.0 25.8–36.2 [vendor] | open-weight (licence not stated in paper extract) | 80B total → ~45+ GB at Q4; exceeds 32 GB laptop budget |
| **Devstral Small 2 (Dec 9 2025)** | Mistral / **France** | 24B dense | 65.8% [vendor, Ollama page] / 68.0% [vendor, as quoted by dev.to] — see conflict | SWE-bench Multilingual 51.6, Terminal-Bench 32.0 [vendor] | Apache-2.0 | `devstral-small-2:24b` (15 GB) |
| **gpt-oss-20b (Aug 5 2025)** | OpenAI / **USA** | 21B / 3.6B MoE | 60.7% high / 53.2% medium / 37.4% low [vendor] | Aider polyglot 34.2 high / 26.6 med / 16.6 low; Codeforces Elo 2230 high; τ-bench retail 54.8 [vendor] | Apache-2.0 | `gpt-oss:20b` (14 GB MXFP4) |
| GLM-4.7-Flash (Jan 2026) | Z.ai (Zhipu) / **China** | 30B / ~3.6B MoE | 59.2% [vendor] | LiveCodeBench v6 64.0, τ²-bench 79.5 [vendor] | not stated in fetched doc | `glm-4.7-flash` (19 GB) |
| Qwen3-Coder-30B-A3B (Jul 2025) | Alibaba Qwen / **China** | 30B / 3.3B MoE | 51.6% [vendor, OpenHands 100-turn]; reproduction details unresolved | — | Apache-2.0 (per HF; not shown on Ollama page) | `qwen3-coder:30b` (19 GB) |
| Devstral Small 1.0/1.1 (May/Jul 2025) | Mistral / **France** | 24B dense | 46.8% [vendor] | — | Apache-2.0 | `devstral:24b` (14 GB) |
| Nemotron 3 Nano 30B-A3B (Dec 14 2025) | NVIDIA / **USA** | 30B / ~3–3.5B MoE (Mamba-2 hybrid) | not published | Terminal-Bench Hard 13.6 (reasoning) / 12.1 [vendor] | NVIDIA Open Model License | `nemotron-3-nano:30b` (24 GB) |
| **Gemma 4 26B-A4B / 31B (2026)** | Google / **USA** | 25.2B/3.8B MoE; 30.7B dense | not published by Google; 17.4% [independent gist, agentic harness] for 26B-A4B | LiveCodeBench v6 77.1 (26B-A4B) / 80.0 (31B); Codeforces Elo 1718 / 2150 [vendor] | Apache-2.0 | `gemma4:26b` (16–19 GB), `gemma4:31b` (19–20 GB) |
| OLMo 3 / 3.1 32B Think (Dec 15 2025) | Allen AI / **USA** | 32B dense | not published | HumanEval+ 91.4, MBPP+ 68.0, LiveCodeBench v3 83.5 [vendor] | Apache-2.0 | `olmo-3:32b-think`, `olmo-3.1:32b` |
| Phi-4-reasoning / -plus (Apr 30 2025) | Microsoft / **USA** | 14B dense | not published | LiveCodeBench 53.8 / 53.1; HumanEval+ 92.9 / 92.3 [vendor] | MIT | `phi4-reasoning:14b`, `phi4-reasoning:plus` |
| Granite 4.2 (2026) | IBM / **USA** | 3B, 8B dense; 30B | not published on Ollama page | none on Ollama page | Apache-2.0 | `granite4.2:3b` (2.2 GB), `:8b` (5.3 GB), `:30b` (18 GB) |
| Qwen2.5-Coder-32B (Nov 2024, still widely used) | Alibaba / **China** | 32B dense | — | Aider polyglot 16.4% correct, 99.6% correct edit format [independent, Aider] | Apache-2.0 | `qwen2.5-coder:32b` (20 GB) |
| Codestral 25.01 (Jan 2025) | Mistral / **France** | 22B dense | — | Aider polyglot 11.1% (whole format, 100% format compliance) [independent, Aider] | MNPL (non-commercial) | `codestral:22b` (13 GB) |
| Qwen3-32B (Apr 2025) | Alibaba / **China** | 32B dense | — | Aider polyglot 40.0%, 83.6% correct edit format [independent, Aider] | Apache-2.0 | `qwen3:32b` |

Per-row sources:

- Qwen3.6-27B: release April 2026, Apache-2.0, 27B, 262K native context (1M with YaRN); SWE-bench Verified 77.2 (vs Qwen3.5-27B 75.0, Claude 4.5 Opus 80.9), SWE-bench Pro 53.5, SWE-bench Multilingual 71.3, Terminal-Bench 2.0 59.3, LiveCodeBench v6 83.9 — all **[vendor]** — [Qwen3.6-27B model card](https://huggingface.co/Qwen/Qwen3.6-27B)
- Independent (RTX 3090 Ti, Q4_K_M, May 16 2026) comparison: Qwen3.6-27B dense ~16 GB, 77.2% SWE-bench Verified (quoting vendor) but with a "context confabulation bug during thinking steps" and "tool-call schema drift past ~10 turns"; Qwen3.6-35B-A3B ~21 GB, 73.4%, with a community SWE-bench regression (53/100 vs 59/100 vs prior version) and "18% failures from system prompt non-compliance"; Gemma 4 26B-A4B ~14.4 GB, 17.4% pass rate, "refuses to use MCP tools even when asked" and "gets stuck in loops" — [hungson175 gist (independent)](https://gist.github.com/hungson175/61a805368649c225026a69adf2ad87e0)
- Qwen3-Coder-Next: 80B total / 3B active, paper dated Feb 28 2026; SWE-bench Verified 70.6 (SWE-Agent) / 71.1 (MiniSWE-Agent) / 71.3 (OpenHands); SWE-bench Multilingual 62.8; SWE-bench Pro 42.7; Terminal-Bench 2.0 25.8–36.2; EvalPlus 86.56; MultiPL-E 88.23; LiveCodeBench 58.93; Codeforces 2100 — **[vendor]** — [Qwen3-Coder-Next technical report](https://arxiv.org/html/2603.00729v1)
- Devstral 2 family: "Devstral 2, released December 9, 2025 by Mistral AI"; Devstral 2 = 123B, Modified MIT, 72.2% SWE-bench Verified; Devstral Small 2 = 24B, Apache-2.0, 68.0%; original Devstral (May 2025) 46.8%; 256K context; Small 2 runs on "24GB VRAM: single NVIDIA RTX 4090" or "Apple Silicon Mac with 32GB unified memory", ~15 GB download, needs Ollama ≥0.13.3 — **[vendor numbers quoted by dev.to]** — [dev.to Devstral 2 guide](https://dev.to/jangwook_kim_e31e7291ad98/devstral-2-run-mistrals-open-coding-agent-locally-13o)
- Devstral Small 2 on Ollama: 24B, Apache-2.0, 384K context (local tag), text+image, "SWE Bench Verified: 65.8%, SWE Bench Multilingual: 51.6%, Terminal Bench: 32.0%", tags `devstral-small-2:latest`/`:24b` = 15 GB, updated ~9 months ago (≈Jan 2026) — **[vendor]** — [ollama.com/library/devstral-small-2](https://ollama.com/library/devstral-small-2). **Conflict:** 65.8% (Ollama page) vs 68.0% (dev.to quoting Mistral); the two likely reflect different scaffolds/attempts; report both.
- Devstral (v1) 24B: 46.8% SWE-bench Verified vs GPT-4.1-mini 23.6%, Claude 3.5 Haiku 40.6% — **[vendor; blog labels it "independent" but it is Mistral's own May 2025 number]** — [morphllm Ollama roundup](https://www.morphllm.com/best-ollama-models)
- gpt-oss model card (Aug 5 2025, Apache-2.0): SWE-bench Verified gpt-oss-20b 37.4/53.2/60.7 (low/med/high), gpt-oss-120b 47.9/52.6/62.4; Aider polyglot gpt-oss-20b 16.6/26.6/34.2, gpt-oss-120b 24.0/34.2/44.4; Codeforces Elo 20b 1366/1998/2230; τ-bench retail 20b 35.0/47.3/54.8 — **[vendor]** — [gpt-oss model card arXiv 2508.10925](https://arxiv.org/html/2508.10925v1)
- gpt-oss-20b HF card: "21B parameters with 3.6B active parameters", "run within 16GB of memory"; gpt-oss-120b "117B parameters with 5.1B active" — [HF openai/gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b)
- Aider's own leaderboard lists gpt-oss-120b (high) at 41.8% polyglot, diff format, $0.74 — **[independent]** — [Aider leaderboard](https://aider.chat/docs/leaderboards/)
- GLM-4.7-Flash (Z.ai, Jan 2026 "Jan 21/22 update"): 30B MoE, ~3.6B active; needs ≥24 GB RAM/unified memory, ~18 GB at 4-bit; SWE-bench Verified 59.2 vs Qwen3-30B-A3B 22.0 vs gpt-oss-20b 34.0 (note: Z.ai's table gives gpt-oss-20b 34.0, far below OpenAI's own 60.7 high — scaffold/effort mismatch); LiveCodeBench v6 64.0 vs 66.0 vs 61.0; τ²-bench 79.5 — **[vendor comparison table]** — [Unsloth GLM-4.7-Flash guide](https://unsloth.ai/docs/models/tutorials/glm-4.7-flash); the 59.2 figure is discussed as "pretty darn good for a 30B model" on [Hacker News](https://news.ycombinator.com/item?id=46681896)
- Qwen3-Coder-30B-A3B: vendor claim 51.6 SWE-bench Verified (OpenHands, 100 turns); an Oct 22 2025 HF discussion asks for OpenHands commit, vLLM version, tool-call parser and max-seq-len because they are undisclosed — no independent reproduction found — [HF discussion #30](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct/discussions/30)
- Qwen3-Coder on Ollama: `qwen3-coder:30b` 19 GB, 30B total / 3.3B active, 256K context (1M extrapolated); pretrained on 7.5T tokens, 70% code, RL "optimized for SWE-Bench" — [ollama.com/library/qwen3-coder](https://ollama.com/library/qwen3-coder)
- Gemma 4 (Google, Apache-2.0): sizes E2B 5.1B (2.3B effective), E4B 8B (4.5B), 12B, 26B-A4B 25.2B total / 3.8B active, 31B 30.7B; context 128K (E-models) / 256K (12B, 26B, 31B); LiveCodeBench v6 31B 80.0 / 26B-A4B 77.1 / 12B 72.0 / E4B 52.0 / E2B 44.0; Codeforces Elo 2150 / 1718 / 1659 / 940 / 633; AIME 2026 89.2 / 88.3 — **[vendor]**; no SWE-bench, Aider, HumanEval or BigCodeBench on card — [HF google/gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it)
- Gemma 4 Ollama tags (updated "5 days ago" as of fetch): `gemma4:e2b` 4.6–7.5 GB, `gemma4:e4b` 6.6–9.5 GB, `gemma4:12b` 7.7–8.0 GB, `gemma4:26b` 16–19 GB, `gemma4:31b` 19–20 GB; page quotes LiveCodeBench v6 80.0% and Codeforces 2150 for 31B — [ollama.com/library/gemma4](https://ollama.com/library/gemma4)
- Nemotron 3 Nano 30B-A3B: released Dec 14 2025, 30B total / 3B active, NVIDIA Open License (weights+datasets+recipes), 262,144 context; only coding-adjacent number on OpenRouter is Terminal-Bench Hard 13.6% reasoning / 12.1% non-reasoning — **[vendor]** — [OpenRouter nemotron-3-nano](https://openrouter.ai/nvidia/nemotron-3-nano-30b-a3b)
- Nemotron 3 Nano on Ollama: hybrid "23 Mamba-2 and MoE layers, along with 6 Attention layers", 3.5B active; `nemotron-3-nano:30b` 24 GB, 1M context; `nemotron-3-nano:4b` 2.8 GB; NVIDIA Open Model License; no benchmarks on page — [ollama.com/library/nemotron-3-nano](https://ollama.com/library/nemotron-3-nano)
- OLMo 3 32B Think (Allen AI, Dec 15 2025, Apache-2.0): HumanEval+ 91.4 (vs Qwen3-32B 91.2, Gemma 3 27B 79.2), MBPP+ 68.0 (vs 70.6, 65.7), LiveCodeBench v3 83.5 (vs 90.2, 39.0) — **[vendor]**; no SWE-bench/BigCodeBench — [HF allenai/Olmo-3-32B-Think](https://huggingface.co/allenai/Olmo-3-32B-Think)
- Phi-4-reasoning / -plus (Microsoft, Apr 30 2025, MIT, 14B, 32K context): LiveCodeBench 53.8 / 53.1, HumanEval+ 92.9 / 92.3 — **[vendor]** — [HF microsoft/Phi-4-reasoning](https://huggingface.co/microsoft/Phi-4-reasoning)
- Granite 4.2 (IBM, Apache-2.0, 128K context): tags `granite4.2:3b` 2.2 GB, `:8b` 5.3 GB, `:30b` 18 GB; updated ~1 month ago; no benchmark numbers on page — [ollama.com/library/granite4.2](https://ollama.com/library/granite4.2); Granite 4.1 also exists at [ollama.com/library/granite4.1](https://ollama.com/library/granite4.1)
- Aider polyglot leaderboard (independent, last entries Aug 2025): Qwen3-32B 40.0% correct / 83.6% correct edit format; Kimi K2 59.1% / 92.9%; Qwen3-235B-A22B 59.6%; DeepSeek R1 (0528) 71.4%; DeepSeek-V3.2-Exp reasoner 74.2%; Llama 4 Maverick 15.6% (whole) / 99.1%; Codestral 25.01 11.1% (whole) / 100%; Qwen2.5-Coder-32B-Instruct 16.4% / 99.6%; QwQ-32B 20.9% — [Aider leaderboard](https://aider.chat/docs/leaderboards/)
- A HF community blog (Nov 13 2025) lists Gemma 4 26B-A4B (25.2B/3.8B, Apache-2.0), Llama 4 Scout (109B/17B, Llama 4 Community License), Phi-4-reasoning (14B, MIT), DeepSeek R1 (671B/37B, MIT), Kimi K2.6 (~1.1T, Modified MIT), GLM-5.1, DeepSeek V4 Flash/Pro — with no coding benchmark scores — [HF blog: open-source LLMs](https://huggingface.co/blog/daya-shankar/open-source-llms)

**Secondary-source numbers I do NOT trust (included so the writer does not re-use them):**
- An April 29 2026 blog claims Qwen3.6-27B HumanEval 91.3 / SWE-bench 77.2, "Devstral Small 24B" 88.4 / 75.1, Qwen2.5-Coder-32B 92.7 / 73.8, Qwen3-Coder-Next 89.6 / 70.6, DeepSeek-Coder-V2-Lite 83.5 / 61.2, DeepSeek-R1-32B 72.6, Phi-4 14B 82.7 / 58.4, Llama 3.3 70B 86.0 / 65.3, and "Devstral achieved 94% tool-call accuracy vs Qwen's 88%" — the SWE-bench values for Qwen2.5-Coder-32B, DeepSeek-Coder-V2-Lite, Phi-4 and Llama 3.3 are far above anything in primary sources and the Devstral 75.1 contradicts Mistral's 68.0, so treat as unreliable — [baeseokjae blog](https://baeseokjae.github.io/posts/best-ollama-models-coding-2026/)
- morphllm's table lists "qwen2.5-coder:32b … Aider: 73.7% (polyglot)" and "deepseek-r1:8b/14b/32b ~71.4% Aider polyglot"; the official Aider leaderboard has Qwen2.5-Coder-32B at 16.4% polyglot and 71.4% is DeepSeek R1-0528 (671B), not the distills; it also labels Apache-2.0 Qwen models "Proprietary" — [morphllm](https://www.morphllm.com/best-ollama-models) vs [Aider leaderboard](https://aider.chat/docs/leaderboards/)

### Inferences
- For *repair* (SWE-bench-style issue → patch), the gap between Chinese and non-Chinese ≤35B models in 2026 is ~10 points: Qwen3.6-27B 77.2 [vendor] vs Devstral Small 2 65.8–68.0 [vendor] vs gpt-oss-20b 60.7 [vendor, high effort]. All three are vendor numbers under different scaffolds, so the ranking is indicative, not precise.
- Gemma 4 has strong *competitive-programming* numbers (LiveCodeBench v6 77–80) but Google publishes no SWE-bench, and the one independent agentic test found it far behind Qwen3.6 (17.4%) with tool-use failures — so it is not a top pick for automated repair despite its benchmark headline.
- Nemotron 3 Nano, Granite 4.x, OLMo 3 and Phi-4 publish no SWE-bench Verified and are best viewed as general/reasoning models with decent function-level coding (HumanEval+ ~91–93), not repair specialists.
- gpt-oss-20b's score depends heavily on reasoning effort (37.4 → 60.7); local users must set `reasoning: high` to get the headline number, at a large token/time cost.

### Gaps
- No **independent** SWE-bench Verified or SWE-bench Lite runs were found for any ≤35B model under a standard scaffold; swebench.com entries for small open models were not retrievable in this pass.
- No official 2026 Aider polyglot entries for Devstral Small 2, Qwen3.6, Gemma 4, GLM-4.7-Flash, Nemotron 3 Nano, Granite 4.x or OLMo 3 — the Aider leaderboard page's newest entries are from Aug 2025.
- BigCodeBench and HumanEval+ numbers were not found for Devstral Small 2, gpt-oss-20b, Gemma 4, Qwen3.6 or GLM-4.7-Flash.
- Kimi-Dev-72B (Moonshot), Seed-Coder (ByteDance), DeepSeek-V3 distills, Llama 4 (Scout is 109B total), CodeGemma and Granite Code 3.x were not covered in this pass (Kimi-Dev and Llama 4 Scout exceed the 32 GB laptop budget anyway).
- Exact release date of Gemma 4 conflicts across sources (independent test dated May 16 2026; one blog says June 3 2026; the paper is arXiv 2607.xxxxx, i.e. July 2026) — treat as "spring/summer 2026".
- Qwen3.6-35B-A3B licence and official model-card numbers were not fetched directly (only as quoted in the independent gist).

---

## Key Question 2: Which of these are NOT from Chinese organisations? (explicit origin tags)

### Takeaway
Non-Chinese, open-weight, laptop-class coding options are: OpenAI gpt-oss-20b (USA), Mistral Devstral Small 2 / Devstral 1.x / Codestral (France), Google Gemma 4 / Gemma 3 (USA), NVIDIA Nemotron 3 Nano (USA), IBM Granite 4.x (USA), Microsoft Phi-4 family (USA), Allen AI OLMo 3 (USA), Meta Llama 3.x/4 (USA). Everything from Alibaba (Qwen), DeepSeek, Z.ai/Zhipu (GLM), Moonshot (Kimi) and ByteDance (Seed) is Chinese.

### Cited Findings
- **Non-Chinese:**
  - OpenAI gpt-oss-20b/120b — OpenAI (USA), Apache-2.0 — [gpt-oss model card](https://arxiv.org/html/2508.10925v1)
  - Mistral Devstral 2 (123B, Modified MIT) and Devstral Small 2 (24B, Apache-2.0) — "released December 9, 2025 by Mistral AI" (France) — [dev.to Devstral 2](https://dev.to/jangwook_kim_e31e7291ad98/devstral-2-run-mistrals-open-coding-agent-locally-13o); Codestral 25.01 (Mistral) on Aider leaderboard — [Aider](https://aider.chat/docs/leaderboards/)
  - Google Gemma 4 (E2B/E4B/12B/26B-A4B/31B), Apache-2.0 — [HF google/gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it)
  - NVIDIA Nemotron 3 Nano 30B-A3B, NVIDIA Open Model License — [ollama nemotron-3-nano](https://ollama.com/library/nemotron-3-nano)
  - IBM Granite 4.2 (3B/8B/30B), Apache-2.0 — [ollama granite4.2](https://ollama.com/library/granite4.2)
  - Microsoft Phi-4-reasoning / -plus (14B), MIT — [HF microsoft/Phi-4-reasoning](https://huggingface.co/microsoft/Phi-4-reasoning)
  - Allen AI OLMo 3 32B Think, Apache-2.0 (Ai2, USA) — [HF allenai/Olmo-3-32B-Think](https://huggingface.co/allenai/Olmo-3-32B-Think)
  - Meta Llama 4 Scout (109B/17B, Llama 4 Community License) and Llama 3.3 70B — Meta (USA); both exceed the 32 GB budget at useful quants (`llama3.3:70b` = 43 GB) — [HF blog](https://huggingface.co/blog/daya-shankar/open-source-llms); [morphllm](https://www.morphllm.com/best-ollama-models)
- **Chinese:**
  - Alibaba Qwen: Qwen3.6-27B/35B-A3B, Qwen3.5, Qwen3-Coder-30B-A3B / -Next / -480B, Qwen2.5-Coder, Qwen3-32B, QwQ — [Qwen3.6-27B card](https://huggingface.co/Qwen/Qwen3.6-27B); [Qwen3-Coder-Next](https://arxiv.org/html/2603.00729v1)
  - Z.ai / Zhipu: GLM-4.7-Flash, GLM-5.x — [Unsloth GLM-4.7-Flash](https://unsloth.ai/docs/models/tutorials/glm-4.7-flash)
  - DeepSeek: R1 (and R1-distill-Qwen/Llama), V3.x, DeepSeek-Coder-V2 — [Aider](https://aider.chat/docs/leaderboards/)
  - Moonshot: Kimi K2 / K2.6 — [Aider](https://aider.chat/docs/leaderboards/); [HF blog](https://huggingface.co/blog/daya-shankar/open-source-llms)

### Inferences
- If restricted to non-Chinese models, the practical shortlist for program repair on a 32 GB Mac is **Devstral Small 2 (24B)** first, **gpt-oss-20b (high reasoning)** second, with Gemma 4 26B-A4B / 31B as a fast-but-unproven-for-agents alternative; for a 16 GB Mac only gpt-oss-20b (14 GB) and small Gemma 4 / Granite 4.2 / Phi-4 fit.
- Note that "DeepSeek-R1 distills" shipped under `deepseek-r1:8b/14b/32b` are Chinese-origin fine-tunes of Qwen (Chinese) and Llama (US) bases; a strict non-Chinese policy would exclude them.

### Gaps
- No source was found that formally classifies model origin; the tags above are from the model cards' publishing organisations.

---

## Key Question 3: Exact Ollama tags, sizes, and Apple Silicon (Metal) fit at 16 GB vs 24–32 GB

### Takeaway
Ollama default (Q4_K_M / MXFP4) downloads: `gpt-oss:20b` 14 GB, `devstral-small-2:24b` 15 GB, `gemma4:26b` 16–19 GB, `gemma4:31b` 19–20 GB, `qwen3-coder:30b` 19 GB, `glm-4.7-flash` 19 GB, `qwen3.6:27b` 17 GB, `nemotron-3-nano:30b` 24 GB, `granite4.2:30b` 18 GB. On a 16 GB Mac only gpt-oss-20b (and ≤12B models) fit with usable context; 24 GB fits Devstral Small 2 / Qwen3.6-27B / Gemma 4 26B at Q4; 32 GB fits all of the above with long context and MoE models run 3–5× faster than dense ones.

### Cited Findings
- `gpt-oss:20b` = 14 GB, 128K context, MXFP4 "4.25 bits per parameter" on MoE weights (90%+ of params); "as little as 16GB memory"; `gpt-oss:120b` = 65 GB — [ollama gpt-oss](https://ollama.com/library/gpt-oss)
- `devstral-small-2:24b` = 15 GB, 384K context, text+image — [ollama devstral-small-2](https://ollama.com/library/devstral-small-2); runs on "Apple Silicon Mac with 32GB unified memory" — [dev.to](https://dev.to/jangwook_kim_e31e7291ad98/devstral-2-run-mistrals-open-coding-agent-locally-13o)
- `devstral:24b` (v1) = 14 GB — [morphllm](https://www.morphllm.com/best-ollama-models)
- `qwen3-coder:30b` = 19 GB, 256K context; `qwen3-coder:480b` = 290 GB (needs ≥250 GB) — [ollama qwen3-coder](https://ollama.com/library/qwen3-coder)
- `gemma4:e2b` 4.6–7.5 GB, `gemma4:e4b` 6.6–9.5 GB, `gemma4:12b` 7.7–8.0 GB, `gemma4:26b` 16–19 GB, `gemma4:31b` 19–20 GB — [ollama gemma4](https://ollama.com/library/gemma4)
- `nemotron-3-nano:30b` 24 GB (1M context), `nemotron-3-nano:4b` 2.8 GB; quant-specific tags exist, e.g. `nemotron-3-nano:30b-a3b-q4_K_M` and `:30b-a3b-q8_0` — [ollama nemotron-3-nano](https://ollama.com/library/nemotron-3-nano); [q4_K_M tag](https://ollama.com/library/nemotron-3-nano:30b-a3b-q4_K_M)
- `granite4.2:3b` 2.2 GB, `:8b` 5.3 GB, `:30b` 18 GB, 128K context — [ollama granite4.2](https://ollama.com/library/granite4.2)
- `olmo-3:32b-think` and `olmo-3.1:32b` exist in the Ollama library — [ollama olmo-3.1:32b](https://ollama.com/library/olmo-3.1:32b)
- `phi4-reasoning:14b` and `phi4-reasoning:plus` exist — [ollama phi4-reasoning:plus](https://ollama.com/library/phi4-reasoning:plus); `phi4:14b` = 9.1 GB — [morphllm](https://www.morphllm.com/best-ollama-models)
- `glm-4.7-flash` exists in the library — [ollama glm-4.7-flash](https://ollama.com/library/glm-4.7-flash); 19 GB — [morphllm](https://www.morphllm.com/best-ollama-models); Unsloth: "around 18GB RAM/unified memory" at 4-bit, minimum 24 GB recommended — [Unsloth](https://unsloth.ai/docs/models/tutorials/glm-4.7-flash)
- Other tags/sizes from the morphllm table (states "every number … verified against ollama.com … September 29, 2026"): `qwen3.8:27b` 18 GB, `qwen3.6:27b` 17 GB, `qwen3.6:35b` 24 GB, `qwen2.5-coder:32b` 20 GB, `:14b` 9.0 GB, `:7b` 4.7 GB, `deepseek-coder-v2:16b` 8.9 GB, `codestral:22b` 13 GB, `gemma3:27b` 17 GB, `gemma3:12b` 8.1 GB, `deepseek-r1:32b` 20 GB, `:14b` 9.0 GB, `nemotron-3.5-lightning:30b` 25 GB — [morphllm](https://www.morphllm.com/best-ollama-models)
- Apple Silicon throughput (self-reported by a blog, not independently verified; Jul–Aug 2026): Qwen 3.6 27B Q6_K ~22 GB, 18–30 tok/s on M2/M3 Pro, 60+ tok/s with MLX; gpt-oss-20b Q8_0 ~22 GB, 35–55 tok/s on M4 Pro; Qwen3.6-35B-A3B Q5_K_M ~24 GB, 30–50 tok/s Ollama / ~130 tok/s MLX; Gemma 4 26B-A4B Q4_K_M ~15 GB, 45–65 tok/s M4 Pro; Devstral Small 24B Q4_K_M ~14.5 GB, 30–45 tok/s; Gemma 4 31B Q6_K ~25.2 GB, 12–20 tok/s M4 Pro; MLX "significantly higher than Ollama" — [openclawdc 32 GB guide](https://openclawdc.com/blog/best-local-llms-32gb-ram/)
- Mac RAM tiers (Aug 6 2026 guide, vendor-style estimates): 16 GB → `gpt-oss:20b` or `qwen2.5-coder:14b`; 24 GB → `qwen3.6:27b` or `qwen3-coder:30b`; 32 GB → `qwen3-coder:30b` or `qwen3.6:35b`; 64 GB+ → `qwen3-coder:30b` q8_0 or `llama3.3:70b`; qwen3-coder "comfortably above 20 tokens/sec" on M3 Max 64 GB (LM Studio); llama3.3:70b "roughly 5-8 tokens/sec" — [matterai Mac guide](https://www.matterai.so/guides/top-5-open-source-coding-models-for-mac-2026)
- Independent GPU (RTX 3090 Ti, Q4_K_M) speeds show the MoE-vs-dense gap: Gemma 4 26B-A4B ~150 tok/s (94 at 64K ctx), Qwen3.6-35B-A3B ~160 (65 at 64K), Qwen3.6-27B dense ~40 (18 at 64K) — [hungson175 gist](https://gist.github.com/hungson175/61a805368649c225026a69adf2ad87e0)

### Inferences
- 16 GB MacBook: `gpt-oss:20b` (14 GB) is the only strong repair-capable non-Chinese model that fits, and only with modest context (macOS reserves memory; Ollama's default Metal allocation leaves ~10–11 GB usable for weights+KV). `gemma4:12b` (~8 GB) and `granite4.2:8b` / `phi4-reasoning:14b` fit with more headroom but have no SWE-bench evidence.
- 24 GB MacBook: `devstral-small-2:24b` (15 GB) and `gemma4:26b` (16–19 GB) fit at Q4 with ~32–64K context; Qwen3.6-27B at 17 GB likewise.
- 32 GB MacBook: all of the above plus `nemotron-3-nano:30b` (24 GB) and Q6/Q8 variants of gpt-oss-20b; MoE models (gpt-oss-20b, Gemma 4 26B-A4B, Qwen3.6-35B-A3B, GLM-4.7-Flash) will be 3–5× faster per token than Devstral Small 2 / Qwen3.6-27B dense.
- Most Mac tok/s figures found are blog self-reports; the only independently measured speeds found were on an RTX 3090 Ti.

### Gaps
- No independently measured Apple Silicon tokens/sec for Devstral Small 2, gpt-oss-20b or Gemma 4 on specific M-series chips were found (only blog-reported ranges).
- Official Ollama page for `qwen3.6` / `qwen3.8` / `glm-4.7-flash` was not fetched; sizes come from the morphllm verification table.
- Context-length vs memory trade-offs (KV cache size at 64K/128K on 16 GB) were not quantified by any source.

---

## Key Question 4: Which models reliably produce exact text edits / diffs (Aider edit-format success, SEARCH/REPLACE) vs only chat quality?

### Takeaway
The only hard data on edit-format reliability is Aider's "percent using correct edit format" column: Qwen2.5-Coder-32B (99.6%), Codestral 25.01 (100%) and Llama 4 Maverick (99.1%) follow the format almost perfectly but solve few tasks, while Qwen3-32B (83.6%) solves more but breaks format 1 in 6 times; gpt-oss-20b has a vendor Aider polyglot score of 34.2% (high) but no published format-compliance figure. Devstral Small 2 and Qwen3.6 were built for *agentic* tool-based editing (SWE-bench scaffolds), and independent testers report tool-call reliability issues with Gemma 4 (refuses tools / loops) and Qwen3.6 (schema drift after ~10 turns).

### Cited Findings
- Aider polyglot (independent): Qwen2.5-Coder-32B-Instruct 16.4% correct / **99.6% correct edit format**; Codestral 25.01 11.1% / **100%** (whole format); Llama 4 Maverick 15.6% / **99.1%** (whole); Qwen3-32B 40.0% / **83.6%** (diff); Kimi K2 59.1% / 92.9% (diff); gpt-oss-120b (high) 41.8% (diff); QwQ-32B 20.9% (diff) — [Aider leaderboard](https://aider.chat/docs/leaderboards/)
- gpt-oss-20b Aider polyglot 16.6 / 26.6 / 34.2 (low/med/high); gpt-oss-120b 24.0 / 34.2 / 44.4 — **[vendor]**; no edit-format compliance column published — [gpt-oss model card](https://arxiv.org/html/2508.10925v1)
- Devstral Small 2 is described by Mistral/Ollama as a "24B model that excels at using tools to explore codebases, editing multiple files and power software engineering agents" — i.e. tool-call-based editing rather than diff-text editing — [ollama devstral-small-2](https://ollama.com/library/devstral-small-2)
- Independent agentic test (May 2026): Gemma 4 26B-A4B "refuses to use MCP tools even when asked" and "gets stuck in loops requiring human intervention"; Qwen3.6-27B shows "tool-call schema drift past ~10 turns" and a context-confabulation bug during thinking; Qwen3.6-35B-A3B had "18% failures from system prompt non-compliance" — [hungson175 gist](https://gist.github.com/hungson175/61a805368649c225026a69adf2ad87e0)
- A 32 GB-RAM guide recommends gpt-oss-20b "for unattended agent reliability despite smaller size" and "best for … production tool-calls" (blog opinion, not measured) — [openclawdc](https://openclawdc.com/blog/best-local-llms-32gb-ram/)
- gpt-oss supports "function calling … structured outputs, chain-of-thought reasoning access, and adjustable reasoning effort levels" — [ollama gpt-oss](https://ollama.com/library/gpt-oss)
- Qwen3-Coder was trained with "execution-driven reinforcement learning optimized for SWE-Bench" (agentic, tool-call style) — [ollama qwen3-coder](https://ollama.com/library/qwen3-coder)

### Inferences
- For a pipeline that needs the model to emit **exact SEARCH/REPLACE or unified-diff text** (Aider-style), format compliance matters as much as raw ability: older Qwen2.5-Coder-32B and Codestral are near-perfect at the format but weak solvers; Qwen3-32B/gpt-oss are better solvers but less format-reliable. No 2026 model has a published format-compliance number, so this must be validated empirically.
- For a pipeline that applies edits via **tool calls** (OpenHands/SWE-agent/mini-swe-agent style), Devstral Small 2 and Qwen3.6-27B have the strongest evidence; Gemma 4 should be avoided for agentic editing per the independent test.
- gpt-oss-20b at high effort is a reasonable non-Chinese middle ground: decent Aider polyglot (34.2) and SWE-bench Verified (60.7) with native structured-output support.

### Gaps
- No Aider "edit format" compliance data for any 2025-Q4/2026 model (Devstral Small 2, gpt-oss-20b, Gemma 4, Qwen3.6, GLM-4.7-Flash, Nemotron 3 Nano, Granite 4.x, OLMo 3).
- No study quantifying SEARCH/REPLACE reliability at Q4 quantisation vs FP16 was found.

---

## Key Question 5: Licences

### Takeaway
Nearly every laptop-class 2025–2026 coding model is Apache-2.0 (gpt-oss, Devstral Small 2, Gemma 4, Granite 4.x, OLMo 3, Qwen3.x/Qwen3-Coder) or MIT (Phi-4 family; Devstral 2 123B is "Modified MIT"); the exceptions are NVIDIA's Nemotron (NVIDIA Open Model License), Meta's Llama (Llama Community License), and Mistral's Codestral 25.01 (MNPL non-commercial).

### Cited Findings
- gpt-oss-20b/120b: Apache-2.0 — [HF gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b); [ollama gpt-oss](https://ollama.com/library/gpt-oss)
- Devstral Small 2 (24B): Apache-2.0; Devstral 2 (123B): Modified MIT — [dev.to](https://dev.to/jangwook_kim_e31e7291ad98/devstral-2-run-mistrals-open-coding-agent-locally-13o); Ollama page confirms Apache-2.0 for Small 2 — [ollama devstral-small-2](https://ollama.com/library/devstral-small-2)
- Gemma 4 (all sizes): Apache-2.0 (a change from the custom Gemma licence of Gemma 3) — [HF gemma-4-26B-A4B-it](https://huggingface.co/google/gemma-4-26B-A4B-it)
- Granite 4.2: "Apache 2.0 license, allowing free use for both research and commercial purposes" — [ollama granite4.2](https://ollama.com/library/granite4.2)
- OLMo 3 32B Think: Apache-2.0 — [HF allenai/Olmo-3-32B-Think](https://huggingface.co/allenai/Olmo-3-32B-Think)
- Phi-4-reasoning / -plus: MIT — [HF microsoft/Phi-4-reasoning](https://huggingface.co/microsoft/Phi-4-reasoning)
- Nemotron 3 Nano: NVIDIA Open Model License Agreement — [ollama nemotron-3-nano](https://ollama.com/library/nemotron-3-nano); described as "fully open with open weights, datasets, and recipes" — [OpenRouter](https://openrouter.ai/nvidia/nemotron-3-nano-30b-a3b)
- Qwen3.6-27B: Apache-2.0 — [HF Qwen3.6-27B](https://huggingface.co/Qwen/Qwen3.6-27B); Qwen3-235B-A22B: Apache-2.0 — [HF blog](https://huggingface.co/blog/daya-shankar/open-source-llms)
- Llama 4 Scout: Llama 4 Community License; DeepSeek R1: MIT; Kimi K2.6: Modified MIT — [HF blog](https://huggingface.co/blog/daya-shankar/open-source-llms)
- Codestral 25.01 appears on the Aider leaderboard as a paid API model ($1.98/run) — [Aider](https://aider.chat/docs/leaderboards/); its weights are under Mistral's non-commercial MNPL (from general knowledge — not re-verified in this pass; see Gaps)

### Inferences
- For a commercial or redistributable tool, the safest non-Chinese choices are Apache-2.0 (gpt-oss-20b, Devstral Small 2, Gemma 4, Granite 4.2, OLMo 3) or MIT (Phi-4); Nemotron's NVIDIA licence and Llama's community licence carry extra terms that need legal review.

### Gaps
- Licence of GLM-4.7-Flash, Qwen3.6-35B-A3B and Qwen3-Coder-Next was not stated in the fetched documents (Qwen models are typically Apache-2.0, GLM-4.x typically MIT, but not verified here).
- Codestral 25.01 MNPL status and Gemma 3's licence were not re-verified from primary sources in this pass.
