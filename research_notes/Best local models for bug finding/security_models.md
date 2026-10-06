# Open-weight security-specialised LLMs for vulnerability detection, secure-code review and repair (state as of 2025–2026)

Research date: 2026-10-06. Scope: open-weight models only; closed/API-only systems are flagged as such. Vendor claims are labelled "vendor"; independent results are labelled "independent".

## Key Question 1: What are the notable security-specialised open models (org, country, base, size, purpose, benchmarks, licence)?

### Takeaway
The credible 2025–2026 open-weight security models are almost all general-purpose *security knowledge* chat/reasoning models (CTI, CVE→CWE mapping, SOC work) built on Llama-3.1-8B, Qwen2.5/Qwen3 or gpt-oss, not code-vulnerability-repair specialists; the only code-specific "repair" models in the literature (VulRepair, SecRepair, RepairLLaMA, SecureFalcon) are small research artefacts, mostly classification or seq2seq, and Google's CodeMender is closed.

### Cited Findings

**Cisco Foundation AI (USA) — Foundation-Sec family**
- Foundation-Sec-8B: released April 28, 2025; base Meta Llama-3.1-8B; continued-pretrained on ~5.1B tokens of cybersecurity data; licence Apache 2.0; it is a *base* model "designed for continued pretraining … rather than conversational interaction"; 16 quantised versions linked from the card — [HF: fdtn-ai/Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)
- Foundation-Sec-8B vendor benchmarks: CTI-MCQA 67.39 vs Llama-3.1-8B 64.14 vs Llama-3.1-70B 68.23; CTI-RCM 75.26 vs 66.43 vs 72.66 — [HF: fdtn-ai/Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)
- Foundation-Sec-8B-Instruct: released August 1, 2025; chat template supported; vendor table: CTI-MCQA 0.644 (Llama-3.1-8B 0.617, GPT-4o-mini 0.672), CTI-RCM 0.692 (0.558, 0.655), CTI-VSP 0.802 (0.815, 0.792), IF-Eval 0.811, AlpacaEval-2 35.45; licence "See NOTICE.md"; 12 quantisations listed; knowledge cutoff April 10, 2025 — [HF: fdtn-ai/Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct); tech report [arXiv 2508.01059](https://arxiv.org/pdf/2508.01059)
- Foundation-Sec-8B-Reasoning: released January 28, 2026; base Llama-3.1-8B; SFT on ~2M exemplars (>25% cybersecurity incl. CVEs/ATT&CK/CWEs, ~17% math, ~17% coding) then GRPO RLVR; emits `<think>…</think>`; vendor table: CTI-MCQA 0.691 (Llama-3.1-8B 0.607, GPT-5-Nano 0.688), CTI-RCM 0.753 (0.531, 0.672), CTI-VSP 0.856, CTI-Reasoning 0.411, CWE-Prediction 70.4%, SecEval 84.8%, MMLU-Security 78.2%; licence "See NOTICE.md"; 9 quantisations — [HF: fdtn-ai/Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [tech report arXiv 2601.21051](https://arxiv.org/html/2601.21051v1)
- The reasoning tech report evaluates HumanEval but "does not feature dedicated security-code vulnerability benchmarks like CyberSecEval or SecCodePLT" — [arXiv 2601.21051](https://arxiv.org/html/2601.21051v1)
- Cisco's June 2025 blog describes the reasoning model's uses as "vulnerability analysis, attack pathway tracing, and risk assessment"; no specific code-review capability claim; NVIDIA NIM packaging announced — [Cisco blog](https://blogs.cisco.com/security/foundation-sec-8b-reasoning-worlds-first-security-reasoning-model)

**Kindo / WhiteRabbitNeo → DeepHat (USA, Venice CA)**
- WhiteRabbitNeo HF org lists: WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B (Oct 9, 2024), Llama-3.1-WhiteRabbitNeo-2-70B and -2-8B (Aug 19, 2024), Llama-3-WhiteRabbitNeo-8B-v2.0 (May 2024), 7B-v1.5a, 33B-v1.5, 13B-v1 (Feb–Mar 2024) — [HF org](https://huggingface.co/WhiteRabbitNeo)
- WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B: base Qwen2.5-Coder-7B; ChatML chat model; "for offensive and defensive cybersecurity"; "public preview"; licence Apache-2.0 + WhiteRabbitNeo extension (no military use etc.); no benchmarks on card — [HF card](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B)
- WhiteRabbitNeo-V3-7B: base chain Qwen2.5-7B → Qwen2.5-Coder-7B → DeepHat-V1-7B; "trained as of February 2025"; ChatML; Apache 2.0 (per bartowski GGUF card) — [bartowski GGUF](https://huggingface.co/bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF)
- Kindo is "an AI-native infrastructure and security-automation company in Venice, California"; WhiteRabbitNeo-33B-v1.5 is a DeepSeek-Coder-33B fine-tune whose "exact training dataset, fine-tune recipe, and dataset size … are not disclosed"; "no benchmarks have been published for this model"; licence DeepSeek Coder Licence + WhiteRabbitNeo Extended — [AdversariaLLM review, Aug 2026 (independent)](https://adversariallm.ai/research/whiterabbitneo-33b)
- DeepHat is the rebrand of the WhiteRabbitNeo line; Deep Hat v2 is 30B and claims to outperform GPT-OSS-120B and Llama-Scout on CTF/threat-intel/offensive tasks (vendor); Deep Hat is described as "proprietary" and optimised for Kindo's terminal; HF org huggingface.co/Deephat exists but the site does not state whether v2 weights are open; no licence stated — [deephat.ai](https://www.deephat.ai/)

**Trend Micro AI Lab / Trend Cybertron (Japan HQ; the 70B README identifies the lab as Taiwan-based)**
- Primus collection: Llama-Primus-Base (8B, Llama-3.1-8B-Instruct continually pretrained on 2.77B tokens of cybersecurity text, Mar 2025), Llama-Primus-Merged (8B instruct, Mar 2025), Llama-Primus-Reasoning (8B, distilled from o1-preview/DeepSeek-R1, Jun 2025); datasets Primus-Seed, Primus-FineWeb (2.57B tokens), Primus-Instruct (~1K), Primus-Reasoning (4.89k) — [HF collection](https://huggingface.co/collections/trendmicro-ailab/primus)
- Llama-Primus-Reasoning: MIT licence (plus Llama 3.1 Community Licence compliance); vendor CISSP CoT 0-shot 0.8193 vs Llama-3.1-8B-Instruct 0.7288 (+15.8%); 5 GGUF quantisations linked; average 1,467 output tokens per answer — [HF card](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning)
- Llama-Primus-Nemotron-70B-Base: base nvidia/Llama-3.1-Nemotron-70B-Instruct; trained on Primus-Seed-V2 (0.417B tok), Primus-FineWeb (2.57B), Primus-Nemotron-CC (7.6B); vendor 5-shot: CTI-Bench MCQ 0.7148, CVE→CWE 0.7410, CVSS MAE 1.0281, CyberMetric 0.9280, SecEval 0.7208, CISSP 0.8703, aggregate +11.19% over base; MIT + Llama licence; an Instruct variant is referenced; it is a base model — [HF README](https://huggingface.co/trend-cybertron/Llama-Primus-Nemotron-70B-Base/blob/main/README.md)

**IBM Research / "Cyber Pal" — CyberPal 2.0 (USA/Israel; authors are IBM Research)**
- Paper "Toward Cybersecurity-Expert Small Language Models" (ICML 2026, authors Levi, Ohayon, Blobstein, Sagi, Molloy, Allouche — IBM Research); models 4B (Qwen3-4B-base), 8B (Qwen3-8B-base), 14B (Qwen3-14B-base), 20B (gpt-oss-20b); CyberPal-2.0-20B ranks 1st on CTI-RCM at 87.40% (above GPT-4o, o1, o3-mini, Sec-Gemini v1), CTI-MCQ 75.5–75.7%, SecEval 72.86%, CyberMetric-2000 89.05%; CyberPal-2.0-8B vs Qwen3-8B: CTI-RCM 63.25% → 85.95% — [arXiv 2510.14113](https://arxiv.org/html/2510.14113v2)
- Secure-code trade-off: on CyberSecEval autocomplete/instruct, CyberPal-2.0-8B average pass 70.94% vs Qwen3-8B baseline 79.58% (security tuning *reduced* secure-code-generation pass rate) — [arXiv 2510.14113](https://arxiv.org/html/2510.14113v2)
- CyberPal2.0-20B HF card: base gpt-oss-20b; Apache 2.0; chain-of-thought prompting recommended; quantised versions listed for llama.cpp/LM Studio/Jan/Ollama (4 models); agentic/tool use "currently not tested"; card org is "Cyber Pal Cybersecurity" (no IBM mention on card) — [HF: cyber-pal-security/CyberPal2.0-20B](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B); sibling [CyberOss-2.0-20B](https://huggingface.co/cyber-pal-security/CyberOss-2.0-20B)

**Smaller / older community models**
- Lily-Cybersecurity-7B-v0.2 (Sego Lily Labs, country not stated): base Mistral-7B-Instruct-v0.2; 22,000 hand-crafted cybersecurity QA pairs; Apache 2.0; Alpaca-style Instruction/Input/Response format; GGUF repo exists; no benchmarks — [HF card](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2)
- ZySec-7B / "SecurityLLM" (ZySec AI): base Zephyr/Mistral-7B; DPO-tuned over 30 security domains and compliance frameworks (CIS, FedRAMP, PCI DSS, ISO 27001); Apache 2.0; chat template; official GGUF (ZySec-7B-v1-GGUF, community v2 GGUF); no benchmarks — [HF card](https://huggingface.co/ZySec-AI/SecurityLLM); [koesn/ZySec-7B-v2-GGUF](https://huggingface.co/koesn/ZySec-7B-v2-GGUF)
- SecGPT (Clouditera 云起无垠, **China**): SecGPT-14B v2.0 April 2025 (original Dec 2023); base Qwen2.5-Instruct / DeepSeek-R1 series; 5TB+ security corpus; Apache 2.0; vendor CISSP 78.84, CS-EVAL 88.60; Qwen2 chat template; strong Chinese-language focus; official GGUF (F16 29.5 GB); also secgpt-mini — [HF: clouditera/SecGPT-14B-GGUF](https://huggingface.co/clouditera/SecGPT-14B-GGUF); [clouditera/secgpt-mini](https://huggingface.co/clouditera/secgpt-mini)
- SecureFalcon (TII UAE + Guelma Univ. Algeria + Univ. Manchester): 121M-parameter model derived from FalconLLM-40B; **classifier only** — binary vulnerable/non-vulnerable (94% on FormAI) and 12-class CWE (92% on FalconVulnDB); C/C++ only; "limited in identifying zero-day vulnerabilities"; paper gives no HF link / no weight release — [arXiv 2307.06616v3 (TSE 2025)](https://arxiv.org/html/2307.06616v3)
- Encoder detectors catalogued in the CAI paper: SecureBERT 2.0, CySecBERT (continued-pretraining recipe) — [CAI Dataset paper, arXiv 2605.28146](https://arxiv.org/pdf/2605.28146)

**Offensive / CTF / RL-trained (catalogued by Alias Robotics, Spain, May 2026)**
- Pentest-R1 (DeepSeek-R1-0528-Qwen3-8B; 24.2% AutoPenBench, 15.0% Cybench), Cyber-Zero (+13.1pp Cybench), PrivEsc-LLM (4B local; 95.8% Linux privesc), xOffense (Qwen3-32B; 79.17% AutoPenBench) — [CAI Dataset paper](https://arxiv.org/pdf/2605.28146)
- CAI Dataset itself: 230,935 session logs, 26M prompts (Mar 2025–May 2026), 18.07 TB; no official fine-tuned model released from it — [CAI Dataset paper](https://arxiv.org/pdf/2605.28146)

**Closed / not open (flagged)**
- Google DeepMind CodeMender (announced Oct 6, 2025): agent on "Gemini Deep Think models" plus static/dynamic analysis, fuzzing, symbolic reasoning, LLM judge; 72 fixes upstreamed; "no code or model weights have been released"; "remains a research effort" — [SiliconANGLE](https://siliconangle.com/2025/10/06/google-deepmind-unveils-codemender-ai-agent-autonomously-patches-software-vulnerabilities/)
- Google SecLM / Sec-Gemini v1: listed as instruction-tuned security models in the CAI catalogue but not open-weight — [CAI Dataset paper](https://arxiv.org/pdf/2605.28146)
- Hirundo "security-hardened" Gemma 4 E4B (May 21, 2026, Tel Aviv): this is prompt-injection/jailbreak hardening via unlearning (4.78% attack success rate), **not** a vulnerability-detection model; HF: hirundo-io/gemma-4-E4B-it-reduced-prompt-injection; evaluated on AutoPatchBench and CyberSOCEval only for utility preservation — [BusinessWire](https://www.businesswire.com/news/home/20260521997520/en/Google-DeepMind-Features-Hirundos-Security-Hardened-Gemma-4-Model-Outperforms-LLMs-170x-Its-Size-on-Security)

**Repair-specific research models (2023–2025)**
- RepairLLaMA: LoRA adapters on CodeLlama for program repair (general APR, not security-specific) — [arXiv 2312.15698](https://arxiv.org/html/2312.15698)
- Vul4J-style "vulnerability security fix generation with code LMs" (Information & Software Technology, 2025) — paper exists but could not be fetched (robots.txt) — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0950584925001259)

### Inferences
- Of the above, only four lines are maintained, instruction-following, non-Chinese and locally runnable at ≤20B: Foundation-Sec-8B-Instruct/Reasoning (Cisco), Llama-Primus-Reasoning/Merged (Trend Micro), WhiteRabbitNeo-2.5 / V3 7B (Kindo), and CyberPal 2.0 (4B–20B). None of them publishes vulnerability *detection/repair* benchmark results (PrimeVul, Vul4J, CyberGym, AutoPatchBench); their published numbers are CTI/CWE-mapping/exam-style.
- "Sec-Gemma" does not appear to exist as an open Google release; the only Gemma security variant found is Hirundo's prompt-injection hardening.
- The Foundation-Sec Instruct/Reasoning licence is a custom NOTICE.md, not Apache 2.0 like the base; check it before commercial redistribution.

### Gaps
- Could not find any 2026 "Primus-Nemotron" instruct release on HF with a date; the 70B README references an Instruct variant but no card was fetched.
- DeepHat v2 open-weight status and licence unknown (site silent; HF org exists).
- No Microsoft "VulnLLM" open model found in searches.
- Vul4J/SecRepair/VulRepair exact numbers not retrieved (ScienceDirect blocked; not re-searched).

## Key Question 2: Which are chat/instruct (can follow "output JSON findings" / "SEARCH-REPLACE patch") vs classifiers?

### Takeaway
Foundation-Sec-8B-Instruct, Foundation-Sec-8B-Reasoning, Llama-Primus-Reasoning/Merged, WhiteRabbitNeo-2.5/V3, CyberPal 2.0, SecGPT-14B, Lily and ZySec are all chat-template instruction models; Foundation-Sec-8B (base) and Llama-Primus-Base/Nemotron-70B-Base are base models; SecureFalcon and the BERT-family detectors are classifiers only.

### Cited Findings
- Foundation-Sec-8B (base) is "designed for continued pretraining on domain-specific tasks rather than conversational interaction" — [HF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)
- Foundation-Sec-8B-Instruct supports `tokenizer.apply_chat_template()` and scores IF-Eval 0.811 (vs Llama-3.1-8B-Instruct 0.791) — [HF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct)
- Foundation-Sec-8B-Reasoning: chat template with instruction following; reasoning traces in `<think>` tags; "longer response generation times" — [HF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [tech report](https://arxiv.org/html/2601.21051v1)
- Llama-Primus-Reasoning: chat template via transformers; ~1,467 tokens average per answer — [HF](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning)
- Llama-Primus-Nemotron-70B-Base is a base model, not instruct — [HF README](https://huggingface.co/trend-cybertron/Llama-Primus-Nemotron-70B-Base/blob/main/README.md)
- WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B: ChatML, "Chat/Instruct model with specialized code generation capabilities"; V3-7B uses ChatML with a Kindo system prompt — [HF 2.5](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B); [bartowski V3 GGUF](https://huggingface.co/bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF)
- CyberPal2.0-20B: instruction-tuned, CoT; agentic/tool use "currently not tested" — [HF](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B)
- Lily: Alpaca-style Instruction/Input/Response (not ChatML) — [HF](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2); ZySec: chat template, OpenAI-compatible — [HF](https://huggingface.co/ZySec-AI/SecurityLLM)
- SecureFalcon: 121M binary / 12-class CWE classifier — [arXiv](https://arxiv.org/html/2307.06616v3); PrimeVul fine-tuned CodeBERT/UniXcoder/CodeT5 are classifiers — [PrimeVul paper](https://arxiv.org/pdf/2403.18624)

### Inferences
- No card found explicitly tests structured-output (JSON) or diff-format compliance; expect Foundation-Sec-Instruct (IF-Eval 0.81) and WhiteRabbitNeo-2.5 (Qwen2.5-Coder base) to be the most likely to follow a JSON/SEARCH-REPLACE instruction, because they inherit strong instruct/coder bases. Reasoning variants will be slower and may wrap output in think blocks.
- Base variants (Foundation-Sec-8B, Primus-Base, Primus-Nemotron-70B-Base) are unsuitable for a review-and-patch prompt without further SFT.

### Gaps
- No published IF-Eval / JSON-compliance numbers for WhiteRabbitNeo, Primus, CyberPal, Lily, ZySec.

## Key Question 3: Ollama / GGUF availability and sizes

### Takeaway
Only WhiteRabbitNeo has an official Ollama namespace; Foundation-Sec, Primus and CyberPal are available as official or community GGUFs on Hugging Face (so `ollama run hf.co/<repo>` or a Modelfile works) and as unofficial community Ollama uploads.

### Cited Findings
- Official Ollama: `ollama run WhiteRabbitNeo/WhiteRabbitNeo-V3-7B` — 15 GB (full-precision), 32K context, 7B, Apache-2.0 + WhiteRabbitNeo extension, updated "1 year ago" — [ollama.com](https://ollama.com/WhiteRabbitNeo/WhiteRabbitNeo-V3-7B)
- WhiteRabbitNeo V3-7B GGUF quants (bartowski): Q4_K_M 4.68 GB, Q5_K_M 5.44 GB, Q6_K 6.25 GB, IQ4_XS 4.22 GB, BF16 15.24 GB — [HF](https://huggingface.co/bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF)
- Community Ollama WhiteRabbitNeo tags: `lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:4b-it-q4_K_M`, `lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0`, `monotykamary/whiterabbitneo-v1.5a:7b_q4_K_M`, `jimscard/whiterabbit-neo` — [Ollama search results](https://ollama.com/lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:4b-it-q4_K_M); [monotykamary](https://ollama.com/monotykamary/whiterabbitneo-v1.5a)
- Foundation-Sec: official GGUF `fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF` on HF — [HF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF); base card lists 16 quantisations, Instruct 12, Reasoning 9 — [HF base](https://huggingface.co/fdtn-ai/Foundation-Sec-8B)
- Foundation-Sec is **not** in Ollama's official library; community uploads: `bogdancsn/Foundation-Sec-8B`, `huihui_ai/foundation-sec-abliterated:8b` (abliterated = refusal-removed, unofficial), `valorvie/Foundation-Sec-8B-Chinese-Chat`; a DIY Modelfile guide exists for the reasoning model — [Ollama bogdancsn](https://ollama.com/bogdancsn/Foundation-Sec-8B); [huihui_ai](https://ollama.com/huihui_ai/foundation-sec-abliterated:8b); [Medium DIY guide](https://medium.com/ai-in-plain-english/how-to-run-ciscos-foundation-sec-8b-reasoning-in-ollama-diy-guide-c073c441dc06)
- Llama-Primus-Reasoning card lists 5 GGUF quantisations — [HF](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning)
- CyberPal2.0-20B card lists quantised versions for llama.cpp / LM Studio / Jan / Ollama (4 models) — [HF](https://huggingface.co/cyber-pal-security/CyberPal2.0-20B)
- ZySec: official `ZySec-AI/ZySec-7B-GGUF`, community `koesn/ZySec-7B-v2-GGUF`, `QuantFactory/SecurityLLM-GGUF` — [HF](https://huggingface.co/ZySec-AI/ZySec-7B-GGUF); Lily: `Lily-Cybersecurity-7B-v0.2-GGUF` — [HF](https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2)
- SecGPT-14B: official GGUF (F16 29.5 GB) — [HF](https://huggingface.co/clouditera/SecGPT-14B-GGUF)
- A June 2026 practitioner guide on local VAPT models names only Foundation-Sec-8B and WhiteRabbitNeo-2.5 as security-specific, and otherwise recommends general Ollama models `qwen3-coder:30b`, `gpt-oss:20b`, `deepseek-r1:14b`, warning that "public benchmarks … do not reproduce your repositories" — [classicdba.com](https://classicdba.com/security-grc/2026-06-20/open-weight-llms-for-cybersecurity-and-vapt-local-models-and-a-safe-testing-agent)

### Inferences
- Practical local set at ≤16 GB VRAM: WhiteRabbitNeo-V3-7B Q4_K_M (~4.7 GB), Foundation-Sec-8B-Instruct/Reasoning Q4–Q8 (~5–9 GB), Llama-Primus-Reasoning Q4 (~5 GB), CyberPal-2.0-20B (gpt-oss MXFP4 ~13 GB class). The 70B Primus-Nemotron is out of reach for typical laptops.
- Community Ollama uploads (abliterated, Chinese-chat) are not vendor artefacts; the AdversariaLLM review's caution that GGUF conversions are "unverified re-packages" with "no perplexity or quality-loss check" applies.

### Gaps
- Exact Ollama tag/size list for CyberPal and Primus GGUFs not enumerated (cards list counts only).

## Key Question 4: Country of origin

### Takeaway
Non-Chinese options: Cisco Foundation-Sec (USA), Kindo WhiteRabbitNeo/DeepHat (USA), Trend Micro Primus (Japan HQ / Taiwan lab), IBM-authored CyberPal 2.0 (USA/Israel), SecureFalcon (UAE/Algeria/UK), Alias Robotics CAI (Spain), Hirundo (Israel); Chinese: Clouditera SecGPT, and Qwen/DeepSeek *bases* under WhiteRabbitNeo-2.5/V3, CyberPal 4B–14B and SecGPT.

### Cited Findings
- Cisco Foundation AI — USA (Cisco blog) — [Cisco](https://blogs.cisco.com/security/foundation-sec-8b-reasoning-worlds-first-security-reasoning-model)
- Kindo — "Venice, California" — [AdversariaLLM](https://adversariallm.ai/research/whiterabbitneo-33b)
- Trend Micro (Trend Cybertron) — README fetch identifies the lab as Taiwan-based — [HF README](https://huggingface.co/trend-cybertron/Llama-Primus-Nemotron-70B-Base/blob/main/README.md)
- CyberPal 2.0 authors are IBM Research — [arXiv 2510.14113](https://arxiv.org/html/2510.14113v2)
- SecureFalcon — Technology Innovation Institute (UAE), Guelma University (Algeria), Univ. of Manchester (UK) — [arXiv](https://arxiv.org/html/2307.06616v3)
- Clouditera (云起无垠) — China — [HF](https://huggingface.co/clouditera/SecGPT-14B-GGUF)
- Alias Robotics — Vitoria-Gasteiz, Spain — [CAI paper](https://arxiv.org/pdf/2605.28146)
- Hirundo — Tel Aviv, Israel — [BusinessWire](https://www.businesswire.com/news/home/20260521997520/en/Google-DeepMind-Features-Hirundos-Security-Hardened-Gemma-4-Model-Outperforms-LLMs-170x-Its-Size-on-Security)
- Base-model provenance: WhiteRabbitNeo-2.5 and V3 are Qwen2.5(-Coder) fine-tunes (Alibaba, China); WhiteRabbitNeo-33B is DeepSeek-Coder-33B; CyberPal 4B/8B/14B are Qwen3; SecGPT-14B is Qwen2.5/DeepSeek-R1 — [HF 2.5](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B); [bartowski V3](https://huggingface.co/bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF); [CyberPal paper](https://arxiv.org/html/2510.14113v2)

### Inferences
- If the restriction is on *any* Chinese-origin weights (including base), the clean choices are Foundation-Sec (Llama-3.1 base), Llama-Primus (Llama-3.1 base), Llama-3.1-WhiteRabbitNeo-2-8B/70B (Llama base, Aug 2024), and CyberPal-2.0-20B (gpt-oss-20b base, OpenAI). If only the fine-tuning org matters, WhiteRabbitNeo-V3 and CyberPal 4B–14B are also fine.

### Gaps
- Sego Lily Labs (Lily) and ZySec AI country not stated on cards.

## Key Question 5: Do security-tuned models beat same-size general/coder models at vulnerability detection/repair? (Published evidence)

### Takeaway
There is no independent evidence that any of the security-chat models (Foundation-Sec, Primus, WhiteRabbitNeo, CyberPal) outperform general coder models at code vulnerability detection or repair; their gains are shown only on CTI/CWE-mapping/exam benchmarks, while task-specific fine-tuning on detection datasets helps a lot but still collapses on realistic pair-wise/low-FPR evaluation.

### Cited Findings
- PrimeVul (2024, independent): fine-tuned CodeT5 19.7% F1, CodeBERT 20.86%, UniXcoder 21.43%, StarCoder2-7B 18.05%, CodeGen2.5-7B 19.61%; pair-wise correct 0.89–3.01%; GPT-4 CoT 12.94% pair-wise; VD-S shows ~88–96% false-negative rate at 0.5% FPR; conclusion: performance "significantly falls short of the requirements for real-world deployment" — [arXiv 2403.18624](https://arxiv.org/pdf/2403.18624)
- Univ. of Mons (Dec 2025, independent): Llama-3.1-8B zero-shot F1 0.363 (BigVul) / 0.410 (PrimeVul); few-shot+RAG 0.700/0.670; "double fine-tuning" 0.970/0.770, matching UniXcoder (0.94/0.77) — "fine-tuning is crucial" — [arXiv 2512.09006](https://arxiv.org/html/2512.09006)
- Ohio/Cincinnati/UTK (Jan 2026, independent): 5 pairs of code vs general 7B models on Big-Vul and VulRepair; fine-tuning "uniformly outperforms" prompting (F1 up to 93% with DeepSeek-R1 distil); "code-specialized models do not consistently exceed general-purpose models"; did not test Foundation-Sec/WhiteRabbitNeo/Primus — [arXiv 2601.08691](https://arxiv.org/html/2601.08691v1)
- CyberGym (ICLR 2026, UC Berkeley, independent): 1,507 real vulns / 188 C/C++ projects; PoC-reproduction success: Claude-Sonnet-4 17.9%, GPT-5 high reasoning 22.0%, GPT-4.1 9.4%, open-weight Qwen3-235B-A22B 2.7%, DeepSeek-V3 3.6%, SWE-specialised 32B models ≤2.0%; found 34 zero-days — [arXiv 2506.02548](https://arxiv.org/pdf/2506.02548)
- SEC-bench (UIUC/Purdue, 2025): 200 verified CVEs; best PoC generation 18.0%, best patching 34.0% (Claude 3.7 Sonnet + SWE-agent); no open-weight models evaluated — [arXiv 2506.11791](https://arxiv.org/html/2506.11791v2)
- AutoPatchBench (Meta, April 2025): 136 ARVO/OSS-Fuzz C/C++ samples; all tested models (incl. Llama 4 Maverick, Gemini 1.5 Pro) ~60% patch generation but only ~5–11% pass verification — [Meta Engineering](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/)
- CyberPal 2.0 (vendor/IBM): security tuning *lowered* CyberSecEval secure-code pass rate (Qwen3-8B 79.58% → CyberPal-8B 70.94%) while raising CTI-RCM by +22.7pp — [arXiv 2510.14113](https://arxiv.org/html/2510.14113v2)
- Foundation-Sec-8B-Reasoning (vendor): CTI-RCM 0.753 vs Llama-3.1-8B 0.531 and GPT-5-Nano 0.672; CWE-Prediction 70.4%; "outperformed Llama-3.3-70B-Instruct on vulnerability mapping tasks"; no CyberSecEval/SecCodePLT reported — [HF](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning); [tech report](https://arxiv.org/html/2601.21051v1)
- Llama-Primus-Reasoning (vendor): CISSP 0.8193 vs 0.7288 baseline; no code-vulnerability benchmark — [HF](https://huggingface.co/trendmicro-ailab/Llama-Primus-Reasoning)
- WhiteRabbitNeo: "no benchmarks have been published"; "zero independent evaluations" — [AdversariaLLM (independent)](https://adversariallm.ai/research/whiterabbitneo-33b)
- SecureFalcon (vendor/academic): 94% binary on FormAI, +4–6pp over CodeBERT, C/C++ only; FormAI is synthetic ESBMC-labelled code — [arXiv](https://arxiv.org/html/2307.06616v3)
- Practitioner guidance (June 2026): a domain model "may understand vulnerability terminology … better than a similarly sized general model" but public benchmarks "do not reproduce your repositories"; recommends private evals — [classicdba.com](https://classicdba.com/security-grc/2026-06-20/open-weight-llms-for-cybersecurity-and-vapt-local-models-and-a-safe-testing-agent)

### Inferences
- For *code* vulnerability detection/repair, the published evidence favours (a) task-specific fine-tuning on detection/repair pairs, or (b) a strong general reasoning/coder model with agentic tooling, over "security-knowledge" chat models. The security models' demonstrated edge is in CVE→CWE mapping, CTI reasoning and security QA, which is useful for *classifying and explaining* a finding, not for *finding* it.
- Open-weight models trail frontier closed models badly on realistic agentic repro/patch benchmarks (CyberGym ≤3.6% for 235B/671B open models vs 17.9–22% closed), so an 8B local security model should be expected to be well below that.
- CyberPal's CyberSecEval regression is a warning that security instruction-tuning can degrade secure-code-generation behaviour of the base.

### Gaps
- No paper found that runs Foundation-Sec, Primus, WhiteRabbitNeo or CyberPal on PrimeVul, Vul4J, CyberGym, SEC-bench, CVE-Bench or AutoPatchBench. This is the central evidence gap.
- CyberSecEval 3/4 and SecCodePLT leaderboards for these specific models were not located.
- DARPA AIxCC-derived open models: not searched in depth; no evidence surfaced in the queries run.
