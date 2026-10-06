# Running KavachForge fully offline (no API key, no internet)

Everything the venue needs is fetched **once** while you still have network, then the
whole loop runs air-gapped: the fuzzing track never needed network; the universal track
scans with locally cached rule packs; and the "brain" is a local model served by Ollama.

## 1. One-time preparation (do this at home, on the demo laptop)

```bash
# 1. local model server
curl -fsSL https://ollama.com/install.sh | sh        # macOS: download from ollama.com
ollama serve &                                        # keep it running (or it autostarts on macOS)

# 2. static analyzer (universal track)
pip install semgrep                                   # any OS; pure pip

# 3. cache everything KavachForge will need
./kavach prefetch                                     # rule packs -> rules/semgrep/ (15 ship in the repo;
                                                      #   p/secrets is fetched here), pulls qwen2.5-coder:7b
./kavach prefetch --model devstral-small-2:24b         # 24 GB+ laptop (see §2b)

# 4. verify
./kavach doctor                                       # must show: semgrep + packs cached, ollama + model
```

From then on, with Wi-Fi off:

```bash
./kavach onboard <path-to-repo> --run --provider ollama         # any stack
./kavach run tinyimg --provider ollama                          # C/C++ fuzz track with the local brain
```

`--provider ollama` is automatic when Ollama is running with a model and no API key is set;
`--model <name>` picks a specific one. Every prompt/response is logged under
`artifacts/<task>/llm_log/` and cached in `cache/llm/`, so a re-run of the same repo costs
nothing and still works if the model server dies mid-demo.

## 2. Which local model

KavachForge asks the model for small, structured edits (SEARCH/REPLACE blocks) and gates every
answer, so a 7B coder model is enough to be useful; bigger models mostly raise the first-try
pass rate at G3/G4. Measured on this project:

| laptop | recommended (`ollama pull …`) | size on disk | notes |
|---|---|---|---|
| 8 GB RAM, any CPU | `qwen2.5-coder:3b` | 1.9 GB | weakest usable; mechanical fixes + simple edits |
| 16 GB RAM (Apple M1/M2/M3, or x86 CPU) | **`qwen2.5-coder:7b`** (default) or `qwen3:8b` | 4.7 GB | the tested default; ~20–40 tok/s on Apple Silicon, ~4–6 tok/s on a 4-core x86 CPU |
| 32 GB Apple Silicon | `qwen2.5-coder:14b`, `qwen3:14b`, `devstral:24b`, or `qwen3:30b-a3b` (MoE, fast) | 9–19 GB | best quality/speed trade-off for a live demo |
| 48–64 GB Apple Silicon / GPU box | `qwen2.5-coder:32b`, `qwen3-coder:30b` | 19–20 GB | strongest; writes AST-level fixes and proof tests reliably |

Rules of thumb: a model needs ~1.2× its download size in free RAM; prefer *coder* variants
(better at exact-text edits); keep `temperature 0` (KavachForge already does). `ollama search
coder` lists newer models than this page; anything in the Qwen-Coder / Devstral / DeepSeek-Coder
families works with the same prompts.

What we observed with `qwen2.5-coder:7b` on a 2-core cloud CPU (worst case):

- NodeGoat eval-injection (`app/routes/contributions.js`): two candidate fixes in one call,
  first candidate passed G0–G2, ≈2 min per model call.
- Python `eval()` service: first answer `ast.literal_eval` was **rejected by G3** (the repo's
  own test `compute("1+2") == 3` fails) — the gates caught a wrong fix from a small model, which
  is exactly the point; a 14B+ model writes the arithmetic-AST evaluator that passes.
- Mechanical hardening (cookie flags, `yaml.safe_load`, `verify=True`, `InsecureSkipVerify`)
  needs no model at all.

## 2b. Recommended models (research-backed, non-Chinese) — read this first

Full evidence in `reports/Best local models for bug finding.md`. Same prompts, same gates; pick by RAM.
All figures are vendor-reported SWE-bench Verified unless marked; no public benchmark covers
vulnerability repair for these exact models, so rehearse once on VAmPI/NodeGoat.

| laptop | pull | origin / licence | why |
|---|---|---|---|
| 24–32 GB | **`devstral-small-2:24b`** (15 GB) | Mistral, France · Apache-2.0 | best open non-Chinese repair score (65.8–68% SWE-bench Verified); built for agentic code edits |
| 24–32 GB | `gpt-oss:20b` (14 GB) | OpenAI, USA · Apache-2.0 | 60.7% at `reasoning: high`; strong structured output → good reviewer / second strategy |
| 16 GB | **`gpt-oss:20b`** (14 GB, MoE, 3.6B active) | OpenAI, USA · Apache-2.0 | the only repair-capable model that fits; keep `KAVACH_OLLAMA_CTX=8192` |
| 16 GB | `gemma4:12b` / `gemma3:12b` (8 GB) | Google, USA · Apache-2.0 / Gemma licence | triage + review; weaker at multi-step edits (independent agentic test: 17%) |
| 16 GB | `phi4-reasoning:14b` (9–11 GB) | Microsoft, USA · MIT | review stage reasoning |
| any | `granite4.2:8b` / `granite3.3:8b` (5 GB) | IBM, USA · Apache-2.0 | enterprise-clean fallback |

Security-tuned models (Cisco Foundation-Sec-8B, Trend Micro Primus, Kindo WhiteRabbitNeo, IBM
CyberPal 2.0) publish gains only on threat-intel / CVE→CWE exams, none on code repair, and IBM's
own tuning *lowered* secure-code scores — so they are not used for patching. Optionally
`ollama run hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF` for CWE narration only.
WhiteRabbitNeo 2.5/V3 and CyberPal 4B–14B are Qwen fine-tunes (Chinese base).

For reference, the excluded Chinese leader is Qwen3.6-27B (77.2%); the exclusion costs ~10 points.
Avoid `codestral` (non-commercial licence). Auto-pick order when several models are installed:
devstral-small-2 → gpt-oss → gemma4 → phi4-reasoning → granite4 → …; force with `--model` or
`KAVACH_LLM_MODEL`. Context is set to 16K by default (`KAVACH_OLLAMA_CTX`) — Ollama's 2K default
roughly halves edit success on 32B-class models.

## 3. Without Ollama at all

Nothing breaks. `--provider offline` (the default when no model is reachable) runs the
deterministic heuristic brain: the C/C++ track still finds, patches and proves the bundled
and onboarded targets; the universal track still discovers everything and applies the
mechanical fixes, and lists the rest as **Unpatched — needs a model** with the analyzer's own
remediation guidance in the dashboard. No finding is ever invented and no patch is ever
claimed verified without passing the gates.

## 4. Demo-day checklist

- [ ] `./kavach doctor` shows green for compiler, semgrep + cached packs, ollama + model
- [ ] `ollama run qwen2.5-coder:7b "say ok"` answers (model is loaded, warm)
- [ ] `./kavach replay all` passes (fuzz track, no network)
- [ ] `./kavach onboard <any repo> --run --yes` completes on a repo you have never seen
- [ ] laptop on mains power; the model is RAM-resident after the first call
