"""Provider-agnostic LLM transport with budget control, caching and logging.

Providers (selected by ``KAVACH_LLM_PROVIDER`` or --provider):

  * ``anthropic`` - api.anthropic.com, key from ANTHROPIC_API_KEY
  * ``openai``    - api.openai.com, key from OPENAI_API_KEY; or ANY OpenAI-compatible
                    server (vLLM, llama.cpp, TGI on an HPC node) via OPENAI_BASE_URL
  * ``ollama``    - local server at OLLAMA_HOST (default http://localhost:11434)
  * ``offline``   - no network; ``complete`` always raises LLMUnavailable so the
                    caller uses its deterministic heuristic brain. This is the
                    default when no API key is present, and is what ``replay``
                    uses, so a full demo runs with no internet and no key.

Only the Python standard library is used (urllib), so KavachForge has zero
pip dependencies and runs anywhere Python 3.8+ is installed.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from typing import Optional

from . import util


class LLMUnavailable(Exception):
    """Raised when no live model answer is available (offline, no key,
    transport error, or budget exhausted). Callers fall back to a heuristic."""


DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-20241022",
    "openai": "gpt-4o-mini",
    "ollama": "phi4:14b",
}


def _ollama_running() -> bool:
    """A local Ollama server with at least one model counts as a provider
    (fully offline operation). Checked once, cheaply."""
    import urllib.request
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=1.5) as r:
            import json as _j
            return bool(_j.loads(r.read().decode()).get("models"))
    except Exception:
        return False


def ollama_models() -> list:
    import urllib.request
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=1.5) as r:
            import json as _j
            return [m["name"] for m in _j.loads(r.read().decode()).get("models", [])]
    except Exception:
        return []


class LLMClient:
    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None,
                 budget: int = 6, cache_dir: str = "cache/llm",
                 log_dir: str = "artifacts/llm_log"):
        self.provider = (provider or os.environ.get("KAVACH_LLM_PROVIDER")
                         or self._auto_provider())
        self.model = (model or os.environ.get("KAVACH_LLM_MODEL")
                      or DEFAULT_MODELS.get(self.provider, ""))
        if self.provider == "ollama" and not model and not os.environ.get("KAVACH_LLM_MODEL"):
            have = ollama_models()
            if have and not any(h.split(":")[0] == self.model.split(":")[0] for h in have):
                # evidence-ranked (docs/OFFLINE_MODELS.md): repair quality first, then review quality
                order = ["phi4:14b", "phi4", "devstral-small-2", "gpt-oss", "devstral", "gemma4", "phi4-reasoning",
                         "granite4", "gemma3", "granite", "qwen3.6", "qwen3-coder", "qwen2.5-coder", "qwen3",
                         "deepseek-coder", "llama3.3", "llama3.1", "mistral", "llama"]
                ranked = sorted(have, key=lambda h: next((i for i, k in enumerate(order) if h.startswith(k)), 99))
                self.model = ranked[0]
        self.budget = int(os.environ.get("KAVACH_LLM_BUDGET", budget))
        self.cache_dir = cache_dir
        self.log_dir = log_dir
        self.deadline = None     # epoch seconds; no new live call after it
        self.slot_end = None     # epoch seconds; the current stage's slot - caps one call's timeout
        self.calls = 0           # live network calls actually made
        self.cached = 0          # answers served from cache
        self.last_source = None  # "live" | "cache"
        self.call_seconds: list = []   # (seconds, kind) of each live call, for time planning
        os.makedirs(cache_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

    @staticmethod
    def _auto_provider() -> str:
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        if os.environ.get("KAVACH_USE_OLLAMA") or _ollama_running():
            return "ollama"
        return "offline"

    def avg_call(self, default: float = 0.0, kind: str = "") -> float:
        """Mean wall time of the live calls so far (a slow CPU model can take
        minutes per call; the pipeline plans its stages around this). With
        `kind`, only calls of that kind count when any exist (a patch call is
        much shorter than a review call)."""
        xs = [s for s, k in self.call_seconds if not kind or k == kind] or [s for s, _ in self.call_seconds]
        return (sum(xs) / len(xs)) if xs else default

    def describe(self) -> str:
        if self.provider == "offline":
            return "offline (deterministic heuristic brain, no network)"
        return "%s / %s (budget %d calls)" % (self.provider, self.model, self.budget)

    # -- caching -----------------------------------------------------------
    def _key(self, system: str, prompt: str) -> str:
        return util.sha256_bytes(
            ("%s|%s|%s|%s" % (self.provider, self.model, system, prompt)).encode())

    def _cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, key + ".json")

    # -- main entry --------------------------------------------------------
    def complete(self, prompt: str, system: str = "", max_tokens: int = 1500, kind: str = "") -> str:
        key = self._key(system, prompt)
        cpath = self._cache_path(key)
        if os.path.exists(cpath):
            self.cached += 1
            self.last_source = "cache"
            data = util.read_json(cpath)
            self._log(system, prompt, data["text"], "cache")
            return data["text"]

        if self.provider == "offline":
            raise LLMUnavailable("offline provider selected")
        if self.calls >= self.budget:
            raise LLMUnavailable("LLM budget of %d calls exhausted" % self.budget)
        if self.deadline and time.time() >= self.deadline:
            raise LLMUnavailable("deadline reached; no new model calls")

        attempts = 3 if self.provider == "ollama" else 1   # a local runner can be
        last = None                                         # restarting (OOM/reload)
        t_start = time.time()
        for i in range(attempts):
            try:
                text = self._call_live(prompt, system, max_tokens)
                self.call_seconds.append((time.time() - t_start, kind))
                break
            except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                    KeyError, ValueError, TimeoutError) as e:
                last = e
                if i + 1 < attempts and not isinstance(e, (TimeoutError, socket.timeout)) \
                        and "timed out" not in str(e):
                    time.sleep(8 * (i + 1))
                    continue
                self.call_seconds.append((time.time() - t_start, kind))   # a timeout is a data point too
                self._log(system, prompt, "ERROR: %s" % e, "error")
                raise LLMUnavailable("transport error: %s" % e)

        self.calls += 1
        self.last_source = "live"
        util.write_json(cpath, {"provider": self.provider, "model": self.model,
                                "text": text, "ts": time.time()})
        self._log(system, prompt, text, "live")
        return text

    def _log(self, system: str, prompt: str, response: str, source: str) -> None:
        idx = len(os.listdir(self.log_dir)) if os.path.isdir(self.log_dir) else 0
        util.write_json(os.path.join(self.log_dir, "call_%03d.json" % idx),
                        {"source": source, "provider": self.provider,
                         "model": self.model, "system": system,
                         "prompt": prompt, "response": response})

    # -- transports --------------------------------------------------------
    def _timeout(self, default: int) -> int:
        """Per-call timeout: the configured one, capped so a single slow call
        cannot overrun the run deadline."""
        t = int(os.environ.get("KAVACH_LLM_TIMEOUT", default))
        for end in (self.deadline, self.slot_end):
            if end:
                t = max(15, min(t, int(end - time.time())))
        return t

    def _http(self, url: str, headers: dict, payload: dict, timeout: int = 60) -> dict:
        timeout = self._timeout(timeout)
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def _call_live(self, prompt: str, system: str, max_tokens: int) -> str:
        if self.provider == "anthropic":
            key = os.environ["ANTHROPIC_API_KEY"]
            out = self._http(
                "https://api.anthropic.com/v1/messages",
                {"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
                {"model": self.model, "max_tokens": max_tokens,
                 "system": system or "You are a precise security engineer.",
                 "messages": [{"role": "user", "content": prompt}]})
            return "".join(b.get("text", "") for b in out["content"])

        if self.provider == "openai":
            # Any OpenAI-compatible server works: vLLM / llama.cpp / TGI on an HPC
            # node, e.g. OPENAI_BASE_URL=http://hpc-node:8000/v1 OPENAI_API_KEY=x
            key = os.environ.get("OPENAI_API_KEY", "none")
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            try:
                out = self._http(
                    base + "/chat/completions",
                    {"Authorization": "Bearer %s" % key,
                     "content-type": "application/json"},
                    {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                     "messages": [{"role": "system", "content":
                                   system or "You are a precise security engineer."},
                                  {"role": "user", "content": prompt}]}, timeout=600)
                return out["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as e:
                if e.code not in (404, 405, 400, 501):
                    raise
            # Server exposes only /v1/completions (plain prompt): fold the
            # system text into the prompt and read .text instead.
            out = self._http(
                base + "/completions",
                {"Authorization": "Bearer %s" % key, "content-type": "application/json"},
                {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                 "prompt": (system or "You are a precise security engineer.") + "\n\n" + prompt + "\n"},
                timeout=600)
            return out["choices"][0]["text"]

        if self.provider == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            out = self._http(
                host.rstrip("/") + "/api/chat",
                {"content-type": "application/json"},
                {"model": self.model, "stream": False,
                 "options": {"temperature": 0, "num_predict": max_tokens,
                             "num_ctx": int(os.environ.get("KAVACH_OLLAMA_CTX", "16384"))},
                 "messages": [{"role": "system", "content":
                               system or "You are a precise security engineer."},
                              {"role": "user", "content": prompt}]},
                timeout=int(os.environ.get("KAVACH_OLLAMA_TIMEOUT", "900")))   # CPU inference is slow
            return out["message"]["content"]

        raise LLMUnavailable("unknown provider %r" % self.provider)
