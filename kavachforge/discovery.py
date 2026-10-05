"""Hybrid discovery: build the harness, seed the corpus (LLM + heuristic),
run fuzzing, and collect reproducible crash candidates.

Two engines share one harness (see toolchain.py):
  * libfuzzer  - coverage-guided; libFuzzer drives mutation.
  * standalone - KavachForge drives a deterministic mutational loop and runs
                 each candidate through the one-shot ASan driver.
"""
from __future__ import annotations

import os
import random
import re
import time
from typing import Dict, List, Tuple

from . import config, llm, toolchain, util

MAX_INPUT = 4096


class BuildError(RuntimeError):
    def __init__(self, log: str):
        super().__init__("target build failed")
        self.log = log


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build_fuzzer(task: "config.Task", tc: "toolchain.Toolchain", out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_bin = os.path.join(out_dir, "fuzzer")
    cmd = toolchain.build_fuzzer_cmd(tc, task.sources, task.harness,
                                     task.include_dirs, out_bin)
    r = util.run(cmd, timeout=180)
    if not r.ok or not os.path.exists(out_bin):
        raise BuildError(" ".join(cmd) + "\n\n" + r.err + r.out)
    return out_bin


# ---------------------------------------------------------------------------
# Seed generation
# ---------------------------------------------------------------------------
def _magic_bytes(task: "config.Task") -> bytes:
    if task.magic:
        return task.magic.encode("latin-1")[:8]
    return b""


def synth_seeds(task: "config.Task") -> List[bytes]:
    """Deterministic structure-aware seeds (the offline/heuristic brain).

    Covers the common ``magic | small-header | length/count | body`` shape
    with several header interpretations so the gated vulnerable path is
    reached regardless of the exact field order."""
    m = _magic_bytes(task)
    seeds: List[bytes] = []
    big = 0xFF
    # version=1 then large count (header-with-version layouts, e.g. tinyimg)
    seeds.append(m + bytes([1, big]) + bytes([0x41]) * 300)
    # large count immediately after magic (count-first layouts, e.g. recordcfg)
    seeds.append(m + bytes([big]) + bytes([big, big]) + bytes([0x42]) * 300)
    # boundary values
    seeds.append(m + bytes([1, 16]) + bytes([0x08]) * 64)
    seeds.append(m + bytes([1, 32]) + bytes([0x43]) * 64)
    # minimal valid-ish
    seeds.append(m + bytes([1, 2]) + bytes([10, 8, 20, 8]))
    # all-magic + ramp
    seeds.append(m + bytes(range(0, 64)))
    return [s[:MAX_INPUT] for s in seeds]


def _parse_llm_seeds(text: str) -> List[bytes]:
    """Accept a JSON array of hex strings, or hex lines, from a model."""
    out: List[bytes] = []
    # try JSON array first
    mobj = re.search(r"\[.*\]", text, re.DOTALL)
    if mobj:
        try:
            import json
            for item in json.loads(mobj.group(0)):
                if isinstance(item, str):
                    out.append(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", item)))
        except Exception:
            pass
    if not out:
        for line in text.splitlines():
            h = re.sub(r"[^0-9a-fA-F]", "", line)
            if len(h) >= 8 and len(h) % 2 == 0:
                try:
                    out.append(bytes.fromhex(h))
                except ValueError:
                    pass
    return [s[:MAX_INPUT] for s in out if s]


def llm_seeds(task: "config.Task", client: "llm.LLMClient") -> Tuple[List[bytes], str]:
    """One LLM turn for structured seeds; heuristic fallback. Returns
    (seeds, source) where source is 'live'/'cache'/'offline-heuristic'."""
    harness = util.read_text(task.harness)
    src = "\n\n".join("/* %s */\n%s" % (config.rel_to_root(task, s), util.read_text(s))
                      for s in task.sources)
    system = ("You are a fuzzing seed generator. Given a C parser and its "
              "libFuzzer harness, produce raw input seeds that satisfy the "
              "format's magic/header gates and push length/count fields to "
              "their extremes to reach deep parsing branches.")
    prompt = (
        "Target description: %s\n\n"
        "=== HARNESS ===\n%s\n\n=== SOURCE ===\n%s\n\n"
        "Return ONLY a JSON array of 4-8 seed inputs, each a hex string "
        "(e.g. \"54494d47\"). Make at least one seed drive the main length/"
        "count field to a large value past any fixed buffer size."
        % (task.description, harness, src[:6000]))
    try:
        text = client.complete(prompt, system=system, max_tokens=800)
        seeds = _parse_llm_seeds(text)
        if seeds:
            # always include heuristic seeds too, so a weak model can't
            # starve discovery
            return seeds + synth_seeds(task), client.last_source
    except llm.LLMUnavailable:
        pass
    return synth_seeds(task), "offline-heuristic"


# ---------------------------------------------------------------------------
# Crash detection helpers
# ---------------------------------------------------------------------------
_ASAN_START = re.compile(r"==\d+==ERROR: AddressSanitizer")
_UBSAN = re.compile(r"runtime error:|UndefinedBehaviorSanitizer")


def _is_crash(r: "util.CmdResult") -> bool:
    blob = r.err + r.out
    return (not r.ok) and bool(_ASAN_START.search(blob) or _UBSAN.search(blob))


def _run_one(fuzzer_bin: str, path: str, rss_mb: int) -> "util.CmdResult":
    env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:"
                           "exitcode=99:detect_stack_use_after_return=1"}
    return util.run([fuzzer_bin, path], env=env, timeout=20)


# ---------------------------------------------------------------------------
# Fuzzing
# ---------------------------------------------------------------------------
def _write_corpus(corpus_dir: str, seeds: List[bytes], provided: List[str]) -> None:
    os.makedirs(corpus_dir, exist_ok=True)
    for i, s in enumerate(seeds):
        with open(os.path.join(corpus_dir, "seed_%03d" % i), "wb") as f:
            f.write(s)
    for p in provided:
        if os.path.exists(p):
            with open(p, "rb") as src, \
                 open(os.path.join(corpus_dir, "given_" + os.path.basename(p)), "wb") as dst:
                dst.write(src.read())


def _mutate(rng: random.Random, data: bytes, corpus: List[bytes]) -> bytes:
    b = bytearray(data)
    op = rng.randint(0, 7)
    if not b:
        b = bytearray(rng.randbytes(4))
    if op == 0 and b:                                   # bit flip
        i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif op == 1 and b:                                 # byte set extreme
        i = rng.randrange(len(b)); b[i] = rng.choice([0x00, 0xFF, 0x7F, 0x80])
    elif op == 2:                                       # insert run
        i = rng.randrange(len(b) + 1)
        b[i:i] = bytes([rng.choice([0xFF, 0x41, 0x00])]) * rng.randint(1, 32)
    elif op == 3 and len(b) > 1:                        # delete run
        i = rng.randrange(len(b)); n = rng.randint(1, min(8, len(b) - i)); del b[i:i + n]
    elif op == 4 and b:                                 # increment byte
        i = rng.randrange(len(b)); b[i] = (b[i] + rng.randint(1, 8)) & 0xFF
    elif op == 5 and corpus:                            # splice
        other = bytearray(rng.choice(corpus))
        if other:
            cut = rng.randrange(len(other)); b[len(b):] = other[cut:]
    elif op == 6 and b:                                 # duplicate chunk
        i = rng.randrange(len(b)); n = rng.randint(1, min(16, len(b) - i)); b[i:i] = b[i:i + n]
    else:                                               # random tail
        b += rng.randbytes(rng.randint(1, 16))
    return bytes(b[:MAX_INPUT])


def run(task: "config.Task", tc: "toolchain.Toolchain", fuzzer_bin: str,
        seeds: List[bytes], work_dir: str) -> Dict:
    """Run discovery. Returns {crashes:[{input_path, asan_text}], stats:{...}}."""
    corpus_dir = os.path.join(work_dir, "corpus")
    crashes_dir = os.path.join(work_dir, "crashes")
    os.makedirs(crashes_dir, exist_ok=True)
    _write_corpus(corpus_dir, seeds, task.seeds)

    if tc.is_libfuzzer:
        return _run_libfuzzer(task, fuzzer_bin, corpus_dir, crashes_dir)
    return _run_standalone(task, fuzzer_bin, corpus_dir, crashes_dir, seeds)


def _run_libfuzzer(task, fuzzer_bin, corpus_dir, crashes_dir) -> Dict:
    t0 = time.time()
    env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"}
    cmd = [fuzzer_bin, corpus_dir,
           "-artifact_prefix=" + crashes_dir + os.sep,
           "-max_total_time=%d" % task.time_budget_s,
           "-rss_limit_mb=%d" % task.rss_mb,
           "-timeout=20", "-print_final_stats=1"]
    r = util.run(cmd, timeout=task.time_budget_s + 60, env=env)
    blob = r.err + r.out
    crashes = []
    # libFuzzer writes crash-<sha1> into the artifact dir on a finding.
    for name in sorted(os.listdir(crashes_dir)):
        if name.startswith(("crash-", "oom-", "timeout-")):
            crashes.append({"input_path": os.path.join(crashes_dir, name),
                            "asan_text": blob})
    execs = 0
    mm = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
    if mm:
        execs = int(mm.group(1))
    return {"crashes": crashes,
            "stats": {"engine": "libfuzzer", "seconds": round(time.time() - t0, 2),
                      "execs": execs, "corpus_seeds": len(os.listdir(corpus_dir))}}


def _run_standalone(task, fuzzer_bin, corpus_dir, crashes_dir, seeds) -> Dict:
    t0 = time.time()
    rng = random.Random(task.rng_seed)
    corpus = list(seeds)
    for name in sorted(os.listdir(corpus_dir)):
        with open(os.path.join(corpus_dir, name), "rb") as f:
            corpus.append(f.read())

    cand_path = os.path.join(crashes_dir, "_candidate")
    execs = 0
    deadline = t0 + task.time_budget_s

    def try_input(data: bytes):
        nonlocal execs
        with open(cand_path, "wb") as f:
            f.write(data)
        execs += 1
        res = _run_one(fuzzer_bin, cand_path, task.rss_mb)
        if _is_crash(res):
            sha = util.sha256_bytes(data)[:16]
            cp = os.path.join(crashes_dir, "crash-" + sha)
            with open(cp, "wb") as f:
                f.write(data)
            return {"input_path": cp, "asan_text": res.err + res.out}
        return None

    # 1) try seeds / provided corpus directly (LLM-reasoned inputs first)
    for data in corpus:
        hit = try_input(data)
        if hit:
            return _done(t0, execs, corpus, "standalone(seed)", [hit])

    # 2) mutational loop until a crash, the time budget, or max_iters
    while execs < task.max_iters and time.time() < deadline:
        base = rng.choice(corpus)
        data = _mutate(rng, base, corpus)
        hit = try_input(data)
        if hit:
            return _done(t0, execs, corpus, "standalone(mutation)", [hit])
        # occasionally grow the corpus with longer inputs to help gates
        if execs % 500 == 0:
            corpus.append(_mutate(rng, rng.choice(corpus), corpus))

    return _done(t0, execs, corpus, "standalone", [])


def _done(t0, execs, corpus, engine, crashes) -> Dict:
    return {"crashes": crashes,
            "stats": {"engine": engine, "seconds": round(time.time() - t0, 2),
                      "execs": execs, "corpus_seeds": len(corpus)}}
