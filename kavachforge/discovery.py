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
    # declared count/length far larger than the data actually present
    # (classic "trusts the header" read-overflow trigger)
    seeds.append(m + bytes([big]))
    seeds.append(m + bytes([1, big]))
    seeds.append(m + bytes([big, big, big]))
    seeds.append(m + bytes([1, big]) + bytes([0x44]) * 8)
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


def _run_generator_program(code: str, out_dir: str, timeout: int = 20) -> List[bytes]:
    """Run an untrusted model-written generator program in a locked-down
    subprocess (no args, CPU/File limits, its own temp dir) and collect the
    seed files it writes to the directory given as argv[1]."""
    import sys
    os.makedirs(out_dir, exist_ok=True)
    prog = os.path.join(out_dir, "_gen.py")
    util.write_text(prog, code)
    r = util.run([sys.executable, prog, out_dir], timeout=timeout, cpu_seconds=timeout)
    seeds = []
    for name in sorted(os.listdir(out_dir)):
        if name == "_gen.py":
            continue
        fp = os.path.join(out_dir, name)
        try:
            if os.path.isfile(fp) and os.path.getsize(fp) <= MAX_INPUT:
                with open(fp, "rb") as f:
                    seeds.append(f.read())
        except OSError:
            pass
    return seeds


GEN_SYSTEM = (
    "You write a short, self-contained Python 3 program that GENERATES valid "
    "and boundary-case binary inputs for a C parser's fuzz harness. The program "
    "takes one argument, an output directory, and writes each seed as a separate "
    "file there. It must compute any checksums, digests, lengths or magic values "
    "the format requires so the inputs pass the parser's header gates, and it "
    "must include at least one input that drives the main count/length field well "
    "past any fixed buffer size. Use only the Python standard library. No network, "
    "no input(), no deletion — only write files into sys.argv[1].")


def llm_generator_seeds(task: "config.Task", client: "llm.LLMClient",
                        work_dir: str) -> Tuple[List[bytes], str]:
    """Ask the model for a generator PROGRAM (Trail-of-Bits style), run it, and
    return its seeds. Falls back to ([], 'n/a') when no model is available —
    the heuristic byte seeds still cover discovery."""
    out_dir = os.path.join(work_dir, "gen")
    harness = util.read_text(task.harness)
    src = "\n\n".join("/* %s */\n%s" % (config.rel_to_root(task, s), util.read_text(s))
                      for s in task.sources)
    prompt = ("Target: %s\n\n=== HARNESS ===\n%s\n\n=== SOURCE ===\n%s\n\n"
              "Write the generator program now. Output ONLY the Python code in one "
              "fenced block." % (task.description, harness, src[:6000]))
    try:
        text = client.complete(prompt, system=GEN_SYSTEM, max_tokens=1200)
    except llm.LLMUnavailable:
        return [], "n/a"
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.DOTALL)
    code = m.group(1) if m else text
    if "argv" not in code:
        return [], "n/a"
    try:
        seeds = _run_generator_program(code, out_dir)
    except Exception:
        return [], "n/a"
    return seeds, (client.last_source if seeds else "n/a")


def generator_seeds(task: "config.Task", client: "llm.LLMClient",
                    work_dir: str) -> Tuple[List[bytes], str]:
    """Seed via a generator PROGRAM: the live model writes one; otherwise a
    generator program shipped with the task (its cached, offline-safe form) is
    run. Returns ([], "n/a") when neither is available."""
    seeds, src = llm_generator_seeds(task, client, work_dir)
    if seeds:
        return seeds, "generator(" + src + ")"
    if task.seed_generator and os.path.exists(task.seed_generator):
        try:
            code = util.read_text(task.seed_generator)
            seeds = _run_generator_program(code, os.path.join(work_dir, "gen"))
            if seeds:
                return seeds, "generator(provided)"
        except Exception:
            pass
    return [], "n/a"


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


def _asan_env(rss_mb: int) -> Dict[str, str]:
    """Sanitizer options with a hard RSS cap (ASan reserves huge virtual
    address space, so RLIMIT_AS cannot be used; hard_rss_limit_mb can)."""
    return {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:exitcode=99:"
                            "detect_stack_use_after_return=1:"
                            "hard_rss_limit_mb=%d:allocator_may_return_null=1"
                            % rss_mb}


def _run_one(fuzzer_bin: str, path: str, rss_mb: int) -> "util.CmdResult":
    """Execute one input through the harness with memory/CPU/wall limits."""
    return util.run([fuzzer_bin, path], env=_asan_env(rss_mb), timeout=20,
                    cpu_seconds=15)


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
        seeds: List[bytes], work_dir: str, max_crashes: int = 8) -> Dict:
    """Run discovery and keep collecting crashes past the first one (so the
    verifier can demonstrate signature-level deduplication).

    Returns {crashes:[{input_path, asan_text}], stats:{engine, seconds,
    execs, corpus_seeds, first_crash_s, raw_crashes}}."""
    corpus_dir = os.path.join(work_dir, "corpus")
    crashes_dir = os.path.join(work_dir, "crashes")
    os.makedirs(crashes_dir, exist_ok=True)
    _write_corpus(corpus_dir, seeds, task.seeds)

    if tc.is_libfuzzer:
        return _run_libfuzzer(task, fuzzer_bin, corpus_dir, crashes_dir, max_crashes)
    return _run_standalone(task, fuzzer_bin, corpus_dir, crashes_dir, seeds, max_crashes)


def _collect_artifacts(crashes_dir: str, blob: str, limit: int) -> List[Dict]:
    out = []
    for name in sorted(os.listdir(crashes_dir)):
        if name.startswith(("crash-", "oom-", "timeout-")):
            out.append({"input_path": os.path.join(crashes_dir, name),
                        "asan_text": blob})
            if len(out) >= limit:
                break
    return out


def _run_libfuzzer(task, fuzzer_bin, corpus_dir, crashes_dir, max_crashes) -> Dict:
    t0 = time.time()
    env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"}
    base = [fuzzer_bin, corpus_dir,
            "-artifact_prefix=" + crashes_dir + os.sep,
            "-rss_limit_mb=%d" % task.rss_mb, "-timeout=20",
            "-print_final_stats=1"]

    # Pass 1: single process until the first crash (gives time-to-first-PoV).
    r = util.run(base + ["-max_total_time=%d" % task.time_budget_s],
                 timeout=task.time_budget_s + 60, env=env)
    first_s = round(time.time() - t0, 2)
    blob = r.err + r.out
    execs = 0
    mm = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
    if mm:
        execs = int(mm.group(1))
    crashes = _collect_artifacts(crashes_dir, blob, max_crashes)

    # Pass 2 (only if a crash was found): a short fork-mode run that ignores
    # crashes keeps harvesting more artifacts so dedup has work to do.
    if crashes:
        extra = min(6, max(2, task.time_budget_s // 6))
        r2 = util.run(base + ["-fork=1", "-ignore_crashes=1",
                              "-max_total_time=%d" % extra],
                      timeout=extra + 60, env=env)
        mm2 = re.search(r"stat::number_of_executed_units:\s*(\d+)", r2.err + r2.out)
        if mm2:
            execs += int(mm2.group(1))
        crashes = _collect_artifacts(crashes_dir, blob, max_crashes)

    raw = len([n for n in os.listdir(crashes_dir) if n.startswith("crash-")])
    return {"crashes": crashes,
            "stats": {"engine": "libfuzzer", "seconds": round(time.time() - t0, 2),
                      "execs": execs, "corpus_seeds": len(os.listdir(corpus_dir)),
                      "first_crash_s": first_s if crashes else None,
                      "raw_crashes": raw}}


def _run_standalone(task, fuzzer_bin, corpus_dir, crashes_dir, seeds, max_crashes) -> Dict:
    t0 = time.time()
    rng = random.Random(task.rng_seed)
    corpus = list(seeds)
    for name in sorted(os.listdir(corpus_dir)):
        with open(os.path.join(corpus_dir, name), "rb") as f:
            corpus.append(f.read())

    cand_path = os.path.join(crashes_dir, "_candidate")
    execs = 0
    deadline = t0 + task.time_budget_s
    crashes: List[Dict] = []
    first_s = None
    how = "standalone"

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

    # 1) seeds / provided corpus directly (structure-aware inputs first)
    for data in corpus:
        hit = try_input(data)
        if hit:
            crashes.append(hit)
            if first_s is None:
                first_s, how = round(time.time() - t0, 2), "standalone(seed)"
            if len(crashes) >= max_crashes:
                break

    # 2) mutational loop: continue after a crash to harvest more candidates,
    #    but stop early once enough are collected or the budget is spent.
    harvest_deadline = min(deadline, time.time() + 4) if crashes else deadline
    while (execs < task.max_iters and time.time() < harvest_deadline
           and len(crashes) < max_crashes):
        base = rng.choice(corpus)
        data = _mutate(rng, base, corpus)
        hit = try_input(data)
        if hit:
            crashes.append(hit)
            if first_s is None:
                first_s, how = round(time.time() - t0, 2), "standalone(mutation)"
                harvest_deadline = min(deadline, time.time() + 4)
        elif execs % 500 == 0:
            corpus.append(_mutate(rng, rng.choice(corpus), corpus))

    try:
        os.remove(cand_path)
    except OSError:
        pass
    return {"crashes": crashes,
            "stats": {"engine": how, "seconds": round(time.time() - t0, 2),
                      "execs": execs, "corpus_seeds": len(corpus),
                      "first_crash_s": first_s, "raw_crashes": len(crashes)}}


# ---------------------------------------------------------------------------
# Seed uplift A/B (optional, measured honestly)
# ---------------------------------------------------------------------------
def measure_uplift(task: "config.Task", tc: "toolchain.Toolchain",
                   fuzzer_bin: str, work_dir: str, budget_s: int = 20) -> Dict:
    """Time-to-first-crash starting from an EMPTY corpus (no structure-aware
    seeds), bounded by `budget_s`. Compared against the seeded run this
    quantifies what the seed generator contributed for this engine."""
    t0 = time.time()
    udir = os.path.join(work_dir, "uplift")
    cdir, adir = os.path.join(udir, "corpus"), os.path.join(udir, "crashes")
    for d in (cdir, adir):
        os.makedirs(d, exist_ok=True)
    found = None
    execs = 0
    if tc.is_libfuzzer:
        env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"}
        r = util.run([fuzzer_bin, cdir, "-artifact_prefix=" + adir + os.sep,
                      "-max_total_time=%d" % budget_s, "-print_final_stats=1",
                      "-rss_limit_mb=%d" % task.rss_mb],
                     timeout=budget_s + 60, env=env)
        blob = r.err + r.out
        mm = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
        execs = int(mm.group(1)) if mm else 0
        if any(n.startswith("crash-") for n in os.listdir(adir)):
            found = round(time.time() - t0, 2)
    else:
        rng = random.Random(task.rng_seed + 1)
        corpus = [rng.randbytes(16), b"\x00" * 16, b"\xff" * 16]
        cand = os.path.join(adir, "_c")
        deadline = t0 + budget_s
        while time.time() < deadline and execs < task.max_iters:
            data = _mutate(rng, rng.choice(corpus), corpus)
            with open(cand, "wb") as f:
                f.write(data)
            execs += 1
            res = _run_one(fuzzer_bin, cand, task.rss_mb)
            if _is_crash(res):
                found = round(time.time() - t0, 2)
                break
            if execs % 300 == 0:
                corpus.append(data)
    return {"budget_s": budget_s, "execs": execs,
            "first_crash_s": found,
            "note": ("coverage-guided engine cracked the format gate unaided"
                     if found is not None and tc.is_libfuzzer else
                     "no crash without structure-aware seeds within budget"
                     if found is None else "mutation found it unaided")}
