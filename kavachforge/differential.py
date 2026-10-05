"""Behaviour-preservation gate (G5): differential corpus replay.

A patch that blocks the PoV and passes the existing tests can still be wrong:
published measurements show >40% of such patches fix a symptom or silently
change specified behaviour. Execution, not a model's opinion, is the only
reliable oracle. So after G0-G4 we replay the ENTIRE discovery corpus (every
input the fuzzer kept) through a behaviour probe built from the unpatched and
the patched tree, and compare the observable result of each input:

    * inputs that crashed the unpatched build are the bug - excluded
    * every other input must produce byte-identical probe output after the
      patch; any divergence is functionality loss -> Rejected

The probe is a tiny per-target main() that prints the parser's result
(return code + parsed fields). Targets without a probe fall back to a
weaker crash-only differential (no previously-fine input may now fault).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config, discovery, toolchain, util


@dataclass
class DiffResult:
    mode: str                 # "probe" | "crash-only" | "skipped"
    total: int = 0            # inputs compared
    excluded: int = 0         # inputs that crash unpatched (the bug itself)
    preserved: int = 0
    diverged: List[Dict] = field(default_factory=list)   # [{input, before, after}]
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.mode != "skipped" and not self.diverged


def _remap(task, tree_root: str, p: str) -> str:
    return os.path.join(tree_root, os.path.relpath(p, task.root))


def _build_probe(task, tc, tree_root: str, out_bin: str) -> Optional[str]:
    """Build the behaviour probe (sources + probe main) from `tree_root`."""
    if not task.probe:
        return None
    srcs = [_remap(task, tree_root, s) for s in task.sources]
    probe = _remap(task, tree_root, task.probe)
    incs = [_remap(task, tree_root, i) for i in task.include_dirs]
    r = util.run(toolchain.build_test_cmd(tc, srcs + [probe], incs, out_bin), timeout=120)
    return out_bin if r.ok and os.path.exists(out_bin) else None


def _observe(binary: str, path: str, rss_mb: int) -> str:
    """Canonical observation of one input: 'CRASH' or the probe's stdout."""
    r = util.run([binary, path], env=discovery._asan_env(rss_mb), timeout=20,
                 cpu_seconds=10)
    if discovery._is_crash(r):
        return "CRASH"
    return "exit=%d %s" % (r.code, r.out.strip())


def _kind(before: str, after: str) -> str:
    """Classify a divergence: a changed result on an accepted input, an input
    newly accepted/rejected, an error code that changed (precedence), or a
    new fault."""
    if after == "CRASH":
        return "new fault"
    rb = " rc=0" in before
    ra = " rc=0" in after
    if rb and ra:
        return "result changed"
    if rb != ra:
        return "accepted/rejected flipped"
    return "error code changed"


def _raw_corpus(work_dir: str) -> List[str]:
    paths: List[str] = []
    for sub in ("corpus", "crashes"):
        d = os.path.join(work_dir, sub)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if not name.startswith("_"):
                paths.append(os.path.join(d, name))
    return paths


def _augment(work_dir: str, valid_bases: List[bytes], limit: int,
             rng_seed: int = 1337) -> List[str]:
    """Structure-aware behaviour corpus derived from VALID inputs:
    1) boundary-value variants: each of the first positions of the smallest
       valid inputs set to a boundary value (header fields - counts, lengths,
       versions - live there, which is exactly where a subtly-wrong patch
       changes behaviour);
    2) random mutants using the standalone engine's operators."""
    import random
    aug = os.path.join(work_dir, "diffcorpus")
    os.makedirs(aug, exist_ok=True)
    out: List[str] = []
    n = 0
    for b in sorted(valid_bases, key=len)[:8]:
        for pos in range(min(len(b), 12)):
            for val in (0, 1, 2, 3, 0x10, 0x20, 0x7f, 0x80, 0xff):
                if b[pos] == val:
                    continue
                m = bytearray(b); m[pos] = val
                pth = os.path.join(aug, "b%04d" % n)
                with open(pth, "wb") as f:
                    f.write(bytes(m))
                out.append(pth); n += 1
                if len(out) >= limit:
                    return out
    rng = random.Random(rng_seed)
    for i in range(min(150, max(0, limit - len(out)))):
        if not valid_bases:
            break
        m = discovery._mutate(rng, rng.choice(valid_bases), valid_bases)
        pth = os.path.join(aug, "m%04d" % i)
        with open(pth, "wb") as f:
            f.write(m)
        out.append(pth)
    return out


def compare(task: "config.Task", tc: "toolchain.Toolchain", patched_tree: str,
            work_dir: str, scratch: str, unpatched_fuzzer: str,
            patched_fuzzer: str, limit: int = 450) -> DiffResult:
    inputs = _raw_corpus(work_dir)
    if not inputs:
        return DiffResult("skipped", detail="no corpus to replay")

    before_bin = _build_probe(task, tc, task.root, os.path.join(scratch, "probe_before"))
    after_bin = _build_probe(task, tc, patched_tree, os.path.join(scratch, "probe_after"))
    if before_bin and after_bin:
        mode = "probe"
    else:
        mode, before_bin, after_bin = "crash-only", unpatched_fuzzer, patched_fuzzer

    # Pass 1: classify the raw corpus on the unpatched tree; collect valid bases.
    before: Dict[str, str] = {}
    valid_bases: List[bytes] = []
    for p in inputs:
        b = _observe(before_bin, p, task.rss_mb)
        before[p] = b
        if b != "CRASH" and (mode != "probe" or " rc=0" in b):
            with open(p, "rb") as f:
                valid_bases.append(f.read())
    # Pass 2: derive the structure-aware behaviour corpus from valid inputs.
    for p in _augment(work_dir, valid_bases, limit - len(inputs)):
        before[p] = _observe(before_bin, p, task.rss_mb)

    res = DiffResult(mode)
    for p, b in before.items():
        if b == "CRASH":
            res.excluded += 1
            continue
        a = _observe(after_bin, p, task.rss_mb)
        res.total += 1
        if a == b:
            res.preserved += 1
        else:
            res.diverged.append({"input": os.path.basename(p), "before": b[:120],
                                 "after": a[:120], "kind": _kind(b, a)})
    if res.diverged:
        kinds = {}
        for d in res.diverged:
            kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
        d = res.diverged[0]
        res.detail = ("%d/%d valid inputs changed behaviour [%s] (e.g. %s: '%s' -> '%s')"
                      % (len(res.diverged), res.total,
                         ", ".join("%s x%d" % kv for kv in sorted(kinds.items())),
                         d["input"], d["before"], d["after"]))
    else:
        res.detail = ("%d/%d valid inputs behave identically (%s); %d PoV-class inputs excluded"
                      % (res.preserved, res.total, mode, res.excluded))
    return res
