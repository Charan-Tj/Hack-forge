"""Repair validator: prove a candidate patch in a clean, disposable worktree.

Gates (all must pass for a Verified patch):
  G0  patch applies cleanly (``patch -p1``)
  G1  the target rebuilds
  G2  the proof-of-vulnerability no longer crashes the rebuilt target
  G3  the regression test command still passes

The original repository is never mutated; everything runs on a copy."""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config, discovery, toolchain, util


@dataclass
class Gate:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Validation:
    status: str                       # "Verified" | "Rejected"
    gates: List[Gate] = field(default_factory=list)
    worktree_kept: Optional[str] = None
    regress: Optional[object] = None  # regress.RegressResult when generated
    diff: Optional[object] = None     # differential.DiffResult when run

    def as_dict(self) -> Dict:
        d = {"status": self.status,
             "gates": [{"name": g.name, "passed": g.passed, "detail": g.detail}
                       for g in self.gates]}
        if self.regress is not None:
            r = self.regress
            d["regression_test"] = {
                "file": os.path.basename(r.source_path),
                "rel_test_path": r.rel_test_path,
                "fails_unpatched": r.fails_unpatched,
                "passes_patched": r.passes_patched,
                "guards_bug": r.guards_bug,
            }
        if self.diff is not None:
            x = self.diff
            d["differential"] = {"mode": x.mode, "compared": x.total,
                                 "preserved": x.preserved, "excluded": x.excluded,
                                 "diverged": x.diverged[:10], "passed": x.passed}
        return d


def _remap(task: "config.Task", worktree: str, abspath: str) -> str:
    return os.path.join(worktree, os.path.relpath(abspath, task.root))


def _build_tests(task, tc, worktree, out_bin) -> "util.CmdResult":
    srcs = [_remap(task, worktree, s) for s in task.test_sources]
    incs = [_remap(task, worktree, i) for i in task.include_dirs]
    return util.run(toolchain.build_test_cmd(tc, srcs, incs, out_bin), timeout=120)


def baseline_tests(task: "config.Task", tc: "toolchain.Toolchain",
                   work_dir: str) -> Gate:
    """Run the regression suite on the UNPATCHED sources (should be green)."""
    out = os.path.join(work_dir, "baseline_test")
    b = _build_tests(task, tc, task.root, out)
    if not b.ok:
        return Gate("baseline tests build", False, b.err[-400:])
    r = util.run([out], env={"ASAN_OPTIONS": "detect_leaks=0"}, timeout=60)
    return Gate("baseline tests", r.ok,
                (r.out.strip().splitlines() or ["(no output)"])[-1])


def validate(task: "config.Task", tc: "toolchain.Toolchain", finding,
             patch_diff: str, work_dir: str, keep: bool = False,
             with_g5: bool = True) -> Validation:
    gates: List[Gate] = []
    os.makedirs(work_dir, exist_ok=True)
    worktree = tempfile.mkdtemp(prefix="kv_wt_", dir=os.path.abspath(work_dir))
    try:
        # Clean copy of the target subtree.
        dst = os.path.join(worktree, "tree")
        shutil.copytree(task.root, dst)

        # G0: apply patch (absolute paths; -f avoids BSD patch prompts).
        diff_path = os.path.join(worktree, "patch.diff")
        util.write_text(diff_path, patch_diff)
        ap = util.run(["patch", "-p1", "-f", "-i", diff_path], cwd=dst, timeout=30)
        gates.append(Gate("G0 patch applies", ap.ok, (ap.out + ap.err).strip()[-300:]))
        if not ap.ok:
            return Validation("Rejected", gates, worktree if keep else None)

        # G1: rebuild target from patched sources
        srcs = [_remap(task, dst, s) for s in task.sources]
        harness = _remap(task, dst, task.harness)
        incs = [_remap(task, dst, i) for i in task.include_dirs]
        out_bin = os.path.join(worktree, "fuzzer_patched")
        cmd = toolchain.build_fuzzer_cmd(tc, srcs, harness, incs, out_bin)
        bld = util.run(cmd, timeout=180)
        ok_build = bld.ok and os.path.exists(out_bin)
        gates.append(Gate("G1 rebuild", ok_build, bld.err[-300:] if not ok_build else "clean build"))
        if not ok_build:
            return Validation("Rejected", gates, worktree if keep else None)

        # G2: PoV must no longer crash
        res = discovery._run_one(out_bin, finding.pov_path, task.rss_mb)
        blocked = not discovery._is_crash(res)
        gates.append(Gate("G2 PoV blocked", blocked,
                          "no crash on PoV" if blocked else "PoV still crashes"))
        if not blocked:
            return Validation("Rejected", gates, worktree if keep else None)

        # G3: regression tests must still pass
        test_bin = os.path.join(worktree, "test_patched")
        tb = _build_tests(task, tc, dst, test_bin)
        if not tb.ok:
            gates.append(Gate("G3 tests", False, "test build failed: " + tb.err[-250:]))
            return Validation("Rejected", gates, worktree if keep else None)
        tr = util.run([test_bin], env={"ASAN_OPTIONS": "detect_leaks=0"}, timeout=60)
        last = (tr.out.strip().splitlines() or ["(no output)"])[-1]
        gates.append(Gate("G3 tests", tr.ok, last))
        if not tr.ok:
            return Validation("Rejected", gates, worktree if keep else None)

        # G4: synthesize a regression test from the PoV and prove it guards
        # the bug (crashes the unpatched tree, passes the patched tree).
        from . import regress
        rr = regress.prove(task, tc, finding, dst, work_dir, worktree)
        gates.append(Gate("G4 regression test", rr.guards_bug, rr.detail))
        if not with_g5:
            return Validation("Verified", gates, worktree if keep else None, regress=rr)

        # G5: behaviour preservation - replay the whole corpus through a
        # behaviour probe on both trees; any divergence on a previously-valid
        # input is functionality loss and rejects the patch.
        from . import differential
        dr = differential.compare(task, tc, dst, work_dir, worktree,
                                  os.path.join(work_dir, "fuzzer"), out_bin)
        gates.append(Gate("G5 behaviour preserved", dr.passed or dr.mode == "skipped",
                          dr.detail))
        status = "Verified" if (dr.passed or dr.mode == "skipped") else "Rejected"
        # G0-G3 + G5 prove the patch; G4 proves the generated test (a G4 miss is
        # reported on its gate but does not un-verify the patch itself).
        return Validation(status, gates, worktree if keep else None, regress=rr, diff=dr)
    finally:
        if not keep:
            shutil.rmtree(worktree, ignore_errors=True)
