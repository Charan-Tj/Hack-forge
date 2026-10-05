"""Turn a verified proof-of-vulnerability into a permanent regression test,
and prove the test itself: it must FAIL (crash) on the unpatched tree and
PASS on the patched tree. A bug that has been fixed this way cannot silently
return without the test suite noticing.

The generated test is generic: it embeds the PoV bytes and drives the same
harness entry point (LLVMFuzzerTestOneInput) under AddressSanitizer, so no
knowledge of the parser's signature is needed.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional

from . import config, discovery, toolchain, util

_TEMPLATE = """/* KavachForge regression test for %(fid)s
 * %(cwe)s - %(cwe_name)s at %(site)s
 * Generated from proof-of-vulnerability sha256 %(sha)s
 *
 * Drives the fuzz harness entry point with the exact input that crashed the
 * unpatched code. Under AddressSanitizer this test aborts if the fault is
 * reintroduced; it exits 0 when the fix holds. Build it with the same
 * sources + harness as the fuzzer, e.g.:
 *   cc -g -fsanitize=address -I<src> <sources> <harness> %(fname)s -o t && ./t
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const uint8_t kPoV_%(cid)s[] = {
%(bytes)s
};

int main(void) {
    LLVMFuzzerTestOneInput(kPoV_%(cid)s, sizeof(kPoV_%(cid)s));
    printf("regression %(fid)s: OK (no sanitizer fault on %%zu-byte PoV)\\n",
           sizeof(kPoV_%(cid)s));
    return 0;
}
"""


@dataclass
class RegressResult:
    source_path: str              # generated test file (in artifacts)
    rel_test_path: str            # where it would live in the target tree
    fails_unpatched: bool         # crashed on the original tree (expected)
    passes_patched: bool          # exit 0 on the patched tree (expected)
    detail: str

    @property
    def guards_bug(self) -> bool:
        return self.fails_unpatched and self.passes_patched


def _c_bytes(b: bytes, per_line: int = 12) -> str:
    lines = []
    for i in range(0, len(b), per_line):
        chunk = b[i:i + per_line]
        lines.append("    " + ", ".join("0x%02x" % x for x in chunk) + ",")
    return "\n".join(lines) if lines else "    0x00,"


def generate(task: "config.Task", finding, out_dir: str) -> str:
    """Write the regression test source; returns its path."""
    with open(finding.pov_path, "rb") as f:
        pov = f.read()
    cid = re.sub(r"[^A-Za-z0-9]", "_", finding.id)
    fname = "regress_%s.c" % cid.lower()
    src = _TEMPLATE % {
        "fid": finding.id, "cwe": finding.cwe, "cwe_name": finding.cwe_name,
        "site": finding.crash_file, "sha": finding.pov_sha256[:16],
        "cid": cid, "bytes": _c_bytes(pov), "fname": fname,
    }
    path = os.path.join(out_dir, "regress", fname)
    util.write_text(path, src)
    return path


def _build_and_run(task, tc, tree_root: str, test_src: str, out_bin: str):
    """Compile sources+harness+test from `tree_root` and run it."""
    def remap(p):
        return os.path.join(tree_root, os.path.relpath(p, task.root))
    srcs = [remap(s) for s in task.sources]
    harness = remap(task.harness)
    incs = [remap(i) for i in task.include_dirs]
    cmd = toolchain.build_test_cmd(tc, srcs + [harness, test_src], incs, out_bin, link_flags=task.link_flags)
    b = util.run(cmd, timeout=120)
    if not b.ok:
        return None, "build failed: " + b.err[-200:]
    r = util.run([out_bin], env=discovery._asan_env(task.rss_mb), timeout=30,
                 cpu_seconds=15)
    return r, ""


def prove(task: "config.Task", tc: "toolchain.Toolchain", finding,
          patched_tree: str, out_dir: str, work_dir: str) -> RegressResult:
    """Generate the test, then prove it guards the bug on both trees."""
    test_src = generate(task, finding, out_dir)
    rel = os.path.join("tests", os.path.basename(test_src))

    # Unpatched tree (the original target) -> must crash.
    r_un, err_un = _build_and_run(task, tc, task.root, test_src,
                                  os.path.join(work_dir, "regress_unpatched"))
    fails_un = bool(r_un) and discovery._is_crash(r_un)

    # Patched tree -> must pass.
    r_pa, err_pa = _build_and_run(task, tc, patched_tree, test_src,
                                  os.path.join(work_dir, "regress_patched"))
    passes_pa = bool(r_pa) and r_pa.ok and not discovery._is_crash(r_pa)

    if err_un or err_pa:
        detail = (err_un or err_pa)
    else:
        detail = "crashes unpatched: %s | passes patched: %s" % (
            "yes" if fails_un else "NO", "yes" if passes_pa else "NO")
    return RegressResult(test_src, rel, fails_un, passes_pa, detail)
