"""Toolchain detection and build-command construction.

Two discovery engines are supported from one harness source:

  * ``libfuzzer`` - clang with ``-fsanitize=fuzzer,address``. Coverage-guided,
    the primary engine (guaranteed inside the Docker image). Produces a
    self-driving ``fuzzer`` binary.

  * ``standalone`` - any compiler that provides AddressSanitizer (gcc+libasan
    or clang+compiler-rt). The harness is linked against KavachForge's own
    one-shot driver (kv_standalone_main.c) and mutation is driven externally.
    This lets discovery run on machines without the libFuzzer runtime.

Both engines share the same sanitizer base flags and the same harness, so a
finding reproduces identically either way.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from . import util

BASE_FLAGS = [
    "-g", "-O1", "-fno-omit-frame-pointer",
    "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-fno-builtin",
]

_HERE = os.path.dirname(os.path.abspath(__file__))
STANDALONE_MAIN = os.path.join(_HERE, "engine", "kv_standalone_main.c")


@dataclass
class Toolchain:
    engine: str          # "libfuzzer" | "standalone"
    cc: str              # compiler binary
    note: str            # human description
    cov_flag: str = ""   # SanitizerCoverage flag for the standalone engine, if any

    @property
    def is_libfuzzer(self) -> bool:
        return self.engine == "libfuzzer"


# Common out-of-PATH LLVM installs that ship compiler-rt + libFuzzer. On macOS
# Apple's clang has no libFuzzer, but `brew install llvm` does - detecting it
# gives the coverage-guided engine natively without Docker.
_LLVM_CANDIDATES = [
    "/opt/homebrew/opt/llvm/bin/clang",      # Apple-silicon Homebrew
    "/usr/local/opt/llvm/bin/clang",         # Intel-mac Homebrew
    "/home/linuxbrew/.linuxbrew/opt/llvm/bin/clang",
    "/usr/lib/llvm-18/bin/clang", "/usr/lib/llvm-17/bin/clang",
    "/usr/lib/llvm-19/bin/clang", "/usr/lib/llvm-20/bin/clang",
]


def _clang_candidates() -> List[str]:
    out = []
    env = os.environ.get("KAVACH_CC")
    if env:
        out.append(env)
    out.append("clang")
    out += [p for p in _LLVM_CANDIDATES if os.path.exists(p)]
    return out


def _can_compile(cc: str, extra: List[str]) -> bool:
    if not (os.path.isabs(cc) and os.path.exists(cc)) and shutil.which(cc) is None:
        return False
    tmp = tempfile.mkdtemp(prefix="kv_probe_")
    try:
        src = os.path.join(tmp, "p.c")
        out = os.path.join(tmp, "p")
        util.write_text(src, "int LLVMFuzzerTestOneInput(const unsigned char*d,"
                              "unsigned long n){return 0;}\n"
                              if "fuzzer" in " ".join(extra)
                              else "int main(void){return 0;}\n")
        r = util.run([cc] + BASE_FLAGS + extra + [src, "-o", out])
        return r.ok and os.path.exists(out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def detect(prefer: Optional[str] = None) -> Toolchain:
    """Pick the best available engine. `prefer` can force 'libfuzzer' or
    'standalone'; falls through if the forced choice is unavailable."""
    want = prefer or os.environ.get("KAVACH_ENGINE")

    if want in (None, "libfuzzer"):
        for cc in _clang_candidates():
            if _can_compile(cc, ["-fsanitize=fuzzer,address"]):
                label = "clang" if cc == "clang" else cc
                return Toolchain("libfuzzer", cc,
                                 "%s libFuzzer + AddressSanitizer (coverage-guided)" % label)
        if want == "libfuzzer":
            util.warn("libFuzzer requested but clang/compiler-rt unavailable; "
                      "falling back")

    for cc in ("clang", "gcc", "cc"):
        if _can_compile(cc, ["-fsanitize=address"]):
            cov = ""
            for flag in ("-fsanitize-coverage=trace-pc-guard", "-fsanitize-coverage=trace-pc"):
                if _can_compile(cc, ["-fsanitize=address", flag]):
                    cov = flag
                    break
            note = ("%s + AddressSanitizer (standalone, %s)"
                    % (cc, "coverage-guided" if cov else "blind mutational"))
            return Toolchain("standalone", cc, note, cov)

    raise RuntimeError(
        "No usable C sanitizer toolchain found. Install clang+compiler-rt or "
        "gcc+libasan, or run KavachForge via Docker (./kavach ... --docker).")


def build_fuzzer_cmd(tc: Toolchain, sources: List[str], harness: str,
                     include_dirs: List[str], out_bin: str) -> List[str]:
    """Command that produces the discovery binary `out_bin`."""
    inc = []
    for d in include_dirs:
        inc += ["-I", d]
    if tc.is_libfuzzer:
        san = ["-fsanitize=fuzzer,address"]
        extra_src: List[str] = []
    else:
        san = ["-fsanitize=address"] + ([tc.cov_flag] if tc.cov_flag else [])
        extra_src = [STANDALONE_MAIN]
    return [tc.cc] + BASE_FLAGS + san + inc + sources + [harness] + extra_src + \
           ["-o", out_bin]


def build_test_cmd(tc: Toolchain, test_sources: List[str],
                   include_dirs: List[str], out_bin: str) -> List[str]:
    """Command that builds the regression-test binary (ASan only, no fuzzer)."""
    inc = []
    for d in include_dirs:
        inc += ["-I", d]
    return [tc.cc] + BASE_FLAGS + ["-fsanitize=address"] + inc + test_sources + \
           ["-o", out_bin]
