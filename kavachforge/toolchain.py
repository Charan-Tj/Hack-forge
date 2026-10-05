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


def _probe_coverage(cc: str) -> str:
    """Return a working SanitizerCoverage flag for `cc`, or "". The probe
    links a stub harness WITH the standalone driver (which defines the
    __sanitizer_cov_* callbacks) + the cov flag — exactly how the real
    discovery binary is built — so detection reflects reality, not a bare
    program that is missing the callback symbols (gcc uses trace-pc, clang
    trace-pc-guard)."""
    tmp = tempfile.mkdtemp(prefix="kv_cov_")
    try:
        stub = os.path.join(tmp, "h.c")
        out = os.path.join(tmp, "h")
        util.write_text(stub, "#include <stddef.h>\n#include <stdint.h>\n"
                              "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
                              "{(void)d;(void)n;return 0;}\n")
        for flag in ("-fsanitize-coverage=trace-pc-guard", "-fsanitize-coverage=trace-pc"):
            r = util.run([cc] + BASE_FLAGS + ["-fsanitize=address", flag,
                          stub, STANDALONE_MAIN, "-o", out])
            if not (r.ok and os.path.exists(out)):
                continue
            # Must also RUN cleanly on a trivial input: if instrumentation makes
            # the driver itself fault (e.g. a compiler that instruments the
            # coverage callbacks into self-recursion), reject this flag and fall
            # back to blind mutation rather than report phantom crashes.
            probe_in = os.path.join(tmp, "in")
            util.write_text(probe_in, "x")
            rr = util.run([out, probe_in],
                          env={"ASAN_OPTIONS": "detect_leaks=0", "KV_COV_OUT": os.path.join(tmp, "c")},
                          timeout=10, cpu_seconds=8)
            if rr.ok and not ("AddressSanitizer" in (rr.err + rr.out)):
                return flag
            try:
                os.remove(out)
            except OSError:
                pass
        return ""
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
            cov = _probe_coverage(cc)
            note = ("%s + AddressSanitizer (standalone, %s)"
                    % (cc, "coverage-guided" if cov else "blind mutational"))
            return Toolchain("standalone", cc, note, cov)

    raise RuntimeError(
        "No usable C sanitizer toolchain found. Install clang+compiler-rt or "
        "gcc+libasan, or run KavachForge via Docker (./kavach ... --docker).")


CXX_EXT = (".cc", ".cpp", ".cxx", ".C")


def is_cxx(path: str) -> bool:
    return path.endswith(CXX_EXT)


def cxx_for(cc: str) -> str:
    """The C++ front-end that pairs with the C compiler `cc`."""
    base = os.path.basename(cc)
    name = {"clang": "clang++", "gcc": "g++", "cc": "c++"}.get(base)
    if name is None:
        # clang-18 -> clang++-18, /opt/llvm/bin/clang -> /opt/llvm/bin/clang++
        name = base.replace("clang", "clang++", 1) if "clang" in base else \
               base.replace("gcc", "g++", 1) if "gcc" in base else base + "++"
    d = os.path.dirname(cc)
    if d and "/" in cc and "\\" not in cc:
        return d.rstrip("/") + "/" + name
    return os.path.join(d, name) if d else name


def _compiler_for(tc: Toolchain, files: List[str]) -> List[str]:
    """Pick the C or C++ driver for `tc.cc` based on the files being built
    (single-language builds). Mixed C/C++ builds go through `_mixed_cmd`."""
    if not any(is_cxx(f) for f in files):
        return [tc.cc]
    return [cxx_for(tc.cc), "-std=c++17"]


def _q(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _mixed_cmd(tc: Toolchain, files: List[str], flags: List[str], out_bin: str,
               link_flags: List[str]) -> str:
    """Shell command for a build that mixes C and C++ translation units
    (common in real repos: a C library with a C++ fuzz harness). Each file is
    compiled by its own front-end into <out_bin>.objs/, then linked with the
    C++ driver so the C++ runtime is pulled in."""
    objdir = out_bin + ".objs"
    cxx = cxx_for(tc.cc)
    steps = ["mkdir -p %s" % _q(objdir)]
    objs = []
    for i, f in enumerate(files):
        o = os.path.join(objdir, "%03d_%s.o" % (i, os.path.basename(f)))
        objs.append(o)
        comp = [cxx, "-std=c++17"] if is_cxx(f) else [tc.cc]
        steps.append(" ".join(_q(x) for x in comp + flags + ["-c", f, "-o", o]))
    lflags, skip = [], False
    for x in flags:                      # drop "-I dir" pairs for the link step
        if skip:
            skip = False; continue
        if x == "-I":
            skip = True; continue
        lflags.append(x)
    link = [cxx] + lflags + objs + ["-o", out_bin] + link_flags
    steps.append(" ".join(_q(x) for x in link))
    return " && ".join(steps)


def _build(tc: Toolchain, files: List[str], san: List[str], include_dirs: List[str],
           out_bin: str, link_flags: Optional[List[str]]):
    inc: List[str] = []
    for d in include_dirs:
        inc += ["-I", d]
    flags = BASE_FLAGS + san + inc
    lf = list(link_flags or [])
    if len({is_cxx(f) for f in files}) > 1:
        return _mixed_cmd(tc, files, flags, out_bin, lf)
    comp = _compiler_for(tc, files)
    return comp + flags + files + ["-o", out_bin] + lf


def cmd_str(cmd) -> str:
    return cmd if isinstance(cmd, str) else " ".join(cmd)


def build_fuzzer_cmd(tc: Toolchain, sources: List[str], harness: str,
                     include_dirs: List[str], out_bin: str,
                     link_flags: Optional[List[str]] = None):
    """Command that produces the discovery binary `out_bin` (a list, or a
    shell string for mixed C/C++ builds; util.run accepts both)."""
    if tc.is_libfuzzer:
        san = ["-fsanitize=fuzzer,address"]
        extra_src: List[str] = []
    else:
        san = ["-fsanitize=address"] + ([tc.cov_flag] if tc.cov_flag else [])
        extra_src = [STANDALONE_MAIN]
    return _build(tc, sources + [harness] + extra_src, san, include_dirs, out_bin, link_flags)


def build_test_cmd(tc: Toolchain, test_sources: List[str],
                   include_dirs: List[str], out_bin: str,
                   link_flags: Optional[List[str]] = None):
    """Command that builds the regression-test binary (ASan only, no fuzzer)."""
    return _build(tc, test_sources, ["-fsanitize=address"], include_dirs, out_bin, link_flags)
