"""Bring-your-own-repository onboarding: turn an arbitrary C/C++ project
into a KavachForge task in one command.

    kavach onboard https://github.com/DaveGamble/cJSON
    kavach onboard ./some/checkout --run

The finale hands teams unfamiliar open-source repositories, so nothing here
may depend on a hand-written task file. The steps are:

  1. Fetch     - clone a URL (shallow) into targets/<name>, or use a local path.
  2. Scan      - find library sources (excluding tests/examples/tools/benchmarks
                 and any file that defines main()), header directories, and
                 every existing libFuzzer harness (LLVMFuzzerTestOneInput).
  3. Build-fix - compile each source on its own and drop the ones that cannot
                 build here (platform-specific files); link the harness and
                 repair the link iteratively: duplicate definitions drop the
                 later file, undefined references add -lm / -lpthread / -ldl /
                 -lz, a missing harness dependency drops it. Every decision is
                 recorded so the judge can see why the task looks as it does.
  4. Harness   - if the repo ships no harness, synthesize one for the best
                 entry point (harness.synthesize) and validate it.
  5. Emit      - tasks/<name>.json (+ one per extra harness), with seeds from
                 any corpus/seed directory the repo carries and the git diff
                 wired in for risk ranking when the checkout is a git repo.

Nothing is guessed silently: the result lists what was kept, what was
dropped and why, and whether the task built.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import config, toolchain, util

SRC_EXT = (".c",) + toolchain.CXX_EXT
EXCLUDE_DIRS = {
    "test", "tests", "testing", "unittest", "unittests", "t",
    "example", "examples", "sample", "samples", "demo", "demos",
    "bench", "benchmark", "benchmarks", "perf",
    "tools", "tool", "scripts", "contrib",
    "doc", "docs", "build", "cmake", "out", "dist", "third_party", "thirdparty",
    "3rdparty", "deps", "vendor", "external", "win32", "windows", "msvc",
    "android", "ios", "apple", "wasm", "emscripten", "python", "java", "ruby",
    "php", "node", "bindings", "swig", "ci", ".github", ".git", "fuzz", "fuzzing",
    "fuzzer", "fuzzers", "oss-fuzz", "afl", "corpus", "seeds", "regress",
}
HARNESS_SYM = "LLVMFuzzerTestOneInput"
_MAIN_RE = re.compile(r"\bint\s+main\s*\(")
_MULTI_RE = re.compile(r"multiple definition of [`'](\w+)'")
_MULTI_FILE_RE = re.compile(r"([^\s:(]+\.o)\)?:")
_UNDEF_RE = re.compile(r"undefined reference to (?:symbol )?[`'](\w+)(?:@@?[\w.]+)?'")
_DSO_RE = re.compile(r"lib(\w+)\.so(?:\.\d+)*: error adding symbols: DSO missing from command line")
_UNDEF_SYM_RE = re.compile(r"undefined symbol:?\s*(\w+)")
_LIB_HINTS = [
    ("-lm", {"sin", "cos", "tan", "pow", "sqrt", "exp", "log", "fabs", "floor",
             "ceil", "fmod", "frexp", "ldexp", "atan2", "round", "trunc", "lround",
             "log10", "log2", "cbrt", "hypot", "nan", "isnan", "isinf", "modf"}),
    ("-lpthread", {"pthread_create", "pthread_join", "pthread_mutex_lock",
                   "pthread_mutex_unlock", "pthread_once", "pthread_key_create"}),
    ("-ldl", {"dlopen", "dlsym", "dlclose", "dlerror"}),
    ("-lz", {"inflate", "deflate", "inflateInit_", "deflateInit_", "crc32",
             "adler32", "compress", "uncompress", "inflateEnd", "deflateEnd"}),
]
SEED_DIRS = ("corpus", "seeds", "seed", "testdata", "test_data", "fuzz/corpus",
             "fuzzing/corpus", "tests/corpus", "test/corpus", "samples", "examples")


@dataclass
class Onboarded:
    name: str
    root: str
    tasks: List[str] = field(default_factory=list)       # task json paths
    sources: List[str] = field(default_factory=list)     # kept (relative)
    dropped: List[Tuple[str, str]] = field(default_factory=list)   # (file, why)
    harnesses: List[str] = field(default_factory=list)   # relative
    synthesized: bool = False
    include_dirs: List[str] = field(default_factory=list)
    link_flags: List[str] = field(default_factory=list)
    built: bool = False
    track: str = "fuzz"            # "fuzz" | "universal"
    detail: str = ""
    log: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)   # test/example/main files (relative)

    def note(self, msg: str):
        self.log.append(msg)


# ---------------------------------------------------------------------------
# 1. fetch
# ---------------------------------------------------------------------------
def _is_url(s: str) -> bool:
    return s.startswith(("http://", "https://", "git@", "ssh://", "git://"))


def _name_from(spec: str) -> str:
    base = spec.rstrip("/").split("/")[-1]
    base = re.sub(r"\.git$", "", base)
    base = re.sub(r"[^A-Za-z0-9_]+", "", base).lower()
    return base or "repo"


def fetch(spec: str, name: Optional[str] = None, dest_dir: Optional[str] = None,
          ref: Optional[str] = None) -> Tuple[str, str]:
    """Return (name, absolute root). Clones a URL shallowly; a local path is
    used in place."""
    name = name or _name_from(spec)
    # never clobber a bundled task/target of the same name (e.g. the vendored
    # cjson vs. a fresh clone of DaveGamble/cJSON)
    tpath = os.path.join(config.PROJECT_ROOT, "tasks", name + ".json")
    if os.path.exists(tpath):
        try:
            import json
            d = json.loads(util.read_text(tpath))
            if not (d.get("_onboarded") or d.get("_synthesized")):
                name += "-oss"
        except Exception:
            name += "-oss"
    if _is_url(spec):
        dest = os.path.join(dest_dir or os.path.join(config.PROJECT_ROOT, "targets", "_onboarded"), name)
        if os.path.isdir(os.path.join(dest, ".git")):
            return name, dest
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        cmd = ["git", "clone", "--depth", "1", "--quiet"] + (["--branch", ref] if ref else []) + [spec, dest]
        r = util.run(cmd, timeout=600)
        if not r.ok:
            raise RuntimeError("clone failed: " + (r.err or r.out)[-400:])
        return name, dest
    root = os.path.abspath(spec)
    if not os.path.isdir(root):
        raise FileNotFoundError("not a directory or URL: %s" % spec)
    return name, root


# ---------------------------------------------------------------------------
# 2. scan
# ---------------------------------------------------------------------------
def _walk(root: str):
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if not d.startswith("."))
        yield dp, dns, fns


def _excluded(rel: str) -> bool:
    parts = rel.replace("\\", "/").lower().split("/")[:-1]
    return any(p in EXCLUDE_DIRS for p in parts)


def scan(root: str) -> Dict[str, List[str]]:
    """Classify files under root (paths relative to root)."""
    libs, harnesses, mains, headers_dirs, tests = [], [], [], set(), []
    for dp, _, fns in _walk(root):
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if fn.endswith((".h", ".hpp", ".hh")):
                headers_dirs.add(os.path.dirname(rel).replace("\\", "/") or ".")
                continue
            if not fn.endswith(SRC_EXT):
                continue
            try:
                text = util.read_text(p)
            except Exception:
                continue
            if HARNESS_SYM in text and not _MAIN_RE.search(text):
                harnesses.append(rel)
                continue
            low = fn.lower()
            if _excluded(rel) or re.search(r"(^|[_\-.])(test|tests|bench|example|fuzz)", low):
                tests.append(rel)
                continue
            if _MAIN_RE.search(text):
                # may be a real program, or a library with an #ifdef'd test
                # main (sds.c); the object file decides in build_fix (nm)
                mains.append(rel)
            libs.append(rel)
    return {"sources": libs, "harnesses": harnesses, "mains": mains,
            "include_dirs": sorted(headers_dirs), "skipped": tests}


_IMPL_RE = re.compile(r"#\s*if(?:def|\s+defined\s*\(?)\s*(\w+_IMPLEMENTATION)\b")


def header_only_sources(root: str, include_dirs: List[str]) -> List[str]:
    """For a header-only library (jsmn, stb_*, ...) emit one translation unit
    per implementation header under .kavach/src/, defining the usual
    *_IMPLEMENTATION macro when the header expects it."""
    from . import harness as hz
    out = []
    for d in include_dirs:
        if _excluded(os.path.join(d, "x")) and d != ".":
            continue
        dp = os.path.join(root, d)
        for h in sorted(os.listdir(dp)):
            if not h.endswith(".h"):
                continue
            text = util.read_text(os.path.join(dp, h))
            if len(text) < 500 or not hz._FUNC_RE.search(text):
                continue
            # the header must define at least one non-static function body
            if not any(not re.search(r"\bstatic\b", m.group(1))
                       for m in hz._FUNC_RE.finditer(text)):
                continue
            m = _IMPL_RE.search(text)
            stem = os.path.splitext(h)[0]
            tu = os.path.join(root, ".kavach", "src", "%s_impl.c" % stem)
            body = ("/* KavachForge: translation unit for header-only library %s */\n" % h
                    + ("#define %s\n" % m.group(1) if m else "")
                    + '#include "%s"\n' % os.path.join(d, h).replace("./", ""))
            util.write_text(tu, body)
            out.append(os.path.relpath(tu, root))
    return out


def _rank_includes(root: str, dirs: List[str], sources: List[str]) -> List[str]:
    """Order header directories: project root/include/src first, then the
    directories of the kept sources, then the rest (capped)."""
    pref = [".", "include", "src", "lib", "source"]
    srcdirs = {os.path.dirname(s) or "." for s in sources}
    def key(d):
        if d in pref:
            return (0, pref.index(d))
        if d in srcdirs:
            return (1, d.count(os.sep))
        if _excluded(os.path.join(d, "x")):
            return (3, d.count(os.sep))
        return (2, d.count(os.sep))
    out = [d for d in sorted(set(dirs) | {"."}, key=key)
           if not (_excluded(os.path.join(d, "x")) and d.count(os.sep) >= 1)]
    return out[:24]


_CODE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py", ".sh", ".cmake", ".md",
             ".in", ".am", ".ac", ".m4", ".mk", ".o", ".a", ".so", ".txt.in", ".yml", ".yaml",
             ".toml", ".gitignore", ".pc", ".def", ".rc")


def find_seeds(root: str, limit: int = 48) -> List[str]:
    """Real sample inputs the repo already carries: a corpus/seed directory
    first, else small data fixtures under tests/examples/testdata (anything
    that is not source, build or doc). These become fuzzing seeds AND the
    behaviour-preservation corpus, so they matter twice."""
    for d in SEED_DIRS:
        p = os.path.join(root, d)
        if not os.path.isdir(p) or not ("corpus" in d or "seed" in d):
            continue
        files = [os.path.join(d, f) for f in sorted(os.listdir(p))
                 if os.path.isfile(os.path.join(p, f))
                 and 0 < os.path.getsize(os.path.join(p, f)) <= 64 * 1024]
        if files:
            return files[:limit]
    out: List[str] = []
    for d in ("tests", "test", "testdata", "test_data", "examples", "example", "samples",
              "fuzz", "fuzzing", "data", "fixtures", "resources", "res", "assets"):
        p = os.path.join(root, d)
        if not os.path.isdir(p):
            continue
        for dp, dns, fns in os.walk(p):
            dns[:] = sorted(x for x in dns if x not in ("unity", "cmocka", "catch2", "googletest", ".git"))
            for fn in sorted(fns):
                fp = os.path.join(dp, fn)
                low = fn.lower()
                if low.endswith(_CODE_EXT) or low in ("makefile", "cmakelists.txt", "license", "readme"):
                    continue
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue
                if 0 < sz <= 32 * 1024:
                    out.append(os.path.relpath(fp, root))
                if len(out) >= limit:
                    return out
    return out


# ---------------------------------------------------------------------------
# 3. build-fix
# ---------------------------------------------------------------------------
def _compile_one(tc, path: str, incs: List[str], tmp: str, extra: List[str] = ()) -> "util.CmdResult":
    comp = [toolchain.cxx_for(tc.cc), "-std=c++17"] if toolchain.is_cxx(path) else [tc.cc]
    inc = []
    for d in incs:
        inc += ["-I", d]
    out = _obj_path(tmp, path)
    return util.run(comp + toolchain.BASE_FLAGS + ["-fsanitize=address"] + list(extra) + inc +
                    ["-c", path, "-o", out], timeout=90)


def _first_error(err: str) -> str:
    lines = [l for l in err.strip().splitlines() if "error:" in l] or err.strip().splitlines() or ["(no diagnostic)"]
    return lines[0][-200:]


def _obj_path(tmp: str, path: str) -> str:
    return os.path.join(tmp, "o_%s.o" % util.sha256_bytes(path.encode())[:8])


def _defines_main(obj: str) -> bool:
    """Ground truth for 'is this a program?': the compiled object exports
    main (an #ifdef'd test main that is compiled out does not count)."""
    if not shutil.which("nm"):
        return False
    r = util.run(["nm", "-g", "--defined-only", obj], timeout=30)
    return any(line.split()[-1] in ("main", "_main") and " T " in line
               for line in r.out.splitlines() if line.strip())


def _sym_file_map(err: str) -> List[Tuple[str, str]]:
    """Pairs (symbol, object-basename) from 'multiple definition' diagnostics
    (both GNU ld and lld shapes)."""
    out = []
    for line in err.splitlines():
        m = _MULTI_RE.search(line)
        if not m:
            continue
        # GNU ld: "/usr/bin/ld: b.o:(.text+0x0): multiple definition of `f'; a.o:(.text+0x0): first defined here"
        # lld:    "ld.lld: error: duplicate symbol: f" ... ">>> defined at b.c:3" ">>> b.o:(f)"
        objs = re.findall(r"([\w./\-]+\.o)", line)
        out.append((m.group(1), os.path.basename(objs[0]) if objs else ""))
    for m in re.finditer(r"duplicate symbol: (\w+)\n>>> defined at ([^\n]+)\n>>>\s+([^\s:(]+)", err):
        out.append((m.group(1), os.path.basename(m.group(3))))
    return out


def _undefined(err: str) -> List[str]:
    return list(dict.fromkeys(_UNDEF_RE.findall(err) + _UNDEF_SYM_RE.findall(err)))


def _obj_to_source(obj_base: str, files: List[str]) -> Optional[str]:
    # mixed builds name objects "NNN_<basename>.o"; single-language builds
    # use the compiler's "<stem>-<hash>.o" / "<stem>.o"
    stem = re.sub(r"^\d{3}_", "", obj_base)
    stem = re.sub(r"\.o$", "", stem)
    stem = re.sub(r"-[0-9a-f]{6}$", "", stem)
    for f in files:
        b = os.path.basename(f)
        if b == stem or os.path.splitext(b)[0] == stem:
            return f
    return None


def _defines(path: str, sym: str) -> bool:
    try:
        t = util.read_text(path)
    except Exception:
        return False
    return re.search(r"\b%s\s*\(" % re.escape(sym), t) is not None


def compile_pass(tc, root: str, sources: List[str], incs: List[str], ob: Onboarded) -> List[str]:
    """Pass 1: every translation unit must compile on this machine and must
    not be a program (nm says main). Returns absolute paths of kept files."""
    tmp = tempfile.mkdtemp(prefix="kv_onb_")
    try:
        absinc = [os.path.join(root, d) for d in incs]
        kept: List[str] = []
        for s in sources:
            a = os.path.join(root, s)
            r = _compile_one(tc, a, absinc, tmp)
            if r.ok and _defines_main(_obj_path(tmp, a)):
                ob.dropped.append((s, "defines main() - a program, not library code"))
                if s not in ob.skipped:
                    ob.skipped.append(s)
            elif r.ok:
                kept.append(a)
            else:
                ob.dropped.append((s, "does not compile here: " + _first_error(r.err)))
        return kept
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_fix(tc, root: str, kept_abs: List[str], harness: str, incs: List[str],
              ob: Onboarded, max_rounds: int = 12) -> Tuple[List[str], List[str], bool, str]:
    """Pass 2: link the harness against the kept sources, repairing the link
    iteratively. Returns (kept_sources_abs, link_flags, ok, detail)."""
    tmp = tempfile.mkdtemp(prefix="kv_onb_")
    try:
        absinc = [os.path.join(root, d) for d in incs]
        kept = list(kept_abs)
        habs = os.path.join(root, harness)
        hr = _compile_one(tc, habs, absinc, tmp, extra=(["-fsanitize=fuzzer"] if tc.is_libfuzzer else []))
        if not hr.ok:
            return kept, [], False, "harness does not compile: " + _first_error(hr.err)
        link_flags: List[str] = []
        tried_libs = set()
        for rnd in range(max_rounds):
            out_bin = os.path.join(tmp, "fz%d" % rnd)
            cmd = toolchain.build_fuzzer_cmd(tc, kept, habs, absinc, out_bin, link_flags)
            r = util.run(cmd, timeout=300)
            if r.ok and os.path.exists(out_bin):
                return kept, link_flags, True, "links with %d source file(s)%s" % (
                    len(kept), (" + " + " ".join(link_flags)) if link_flags else "")
            err = r.err + r.out
            changed = False
            # duplicate definitions -> drop the file that re-defines the symbol
            for sym, obj in _sym_file_map(err):
                f = _obj_to_source(obj, kept)
                if f is None:
                    cands = [k for k in kept if _defines(k, sym)]
                    f = cands[-1] if len(cands) > 1 else None
                if f and f in kept and f != habs:
                    kept.remove(f)
                    ob.dropped.append((os.path.relpath(f, root),
                                       "duplicate definition of %s()" % sym))
                    changed = True
            if changed:
                continue
            undef = _undefined(err)
            # gcc/ld spell a missing shared lib as "libm.so.6: ... DSO missing"
            for dso in _DSO_RE.findall(err):
                lib = "-l" + dso
                if lib not in tried_libs:
                    link_flags.append(lib); tried_libs.add(lib); changed = True
            if changed:
                continue
            if undef:
                for lib, syms in _LIB_HINTS:
                    if lib not in tried_libs and any(u in syms or u.rstrip("f") in syms or u.lstrip("_") in syms for u in undef):
                        link_flags.append(lib); tried_libs.add(lib); changed = True
                if not changed:
                    # a file we excluded (helper under fuzz/, tests/, ...) that
                    # the harness needs: re-add any skipped file defining it
                    for u in undef:
                        for s in ob.skipped:
                            a = os.path.join(root, s)
                            if a in kept or a == habs:
                                continue
                            if _defines(a, u) and _compile_one(tc, a, absinc, tmp).ok \
                                    and not _defines_main(_obj_path(tmp, a)):
                                kept.append(a); changed = True
                                ob.note("re-added %s (defines %s)" % (s, u))
                                break
                if changed:
                    continue
                return kept, link_flags, False, "unresolved symbols: %s" % ", ".join(undef[:6])
            return kept, link_flags, False, (err.strip().splitlines() or ["link failed"])[-1][-200:]
        return kept, link_flags, False, "could not repair the build in %d rounds" % max_rounds
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 4/5. harness + emit
# ---------------------------------------------------------------------------
_TU_RE = re.compile(r"translation unit for header-only library (\S+)")


def analysis_file(root: str, src: str) -> str:
    """The file whose functions are entry points: the source itself, or the
    header behind a generated header-only translation unit."""
    a = os.path.join(root, src)
    if os.sep + ".kavach" + os.sep in a:
        m = _TU_RE.search(util.read_text(a))
        inc = re.search(r'#include "([^"]+)"', util.read_text(a))
        if m and inc:
            return os.path.join(root, inc.group(1))
    return a


def _pick_entry_source(root: str, sources: List[str], allow_cxx: bool = False) -> Optional[str]:
    """For harness synthesis: the library file with the best entry point.
    C++ entry points need a model to wire them (allow_cxx)."""
    from . import harness as hz
    best, best_score = None, 0
    for s in sources:
        if toolchain.is_cxx(s) and not allow_cxx:
            continue
        try:
            ents = hz.analyze(analysis_file(root, s))
        except Exception:
            continue
        if ents and ents[0].score > best_score:
            best, best_score = s, ents[0].score
    return best


def _write_task(name: str, root: str, sources: List[str], harness: str,
                incs: List[str], link_flags: List[str], seeds: List[str],
                budget_s: int, description: str, probe: Optional[str] = None,
                is_git: bool = False, patch_scope: Optional[List[str]] = None) -> str:
    rel = lambda p: os.path.relpath(p, root).replace(os.sep, "/")
    task = {
        "name": name,
        "language": "cpp" if any(toolchain.is_cxx(s) for s in sources + [harness]) else "c",
        "description": description,
        "root": root if not root.startswith(config.PROJECT_ROOT + os.sep) else rel_proj(root),
        "sources": [rel(s) for s in sources],
        "include_dirs": incs,
        "harness": rel(harness),
        "test_sources": [],
        "patch_scope": [rel(s) for s in patch_scope or sources],
        "magic": None,
        "static_alerts": [],
        "seeds": seeds,
        "budgets": {"time_budget_s": budget_s, "rng_seed": 1337},
        "link_flags": link_flags,
        "_onboarded": True,
    }
    if probe:
        task["probe"] = rel(probe)
    if is_git:
        task["diff"] = "git"
    path = os.path.join(config.PROJECT_ROOT, "tasks", "%s.json" % name)
    util.write_json(path, task)
    return path


def generate_config(root: str, log=lambda m: None) -> List[str]:
    """Best-effort: run cmake (or ./configure) so generated headers exist.
    Returns extra include dirs (relative to root) that now hold headers."""
    out: List[str] = []
    bdir = os.path.join(root, ".kavach", "build")
    if os.path.exists(os.path.join(root, "CMakeLists.txt")) and shutil.which("cmake"):
        log("missing generated headers: trying cmake configure")
        os.makedirs(bdir, exist_ok=True)
        r = util.run(["cmake", "-S", root, "-B", bdir, "-DBUILD_TESTING=OFF", "-DBUILD_SHARED_LIBS=OFF"],
                     timeout=300)
        if r.ok:
            for dp, _, fns in os.walk(bdir):
                if any(f.endswith(".h") for f in fns):
                    out.append(os.path.relpath(dp, root))
    if not out and os.path.exists(os.path.join(root, "configure")):
        log("missing generated headers: trying ./configure")
        r = util.run(["sh", "-c", "./configure >/dev/null 2>&1"], cwd=root, timeout=300)
        if r.ok:
            out.append(".")
    return out[:8]


def rel_proj(p: str) -> str:
    return os.path.relpath(p, config.PROJECT_ROOT).replace(os.sep, "/")


def sanity(tc, root: str, kept: List[str], habs: str, incs: List[str],
           link_flags: List[str], tname: str) -> str:
    """Build the discovery binary once and feed it a few trivial inputs: a
    harness that faults on "" or "x" is almost certainly mis-wired, and the
    judge should know before the loop reports a 'finding' on it."""
    from . import discovery
    scratch = os.path.join(config.PROJECT_ROOT, "artifacts", "onboard", tname)
    os.makedirs(scratch, exist_ok=True)
    out_bin = os.path.join(scratch, "fuzzer")
    absinc = [os.path.join(root, d) for d in incs]
    r = util.run(toolchain.build_fuzzer_cmd(tc, kept, habs, absinc, out_bin, link_flags), timeout=300)
    if not r.ok:
        return "sanity build failed"
    for probe in (b"", b"x", b"{}", b"\x00\x00\x00\x00", b"0123456789abcdef"):
        pf = os.path.join(scratch, "in")
        with open(pf, "wb") as f:
            f.write(probe)
        rr = discovery._run_one(out_bin, pf, 2048)
        if discovery._is_crash(rr):
            return "SUSPICIOUS - faults on trivial input %r (check the harness before trusting findings)" % probe[:8]
    return "sanity OK (clean on trivial inputs)"


def write_universal_task(name: str, root: str, stacks: List[str], description: str = "") -> str:
    task = {
        "name": name, "kind": "universal", "language": ",".join(stacks) or "unknown",
        "description": description or "%s (onboarded; stacks: %s; static track)" % (
            os.path.basename(root), ", ".join(stacks) or "unknown"),
        "root": root if not root.startswith(config.PROJECT_ROOT + os.sep) else rel_proj(root),
        "stacks": stacks, "sources": [], "patch_scope": [], "test_sources": [],
        "static_alerts": [], "budgets": {"time_budget_s": 0}, "_onboarded": True,
    }
    if os.path.isdir(os.path.join(root, ".git")):
        task["diff"] = "git"
    path = os.path.join(config.PROJECT_ROOT, "tasks", "%s.json" % name)
    util.write_json(path, task)
    return path


def onboard(spec: str, name: Optional[str] = None, harness_sel: Optional[str] = None,
            budget_s: int = 60, tc=None, client=None, ref: Optional[str] = None,
            mode: str = "auto", log=lambda m: None) -> Onboarded:
    """mode: auto (C/C++ fuzz track when the repo has C/C++ library sources,
    else the universal static track), fuzz, or universal."""
    from . import universal
    name, root = fetch(spec, name, ref=ref)
    ob = Onboarded(name=name, root=root)
    stacks = universal.detect_stacks(root)
    log("stacks: %s" % (", ".join(stacks) or "none recognised"))
    if mode == "universal" or (mode == "auto" and "c" not in stacks):
        if not stacks and not universal.source_files(root):
            ob.detail = "no source files in a language KavachForge recognises"
            return ob
        ob.tasks.append(write_universal_task(name, root, stacks))
        ob.built = True
        ob.track = "universal"
        ob.detail = "universal track: %s; %d source file(s) in scope" % (
            ", ".join(stacks) or "unknown stack", len(universal.source_files(root)))
        return ob
    ob.track = "fuzz"
    tc = tc or toolchain.detect()
    info = scan(root)
    ob.skipped = list(info["skipped"])
    log("scan: %d library source(s), %d harness(es), %d header dir(s), %d skipped"
        % (len(info["sources"]), len(info["harnesses"]), len(info["include_dirs"]),
           len(info["skipped"])))
    if not info["sources"]:
        info["sources"] = header_only_sources(root, info["include_dirs"])
        if info["sources"]:
            log("header-only library: generated %d translation unit(s) under .kavach/src"
                % len(info["sources"]))
    if not info["sources"]:
        ob.detail = "no C/C++ library sources found"
        return ob
    incs = _rank_includes(root, info["include_dirs"], info["sources"])
    ob.include_dirs = incs
    seeds = find_seeds(root)
    is_git = os.path.isdir(os.path.join(root, ".git"))

    kept0 = compile_pass(tc, root, info["sources"], incs, ob)
    if info["sources"] and len(kept0) * 2 < len(info["sources"]) \
            and any("file not found" in why or "No such file" in why for _, why in ob.dropped):
        # a generated header (config.h, *conf.h) is missing: let the project's
        # own build system generate it, then widen the include path and retry
        gen = generate_config(root, log)
        if gen:
            incs = list(dict.fromkeys(incs + gen))
            ob.include_dirs = incs
            ob.dropped = []
            kept0 = compile_pass(tc, root, info["sources"], incs, ob)
    if not kept0 and not info["harnesses"]:
        ob.detail = "none of the %d library source(s) compile here (see dropped list)" % len(info["sources"])
        return ob

    harnesses = info["harnesses"]
    if harness_sel:
        harnesses = [h for h in harnesses if harness_sel in h] or harnesses
    if not harnesses:
        # synthesize one from the best entry point
        from . import harness as hz
        src = _pick_entry_source(root, [os.path.relpath(k, root) for k in kept0], allow_cxx=client is not None)
        if not src:
            ob.detail = ("no libFuzzer harness in the repo and no fuzzable entry point to synthesize one"
                         + ("" if client else " (add --provider: a model can wire non-trivial or C++ APIs)"))
            return ob
        afile = analysis_file(root, src)
        log("no harness shipped; synthesizing one for %s" % os.path.relpath(afile, root))
        inc_dir = os.path.dirname(afile)
        # harness.synthesize writes into <root>/harness/ relative to the include dir's parent;
        # give it a dedicated subdir so we never touch the repo's own layout
        syn_root = os.path.join(root, ".kavach")
        os.makedirs(os.path.join(syn_root, "src"), exist_ok=True)
        hdr_dir = os.path.join(syn_root, "src")
        # expose the entry header next to the source (prefer <stem>.h)
        stem = os.path.splitext(os.path.basename(afile))[0]
        hdrs = sorted(h for h in os.listdir(inc_dir) if h.endswith(".h"))
        hdrs = [h for h in hdrs if h == stem + ".h"] or hdrs
        for h in hdrs:
            shutil.copy(os.path.join(inc_dir, h), os.path.join(hdr_dir, h))
        syn = hz.synthesize(os.path.join(root, src), hdr_dir, name, client=client, tc=tc,
                            analysis_path=afile,
                            extra_sources=list(kept0),
                            extra_includes=[os.path.join(root, d) for d in incs])
        if not syn.harness_path:
            ob.detail = "harness synthesis failed: " + syn.detail
            return ob
        ob.synthesized = True
        ob.note("synthesized harness: entry '%s' (%s)%s" % (
            syn.entry.name, syn.entry.shape,
            "" if syn.validated else " - single-file validation failed, re-validated by build-fix below"))
        harnesses = [os.path.relpath(syn.harness_path, root)]
        # synthesize() wrote a task for a single file; we overwrite it below
        probe = syn.probe_path or None
    else:
        probe = None

    ok_any = False
    for i, h in enumerate(harnesses[:6]):
        tname = name if i == 0 else "%s-%s" % (name, re.sub(r"[^a-z0-9]+", "", os.path.splitext(os.path.basename(h))[0].lower())[:16])
        log("build-fix: harness %s" % h)
        kept, lf, ok, detail = build_fix(tc, root, kept0, h, incs, ob)
        log(("  " + detail) if ok else ("  FAILED: " + detail))
        if not ok:
            ob.note("harness %s: %s" % (h, detail))
            continue
        ok_any = True
        ob.harnesses.append(h)
        ob.sources = [os.path.relpath(k, root) for k in kept]
        ob.link_flags = lf
        ob.note("harness %s: %s" % (h, sanity(tc, root, kept, os.path.join(root, h), incs, lf, tname)))
        desc = "%s (onboarded%s; harness %s)" % (
            os.path.basename(root), ", synthesized harness" if ob.synthesized else "", os.path.basename(h))
        # patch scope: the real library files - for a header-only library the
        # header(s), even when the generated translation unit was dropped
        # because the harness's own #include already defines everything
        scope = list(dict.fromkeys(analysis_file(root, os.path.relpath(k, root))
                                   for k in kept + [os.path.join(root, x) for x in info["sources"]]
                                   if not os.path.relpath(k, root).startswith(".kavach" + os.sep)
                                   or analysis_file(root, os.path.relpath(k, root)) != k))
        tp = _write_task(tname, root, kept, os.path.join(root, h), incs, lf, seeds,
                         budget_s, desc, probe=probe, is_git=is_git,
                         patch_scope=scope if scope != kept else None)
        ob.tasks.append(tp)
    ob.built = ok_any
    if ok_any:
        ob.detail = "%d task(s) written; %d source file(s) kept, %d dropped" % (
            len(ob.tasks), len(ob.sources), len(ob.dropped))
    elif not ob.detail:
        ob.detail = "no harness could be built against the library"
    if not ok_any and mode == "auto":
        log("fuzz track unavailable (%s) - falling back to the universal static track" % ob.detail)
        ob.tasks.append(write_universal_task(name, root, stacks))
        ob.built, ob.track = True, "universal"
        ob.detail += "; universal track task written instead"
    return ob
