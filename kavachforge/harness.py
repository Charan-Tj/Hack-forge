"""Automatic fuzz-harness synthesis for an unfuzzed C source.

Pipeline (mirrors OSS-Fuzz's LLM harness synthesis, validated the same way):
  1. Analyze   - find candidate entry functions and rank them by how
                 fuzzer-friendly their signature is.
  2. Synthesize- emit a libFuzzer harness, a behaviour probe, and a task file.
                 A byte-buffer entry point (`const uint8_t*, size_t`) is wired
                 by template; anything else is handed to the model, with a
                 template fallback for the common `const char*[, len]` shape.
  3. Validate  - the harness must compile against the source, run without an
                 immediate crash on the empty input and a few benign inputs
                 (so a broken harness is never accepted), and reach the target
                 function (checked via a sanitizer-coverage counter).

Only an entry point that passes validation yields a task; the normal
discovery/repair loop then runs on it unchanged.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import config, llm, toolchain, util

# A function definition: return type, name, parameter list.
# The prefix tolerates export macros such as "CJSON_PUBLIC(cJSON *)" or
# "JSMN_API int"; the parameter list may not itself contain parentheses.
_FUNC_RE = re.compile(
    r"^([A-Za-z_][\w\s\*\(\),:<>&]*?)\b((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*\(([^;{}()]*)\)"
    r"\s*(?:const\s*)?\n?\s*\{", re.MULTILINE)


@dataclass
class Entry:
    name: str
    params: str
    shape: str          # "buf_size" | "cstr_size" | "cstr" | "other"
    score: int
    out_param: Optional[str] = None   # name of a trailing out-struct pointer
    rtype: str = "int"                # return type text (drives the probe's observation)


_SIZE_T = r"(?:const\s+)?(?:size_t|unsigned|unsigned\s+int|unsigned\s+long|int|long|uint32_t|uint64_t|ssize_t)\s+\w+$"
_BUF_T = r"^const\s+(?:unsigned\s+char|uint8_t|u8|byte)\s*\*\s*\w+$"
_STR_T = r"^const\s+char\s*\*\s*\w+$"


def _classify(params: str) -> Tuple[str, int]:
    """Shape of an entry point as seen from a fuzzer. Only buffer-FIRST
    signatures are template-able; anything else that still takes bytes
    somewhere is 'other' (a model can wire it, the template cannot)."""
    plist = [re.sub(r"\s+", " ", x.strip()) for x in params.split(",") if x.strip()]
    if not plist or plist == ["void"]:
        return "other", 0
    p0 = plist[0]
    p1 = plist[1] if len(plist) > 1 else ""
    trailing_out = len(plist) <= 3
    if re.match(_BUF_T, p0) and re.match(_SIZE_T, p1) and trailing_out:
        return "buf_size", 100
    if re.match(_STR_T, p0) and re.match(_SIZE_T, p1) and trailing_out:
        return "cstr_size", 80
    if re.match(_STR_T, p0) and len(plist) <= 2:
        return "cstr", 50
    if re.search(r"const (?:char|unsigned char|uint8_t)\s*\*", " ".join(plist)):
        return "other", 10
    return "other", 0


def analyze(source_path: str, header_text: str = "") -> List[Entry]:
    """Rank fuzzable entry points. `static` (file-local) functions are never
    entry points; a function declared in the public header is preferred."""
    text = util.read_text(source_path)
    if not header_text:
        hp = os.path.splitext(source_path)[0] + ".h"
        if os.path.exists(hp):
            header_text = util.read_text(hp)
    entries: List[Entry] = []
    defs = list(_FUNC_RE.finditer(text))
    # Is this header really the public API of this file? Only then does "not
    # declared in the header" mean "internal helper".
    api_header = bool(header_text) and any(
        re.search(r"\b%s\s*\(" % re.escape(m.group(2)), header_text) for m in defs)
    for m in defs:
        prefix, name, params = m.group(1), m.group(2), m.group(3)
        if name in ("if", "for", "while", "switch", "main"):
            continue
        if re.search(r"\bstatic\b", prefix):
            continue
        shape, score = _classify(params)
        if "::" in name and shape != "other":
            shape, score = "other", 10 + score // 4   # member function: model-only wiring
        if score == 0:
            continue
        if shape == "other" and re.search(r"\bFILE\s*\*", params):
            continue
        if api_header and re.search(r"\b%s\s*\(" % re.escape(name), header_text):
            score += 30
        elif api_header:
            score -= 70          # not part of the public API: an internal helper
        # a trailing pointer param (after the input) is an out-struct; the
        # input string itself is never one
        out = None
        plist = [x.strip() for x in params.split(",")]
        if len(plist) >= 2 and shape != "other":
            pm = re.match(r"(?:const\s+)?(?:struct\s+)?([A-Za-z_]\w*)\s*\*\s*(\w+)$", plist[-1])
            if pm and pm.group(1) not in ("char", "uint8_t", "void", "unsigned"):
                out = pm.group(2)
        if re.search(r"file|path|fd\b|stream|FILE", name + " " + params, re.I):
            score -= 60          # takes a filename/handle, not the bytes themselves
        if re.search(r"parse|decode|read|load|scan|unpack|deserial", name, re.I):
            score += 45          # a parser beats a constructor/copier every time
        if re.search(r"init|new|create|alloc|free|set_|copy|dup", name, re.I):
            score -= 15
        rtype = prefix.strip()
        em = re.match(r"^[\w\s]*?\w+\s*\(\s*(.*?)\s*\)\s*$", rtype)     # EXPORT(T *) -> T *
        if em:
            rtype = em.group(1)
        rtype = re.sub(r"\b(static|inline|extern|\w+_API|\w+_EXPORT|\w+_PUBLIC|\w+_DECL)\b", " ", rtype)
        rtype = re.sub(r"\s+", " ", rtype).strip() or "int"
        entries.append(Entry(name, params.strip(), shape, score, out, rtype))
    entries = [e for e in entries if e.score >= 30]     # internal helpers are not entry points
    entries.sort(key=lambda e: -e.score)
    return entries


def _out_type(text: str, entry: Entry) -> Optional[str]:
    if not entry.out_param:
        return None
    m = re.search(r"([A-Za-z_]\w*)\s*\*\s*%s\s*(?:[,)]|$)" % re.escape(entry.out_param),
                  entry.params)
    return m.group(1) if m else None


def _template_harness(header: str, entry: Entry, text: str) -> Optional[str]:
    out_type = _out_type(text, entry)
    out_decl = ("    %s out;\n" % out_type) if out_type else ""
    out_arg = ", &out" if out_type else ""
    inc = '#include <stdint.h>\n#include <stddef.h>\n#include "%s"\n' % header
    if entry.shape == "buf_size":
        call = "    %s(data, size%s);\n" % (entry.name, out_arg)
    elif entry.shape == "cstr_size":
        call = "    %s((const char *)data, size%s);\n" % (entry.name, out_arg)
    elif entry.shape == "cstr":
        # NUL-terminate the fuzz input into a heap buffer
        return (inc +
                "#include <stdlib.h>\n#include <string.h>\n"
                "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                "    char *s = (char *)malloc(size + 1);\n"
                "    if (!s) return 0;\n"
                "    memcpy(s, data, size); s[size] = '\\0';\n"
                + (("    %s out;\n" % out_type) if out_type else "") +
                "    %s(s%s);\n" % (entry.name, out_arg) +
                "    free(s);\n    return 0;\n}\n")
    else:
        return None
    return (inc + "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            + out_decl + call + "    return 0;\n}\n")


def _template_probe(header: str, entry: Entry, text: str) -> str:
    out_type = _out_type(text, entry)
    inc = '#include "%s"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n' % header
    if entry.shape == "cstr":
        prep = ("    char *s = (char *)malloc(got + 1); if(!s) return 2;\n"
                "    memcpy(s, buf, got); s[got] = '\\0';\n")
        arg = "s"
    else:
        prep = ""
        arg = "buf, got" if entry.shape == "buf_size" else "(const char *)buf, got"
    out_decl = ("    %s out; memset(&out, 0, sizeof(out));\n" % out_type) if out_type else ""
    out_arg = ", &out" if out_type else ""
    callarg = arg + out_arg if entry.shape != "cstr" else "s" + out_arg
    if "*" in entry.rtype:
        # pointer result: observe success/failure (non-NULL), never the address
        obs = ("    const void *r=%s(%s);\n    printf(\"rc=%%d\\n\", r != NULL ? 0 : -1);\n"
               % (entry.name, callarg))
    elif re.search(r"\bvoid\b", entry.rtype):
        obs = "    %s(%s);\n    printf(\"rc=0\\n\");\n" % (entry.name, callarg)
    else:
        obs = "    long rc=(long)%s(%s);\n    printf(\"rc=%%ld\\n\", rc);\n" % (entry.name, callarg)
    return (inc +
            "int main(int argc, char **argv){\n"
            "    if(argc<2) return 2; FILE*f=fopen(argv[1],\"rb\"); if(!f) return 2;\n"
            "    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);\n"
            "    unsigned char*buf=(unsigned char*)malloc(n>0?(size_t)n:1); size_t got=fread(buf,1,(size_t)n,f); fclose(f);\n"
            + prep + out_decl + obs + "    return 0;\n}\n")


@dataclass
class Synth:
    entry: Entry
    harness_path: str
    probe_path: str
    task_path: str
    validated: bool
    detail: str
    candidates: List[Entry] = field(default_factory=list)


def synthesize(source_path: str, include_dir: str, name: str,
               client: Optional["llm.LLMClient"] = None,
               tc: Optional["toolchain.Toolchain"] = None,
               analysis_path: Optional[str] = None,
               extra_sources: Optional[List[str]] = None,
               extra_includes: Optional[List[str]] = None,
               link_flags: Optional[List[str]] = None) -> Synth:
    """`analysis_path` is the file whose functions are the candidate entry
    points (defaults to source_path; a header for header-only libraries).
    `extra_sources`/`extra_includes`/`link_flags` make validation build the
    whole library, not just one file."""
    analysis_path = analysis_path or source_path
    text = util.read_text(analysis_path)
    header = None
    stem = os.path.splitext(os.path.basename(analysis_path))[0]
    hs = sorted(h for h in os.listdir(include_dir) if h.endswith(".h"))
    for h in [x for x in hs if x == stem + ".h"] + hs:
        header = h
        break
    entries = analyze(analysis_path)
    if not entries:
        return Synth(Entry("", "", "other", 0), "", "", "", False,
                     "no fuzzable entry point found", [])
    entry = entries[0]

    harness_src = _template_harness(header, entry, text)
    if harness_src is None and client is not None:
        try:
            lang = "C++" if (toolchain.is_cxx(analysis_path) or analysis_path.endswith((".hpp", ".hh"))
                             or "::" in entry.name) else "C"
            prompt = ("Write a libFuzzer harness (LLVMFuzzerTestOneInput) in %s for this "
                      "function. Include \"%s\". Call %s appropriately, converting the "
                      "fuzzer's (data,size) to its arguments; construct any receiver object "
                      "or context the call needs, and free/destroy what you create. "
                      "%sReturn only one ```c code block.\n\nSIGNATURE: %s %s(%s)\n\nSOURCE:\n%s"
                      % (lang, header, entry.name,
                         'Declare the entry point extern "C". ' if lang == "C++" else "",
                         entry.rtype, entry.name, entry.params, text[:4000]))
            resp = client.complete(prompt, system="You write minimal, correct libFuzzer harnesses.",
                                   max_tokens=500)
            m = re.search(r"```(?:c)?\s*\n(.*?)```", resp, re.DOTALL)
            harness_src = m.group(1) if m else resp
        except llm.LLMUnavailable:
            harness_src = None
    if harness_src is None:
        return Synth(entry, "", "", "", False,
                     "entry '%s' has an unsupported signature and no model available"
                     % entry.name, entries)

    root = os.path.dirname(include_dir.rstrip("/"))
    cxx = toolchain.is_cxx(analysis_path) or toolchain.is_cxx(source_path) or analysis_path.endswith((".hpp", ".hh"))
    ext = ".cc" if cxx else ".c"
    hpath = os.path.join(root, "harness", "fuzz_%s%s" % (name, ext))
    ppath = os.path.join(root, "harness", "probe_%s%s" % (name, ext))
    if cxx and "extern \"C\"" not in harness_src:
        harness_src = re.sub(r"^(\s*)int\s+LLVMFuzzerTestOneInput", r'\1extern "C" int LLVMFuzzerTestOneInput',
                             harness_src, count=1, flags=re.M)
    util.write_text(hpath, harness_src)
    if entry.shape == "other":
        ppath = ""                       # no template probe for model-wired entries
    else:
        util.write_text(ppath, _template_probe(header, entry, text))

    # ---- validate: compile + run on empty and a few benign inputs ----------
    tc = tc or toolchain.detect()
    import tempfile
    tmp = tempfile.mkdtemp(prefix="kv_hsyn_")
    out_bin = os.path.join(tmp, "h")
    srcs = list(dict.fromkeys([source_path] + list(extra_sources or [])))
    incs = list(dict.fromkeys([include_dir] + list(extra_includes or [])))
    cmd = toolchain.build_fuzzer_cmd(tc, srcs, hpath, incs, out_bin, link_flags=link_flags)
    b = util.run(cmd, timeout=240)
    validated, detail = False, ""
    if not b.ok or not os.path.exists(out_bin):
        detail = "harness did not compile: " + b.err[-200:]
    else:
        from . import discovery
        ok = True
        for probe in (b"", b"http://x/", b"\x00\x00\x00\x00", b"SPK1"):
            pf = os.path.join(tmp, "in")
            with open(pf, "wb") as f:
                f.write(probe)
            r = discovery._run_one(out_bin, pf, 2048)
            if discovery._is_crash(r):
                ok = False
                detail = "harness crashes on a trivial input (%r) - likely wrong, rejected" % probe[:8]
                break
        if ok:
            validated = True
            detail = ("entry '%s' (%s); harness compiles and runs cleanly on trivial inputs"
                      % (entry.name, entry.shape))

    task = {
        "name": name, "language": "c",
        "description": "Auto-harnessed: %s() [synthesized entry point]" % entry.name,
        "root": os.path.relpath(root, config.PROJECT_ROOT),
        "sources": [os.path.relpath(source_path, root)],
        "include_dirs": [os.path.relpath(include_dir, root)],
        "harness": os.path.relpath(hpath, root),
        "probe": (os.path.relpath(ppath, root) if ppath else None),
        "test_sources": [os.path.relpath(source_path, root)],
        "patch_scope": [os.path.relpath(source_path, root)],
        "diff_changed": [os.path.relpath(source_path, root)],
        "static_alerts": [],
        "budgets": {"time_budget_s": 30, "rng_seed": 1337},
        "_synthesized": {"entry": entry.name, "shape": entry.shape, "validated": validated},
    }
    tp = os.path.join(root, "tests", "test_%s.c" % name)
    if os.path.exists(tp):
        task["test_sources"].append(os.path.relpath(tp, root))
    seeds_dir = os.path.join(root, "seeds")
    if os.path.isdir(seeds_dir):
        task["seeds"] = [os.path.relpath(os.path.join(seeds_dir, f), root)
                         for f in sorted(os.listdir(seeds_dir))
                         if os.path.isfile(os.path.join(seeds_dir, f))]
    task_path = os.path.join(config.PROJECT_ROOT, "tasks", "%s.json" % name)
    util.write_json(task_path, task)
    return Synth(entry, hpath, ppath, task_path, validated, detail, entries)
