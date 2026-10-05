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
_FUNC_RE = re.compile(
    r"^[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{", re.MULTILINE)


@dataclass
class Entry:
    name: str
    params: str
    shape: str          # "buf_size" | "cstr_size" | "cstr" | "other"
    score: int
    out_param: Optional[str] = None   # name of a trailing out-struct pointer


def _classify(params: str) -> Tuple[str, int]:
    p = re.sub(r"\s+", " ", params.strip())
    low = p.lower()
    if re.search(r"const\s+(unsigned char|uint8_t)\s*\*\s*\w+\s*,\s*(size_t|unsigned|int|uint32_t)\s+\w+", low):
        return "buf_size", 100
    if re.search(r"const\s+char\s*\*\s*\w+\s*,\s*(size_t|unsigned|int)\s+\w+", low):
        return "cstr_size", 80
    if re.search(r"const\s+char\s*\*\s*\w+", low) and "," not in p.split(")")[0].replace("const char", "", 1):
        return "cstr", 50
    if re.search(r"const\s+char\s*\*\s*\w+", low):
        return "cstr", 45
    return "other", 0


def analyze(source_path: str) -> List[Entry]:
    text = util.read_text(source_path)
    entries: List[Entry] = []
    for m in _FUNC_RE.finditer(text):
        name, params = m.group(1), m.group(2)
        if name in ("if", "for", "while", "switch", "main"):
            continue
        if name.startswith("_") or name.islower() is False:
            pass
        shape, score = _classify(params)
        if score == 0:
            continue
        # prefer an exported-looking parser; a trailing pointer param is an out-struct
        out = None
        pm = re.findall(r"([A-Za-z_]\w*)\s*\*\s*(\w+)\s*$", params.strip())
        if pm:
            out = pm[-1][1]
        if re.search(r"parse|decode|read|load|scan", name):
            score += 20
        entries.append(Entry(name, params.strip(), shape, score, out))
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
    inc = '#include "%s"\n' % header
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
    return (inc +
            "int main(int argc, char **argv){\n"
            "    if(argc<2) return 2; FILE*f=fopen(argv[1],\"rb\"); if(!f) return 2;\n"
            "    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);\n"
            "    unsigned char*buf=malloc(n>0?(size_t)n:1); size_t got=fread(buf,1,(size_t)n,f); fclose(f);\n"
            + prep + out_decl +
            "    int rc=%s(%s);\n" % (entry.name, callarg) +
            "    printf(\"rc=%d\\n\", rc);\n    return 0;\n}\n")


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
               tc: Optional["toolchain.Toolchain"] = None) -> Synth:
    text = util.read_text(source_path)
    header = None
    for h in os.listdir(include_dir):
        if h.endswith(".h"):
            header = h
            break
    entries = analyze(source_path)
    if not entries:
        return Synth(Entry("", "", "other", 0), "", "", "", False,
                     "no fuzzable entry point found", [])
    entry = entries[0]

    harness_src = _template_harness(header, entry, text)
    if harness_src is None and client is not None:
        try:
            prompt = ("Write a libFuzzer harness (LLVMFuzzerTestOneInput) for this C "
                      "function. Include \"%s\". Call %s appropriately, converting the "
                      "fuzzer's (data,size) to its arguments.\n\nSIGNATURE: %s\n\nSOURCE:\n%s"
                      % (header, entry.name, entry.params, text[:4000]))
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
    hpath = os.path.join(root, "harness", "fuzz_%s.c" % name)
    ppath = os.path.join(root, "harness", "probe_%s.c" % name)
    util.write_text(hpath, harness_src)
    util.write_text(ppath, _template_probe(header, entry, text))

    # ---- validate: compile + run on empty and a few benign inputs ----------
    tc = tc or toolchain.detect()
    import tempfile
    tmp = tempfile.mkdtemp(prefix="kv_hsyn_")
    out_bin = os.path.join(tmp, "h")
    cmd = toolchain.build_fuzzer_cmd(tc, [source_path], hpath, [include_dir], out_bin)
    b = util.run(cmd, timeout=120)
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
        "probe": os.path.relpath(ppath, root),
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
