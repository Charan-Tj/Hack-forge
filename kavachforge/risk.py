"""Deterministic, explainable risk prioritizer (runs before any LLM call).

Score for each function:
    +4  the function lives in a changed file (from the task's diff)
    +3  the function contains a selected dangerous sink/API
    +2  the function is reachable from a fuzz entry point
    +1  a static-analysis alert references it

This is a *prioritization heuristic*, not a claim of exploitability. Every
component of every score cites the source location / rule that produced it,
so the ledger is fully auditable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

from . import config, util

# Dangerous operation classes -> matching tokens.
SINKS = {
    "copy":       [r"\bmemcpy\b", r"\bmemmove\b", r"\bstrcpy\b", r"\bstrncpy\b",
                   r"\bstrcat\b", r"\bsprintf\b", r"\bgets\b"],
    "alloc":      [r"\bmalloc\b", r"\bcalloc\b", r"\brealloc\b", r"\balloca\b"],
    "index":      [r"\[\s*[a-zA-Z_]\w*\s*\]"],           # array[var]
    "arithmetic": [r"\*\s*\d", r"\+\s*len", r"len\s*\*"],  # size math
    "exec":       [r"\bsystem\b", r"\bexecve?\b", r"\bpopen\b"],
}

_FUNC_RE = re.compile(
    r"^[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.MULTILINE)


@dataclass
class FuncRisk:
    name: str
    file: str            # display path (relative to task root)
    line: int
    score: int = 0
    components: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)


def _functions(src: str):
    """Yield (name, start_index, line_no) for each function definition."""
    for m in _FUNC_RE.finditer(src):
        yield m.group(1), m.start(), src[:m.start()].count("\n") + 1


def _body(src: str, start: int) -> str:
    """Extract a function body by brace matching from its opening '{'."""
    i = src.find("{", start)
    if i < 0:
        return ""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
        j += 1
    return src[i:]


def analyze(task: "config.Task", harness_text: str) -> List[Dict]:
    changed = set(task.diff_changed)
    alerts = task.static_alerts

    # Which functions does the harness call directly (entry reachability)?
    entry_calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", harness_text))

    ranked: List[FuncRisk] = []
    for src_path in task.sources:
        rel = config.rel_to_root(task, src_path)
        src = util.read_text(src_path)
        for name, start, line in _functions(src):
            if name in ("if", "for", "while", "switch", "sizeof", "return"):
                continue
            body = _body(src, start)
            fr = FuncRisk(name=name, file=rel, line=line)

            if rel in changed:
                fr.score += 4
                fr.components.append("+4 in changed file (%s)" % rel)

            found = []
            for cls, pats in SINKS.items():
                for p in pats:
                    if re.search(p, body):
                        found.append(cls)
                        break
            if found:
                fr.score += 3
                fr.sinks = sorted(set(found))
                fr.components.append("+3 dangerous sink(s): %s" % ", ".join(fr.sinks))

            if name in entry_calls:
                fr.score += 2
                fr.components.append("+2 reachable from fuzz entry point")

            hit = [a for a in alerts if a.get("file") == rel]
            if hit:
                fr.score += 1
                rules = "; ".join(a.get("rule", "alert") for a in hit)
                fr.components.append("+1 static alert: %s" % rules)

            if fr.score > 0:
                ranked.append(fr)

    ranked.sort(key=lambda f: (-f.score, f.file, f.line))
    return [{"function": f.name, "file": f.file, "line": f.line,
             "score": f.score, "sinks": f.sinks, "rationale": f.components}
            for f in ranked]
