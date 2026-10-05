"""Repair agent: propose a minimal, policy-compliant source patch for a
verified finding.

Order of operations per finding:
  1. Build a tightly-scoped prompt (ASan report + source slice + policy).
  2. Up to N attempts (budget-capped) of: ask the model for a unified diff,
     run static patch-policy checks; if they fail, feed the reason back
     (self-reflection) and retry.
  3. If the model is unavailable or every attempt is rejected, fall back to
     the deterministic heuristic repair brain, which synthesizes a bounds/
     length guard and emits a clean unified diff via difflib.

Only the *static* policy is enforced here; the executable three-gate proof
(build + PoV-blocked + tests) lives in validator.py.
"""
from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import config, llm, util, verifier

FORBIDDEN = [
    (r"-?fsanitize", "must not alter sanitizer flags"),
    (r"_FORTIFY_SOURCE", "must not change fortify level"),
    (r"#\s*pragma\s+GCC\s+diagnostic", "must not suppress diagnostics"),
    (r"\bexit\s*\(", "must not call exit() to mask the fault"),
    (r"/\*\s*VULN", "must not just delete/annotate the vulnerable line"),
]


@dataclass
class PatchResult:
    diff: str
    rel_path: str
    source: str              # "live" | "cache" | "offline-heuristic"
    attempts: int
    rationale: str
    rejected: List[str]      # reasons for rejected attempts


# ---------------------------------------------------------------------------
# Static patch policy
# ---------------------------------------------------------------------------
def touched_files(diff: str) -> List[str]:
    files = []
    for m in re.finditer(r"^\+\+\+\s+b/(\S+)", diff, re.MULTILINE):
        files.append(m.group(1))
    if not files:
        for m in re.finditer(r"^\+\+\+\s+(\S+)", diff, re.MULTILINE):
            files.append(m.group(1).lstrip("b/"))
    return files


def check_policy(task: "config.Task", diff: str) -> Optional[str]:
    if not diff.strip():
        return "empty patch"
    if "@@" not in diff:
        return "not a unified diff (no @@ hunk header)"

    scope_rel = {config.rel_to_root(task, p) for p in task.patch_scope}
    for f in touched_files(diff):
        if f not in scope_rel:
            return ("patch touches out-of-scope file %r; only %s may be edited"
                    % (f, sorted(scope_rel)))

    added = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    added_text = "\n".join(added)

    for pat, why in FORBIDDEN:
        if re.search(pat, added_text):
            return "policy violation: %s" % why

    # Must add a guard (comparison or clamp), not merely remove the sink.
    has_guard = bool(re.search(r"\bif\s*\(.*[<>]=?.*\)", added_text)) or \
        bool(re.search(r"=\s*\w+\s*>\s*\w+\s*\?", added_text))
    if removed and not added:
        return "patch only removes code; a guard/validation must be added"
    if not has_guard:
        return ("patch must add a bounds/length guard (an if-check comparing the "
                "attacker-controlled size against the buffer capacity)")
    if len(added) > 30:
        return "patch is not minimal (%d added lines); keep it localized" % len(added)
    return None


# ---------------------------------------------------------------------------
# Heuristic repair brain (deterministic, offline)
# ---------------------------------------------------------------------------
def _find_source(task: "config.Task", finding: "verifier.Finding") -> Optional[str]:
    base = finding.crash_file.split(":")[0]
    for p in task.patch_scope:
        if os.path.basename(p) == base:
            return p
    return task.patch_scope[0] if task.patch_scope else None


def _function_bounds(text: str, line_no: int) -> Tuple[int, int]:
    """Return (start_idx, end_idx) char offsets of the TOP-LEVEL function
    body containing the 1-based line_no. Tracks brace depth from 0 so inner
    blocks (loops, structs) are not mistaken for the function."""
    lines = text.splitlines(keepends=True)
    pos = sum(len(l) for l in lines[:max(0, line_no - 1)])
    depth = 0
    func_open = 0
    for j, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                func_open = j
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and func_open <= pos <= j:
                return func_open, j
    return 0, len(text)


def _pick_error_return(text: str) -> str:
    m = re.search(r"return\s+(\w*ERR\w*)\s*;", text)
    if m:
        return "return %s;" % m.group(1)
    return "return -1;"


def _macro_value_name(text: str, hint_tokens) -> Optional[str]:
    for tok in hint_tokens:
        if re.search(r"#\s*define\s+%s\b" % re.escape(tok), text):
            return tok
    m = re.search(r"#\s*define\s+(\w*(?:MAX|CAP|SIZE)\w*)\s+\d+", text)
    return m.group(1) if m else None


def synth_patch(task: "config.Task", finding: "verifier.Finding") -> Optional[PatchResult]:
    path = _find_source(task, finding)
    if not path:
        return None
    text = util.read_text(path)
    rel = config.rel_to_root(task, path)
    try:
        line_no = int(finding.crash_file.split(":")[1])
    except (IndexError, ValueError):
        line_no = 1
    fstart, fend = _function_bounds(text, line_no)
    body = text[fstart:fend]
    err_ret = _pick_error_return(text)
    lines = text.splitlines(keepends=True)
    lo = text[:fstart].count("\n")          # 0-based first line of function
    hi = text[:fend].count("\n")            # 0-based last line of function
    insert_at = None      # 0-based line index to insert BEFORE
    guard = None

    # Strategy B: unchecked memcpy length
    mm = re.search(r"memcpy\s*\(\s*([^,]+),\s*[^,]+,\s*([^)]+)\)", body)
    if mm:
        dst, length = mm.group(1).strip(), mm.group(2).strip()
        # capacity: array field decl "... name[CAP];" for the dst field name
        field = dst.split("->")[-1].split(".")[-1].strip()
        fm = re.search(r"\b%s\s*\[\s*(\w+)\s*\]" % re.escape(field), text)
        capname = fm.group(1) if fm else (_macro_value_name(text, []) or "sizeof(%s)" % dst)
        # cleanup (free) if the function allocates
        free_m = re.search(r"free\s*\(\s*(\w+)\s*\)", body)
        cleanup = ("free(%s); " % free_m.group(1)) if free_m else ""
        for i in range(lo, min(hi + 1, len(lines))):
            if "memcpy(" in lines[i]:
                insert_at = i
                indent = re.match(r"\s*", lines[i]).group(0)
                guard = ("%sif (%s > %s) { %s%s }\n"
                         % (indent, length, capname, cleanup, err_ret))
                break

    # Strategy A: loop writing fixed array indexed by attacker count
    if insert_at is None:
        lm = re.search(r"for\s*\(\s*\w[\w\s]*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;", body)
        if lm:
            count = lm.group(1)
            dm = (re.search(r"\[\s*([A-Z_][A-Z0-9_]*)\s*\]", body)
                  or re.search(r"\[\s*(\d+)\s*\]", body))
            capname = dm.group(1) if dm else (_macro_value_name(text, []) or "16")
            for i in range(lo, min(hi + 1, len(lines))):
                if re.search(r"for\s*\(.*<\s*%s\s*;" % re.escape(count), lines[i]):
                    insert_at = i
                    indent = re.match(r"\s*", lines[i]).group(0)
                    guard = ("%sif (%s > %s) %s\n"
                             % (indent, count, capname, err_ret))
                    break

    if insert_at is None or guard is None:
        return None

    patched = lines[:insert_at] + [guard] + lines[insert_at:]
    diff = "".join(difflib.unified_diff(
        lines, patched, fromfile="a/" + rel, tofile="b/" + rel, n=3))
    rationale = ("Insert a guard that rejects inputs whose attacker-controlled "
                 "size exceeds the fixed buffer capacity, at the root cause in "
                 "%s, before the out-of-bounds write." % rel)
    return PatchResult(diff=diff, rel_path=rel, source="offline-heuristic",
                       attempts=1, rationale=rationale, rejected=[])


def fstart_line(text: str, char_off: int) -> int:
    return text[:char_off].count("\n") + 1


# ---------------------------------------------------------------------------
# LLM repair with self-reflection
# ---------------------------------------------------------------------------
PATCH_SYSTEM = (
    "You are a security patch engineer. You fix the ROOT CAUSE of memory-safety "
    "bugs with minimal, readable changes and never hide a fault. You only edit "
    "the allowed source file(s), never tests or the fuzz harness, and never "
    "change build or sanitizer flags.")


def _source_slice(task: "config.Task", finding: "verifier.Finding") -> str:
    path = _find_source(task, finding)
    if not path:
        return ""
    return util.read_text(path)


def _prompt(task, finding, rel, prior_reason: Optional[str]) -> str:
    src = _source_slice(task, finding)
    reflect = ""
    if prior_reason:
        reflect = ("\nYour previous patch was REJECTED: %s\nProduce a corrected "
                   "patch that fixes this.\n" % prior_reason)
    return (
        "A verified %s (%s) was found.\n"
        "Crash site: %s in %s   | sanitizer access: %s\n\n"
        "=== SANITIZER REPORT ===\n%s\n\n"
        "=== SOURCE FILE a/%s (the ONLY file you may edit) ===\n%s\n\n"
        "Patch policy: edit only a/%s; add a bounds/length check at the root "
        "cause; prefer input validation / checked lengths; do not remove "
        "functionality, suppress errors, or touch tests/harness/flags; keep it "
        "minimal.%s\n"
        "Respond with ONLY a unified diff using headers exactly 'a/%s' and "
        "'b/%s' (git-style, 3 lines of context)."
        % (finding.cwe_name, finding.cwe, finding.crash_file, finding.crash_func,
           finding.access, finding.asan_report, rel, src, rel, reflect, rel, rel))


def _extract_diff(text: str) -> str:
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.DOTALL)
    body = m.group(1) if m else text
    # keep from the first diff/--- marker
    idx = body.find("--- ")
    if idx < 0:
        idx = body.find("diff --git")
    return body[idx:].strip() + "\n" if idx >= 0 else body.strip() + "\n"


def propose(task: "config.Task", finding: "verifier.Finding",
            client: "llm.LLMClient", attempts: int = 2) -> Optional[PatchResult]:
    rel = config.rel_to_root(task, _find_source(task, finding) or finding.crash_file)
    rejected: List[str] = []
    reason = None
    for attempt in range(1, attempts + 1):
        try:
            text = client.complete(_prompt(task, finding, rel, reason),
                                   system=PATCH_SYSTEM, max_tokens=1200)
        except llm.LLMUnavailable:
            break
        diff = _extract_diff(text)
        why = check_policy(task, diff)
        if why is None:
            return PatchResult(diff=diff, rel_path=rel, source=client.last_source,
                               attempts=attempt, rejected=rejected,
                               rationale="LLM-proposed minimal guard at root cause.")
        rejected.append("attempt %d: %s" % (attempt, why))
        reason = why

    # Deterministic fallback so a verified fix is always attempted.
    h = synth_patch(task, finding)
    if h:
        h.rejected = rejected
        h.attempts = (attempts if rejected else 0) + 1
        return h
    return None
