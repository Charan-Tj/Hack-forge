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
    label: str = "patch"     # short strategy name for the ensemble table
    strategy: str = ""       # "use-site" | "root-cause" | "clamp" | "llm"
    guard_line: int = 0      # 1-based line in the patched file where the guard sits
    root_cause_line: int = 0 # where the untrusted value is first assigned
    distance: int = 0        # |guard_line - root_cause_line|
    added_lines: int = 0


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
        bool(re.search(r"=\s*\w+\s*>\s*\w+\s*\?", added_text)) or \
        bool(re.search(r"alloc\s*\(.*\+\s*1\b", added_text))   # allocation enlarged
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


def _pick_error_return(text: str, body: str = "", header: str = "") -> str:
    """The statement a guard uses to bail out. Prefer what the function itself
    already does on error (a cleanup label, an error enum it returns), then
    fall back on the return type: pointer -> NULL, void -> bare return,
    bool -> false, anything else -> -1. Wrong-typed bail-outs are what make a
    heuristic patch fail to rebuild on unfamiliar code."""
    lm = re.search(r"^\s*(error|err|fail|failure|cleanup|out|bail|done)\s*:\s*$", body, re.M)
    if lm:
        return "goto %s;" % lm.group(1)
    for scope in (body, text):
        m = re.search(r"return\s+(\w*(?:ERR|FAIL|INVALID|ERROR)\w*)\s*;", scope)
        if m:
            return "return %s;" % m.group(1)
    sig = re.search(r"([A-Za-z_][\w\s\*\(\)]*?)\b[A-Za-z_]\w*\s*\([^;{}]*\)\s*$", header.strip())
    rtype = (sig.group(1) if sig else "").strip()
    if "*" in rtype:
        return "return NULL;"
    if re.search(r"\bvoid\s*$", rtype):
        return "return;"
    if re.search(r"\b(bool|_Bool)\b", rtype):
        return "return false;"
    if re.search(r"\bsize_t\b|\bunsigned\b|\buint\d+_t\b", rtype):
        return "return 0;"
    return "return -1;"


def _macro_value_name(text: str, hint_tokens) -> Optional[str]:
    for tok in hint_tokens:
        if re.search(r"#\s*define\s+%s\b" % re.escape(tok), text):
            return tok
    m = re.search(r"#\s*define\s+(\w*(?:MAX|CAP|SIZE)\w*)\s+\d+", text)
    return m.group(1) if m else None


def synth_variants(task: "config.Task", finding: "verifier.Finding") -> List[PatchResult]:
    """Deterministic repair brain: emit several candidate patches for the
    ensemble. Each candidate is a one-line guard; they differ in WHERE the
    guard sits (use site vs. where the untrusted value is first assigned) and
    in semantics (reject vs. clamp). The validator + ranker decide."""
    path = _find_source(task, finding)
    if not path:
        return []
    text = util.read_text(path)
    rel = config.rel_to_root(task, path)
    try:
        line_no = int(finding.crash_file.split(":")[1])
    except (IndexError, ValueError):
        line_no = 1
    fstart, fend = _function_bounds(text, line_no)
    body = text[fstart:fend]
    header = text[max(0, text.rfind("\n", 0, text.rfind("\n", 0, fstart))):fstart]
    err_ret = _pick_error_return(text, body, header)
    lines = text.splitlines(keepends=True)
    lo = text[:fstart].count("\n")
    hi = text[:fend].count("\n")
    out: List[PatchResult] = []

    def indent_of(i):
        return re.match(r"\s*", lines[i]).group(0)

    # ---- Strategy C: out-of-bounds READ of the input buffer --------------
    if (finding.access or "").lower().startswith("read") and 0 < line_no <= len(lines):
        header = text[max(0, text.rfind("\n", 0, fstart) - 400):fstart]
        sig = re.search(r"\(\s*const\s+(?:unsigned\s+char|uint8_t|char)\s*\*\s*(\w+)\s*,"
                        r"\s*(?:size_t|unsigned|int|uint32_t)\s+(\w+)", header)
        crash_line = lines[line_no - 1]
        if sig:
            buf, size_name = sig.group(1), sig.group(2)
            am = re.search(r"\b%s\s*\[\s*([^\]]+?)\s*\]" % re.escape(buf), crash_line)
            if am:
                idx_expr = am.group(1).strip()
                ind = indent_of(line_no - 1)
                in_loop = False
                for j in range(line_no - 2, lo - 1, -1):
                    ind_j = len(indent_of(j))
                    if ind_j < len(ind) and re.search(r"\b(for|while)\s*\(", lines[j]):
                        in_loop = True
                        break
                    if ind_j < len(ind) and re.search(r"^\s*\}", lines[j]):
                        break
                root = _first_assignment_line(lines, lo, hi, idx_expr) or line_no
                g1 = "%sif (%s >= %s) %s\n" % (ind, idx_expr, size_name,
                                                 "break;" if in_loop else err_ret)
                out.append(_make_result(lines, rel, line_no - 1, g1, "bound read at use site",
                                        "use-site", root,
                                        "Bound the input-buffer index by the available size "
                                        "immediately before the out-of-bounds read."))
                return out

    # ---- Strategy D: heap WRITE one past a buffer this function allocated --
    # (the classic missing "+ 1" for a terminator). Enlarge the allocation at
    # its root cause rather than guarding the write.
    if (finding.access or "").lower().startswith("write") and 0 < line_no <= len(lines) \
            and "heap" in (finding.asan_class or ""):
        crash_line = lines[line_no - 1]
        wm = re.search(r"^\s*\*?\s*([A-Za-z_]\w*)(?:\s*\[[^\]]*\]|\s*\+\+)?\s*=[^=]", crash_line)
        for i in range(lo, min(hi + 1, len(lines))):
            am = re.search(r"\b(\w*alloc)\s*\((.+)\)\s*;", lines[i])
            if not am or re.search(r"\+\s*1\b", am.group(2)):
                continue
            # the allocated pointer must be what the crash line writes through
            lhs = re.match(r"\s*(?:\w+\s*=\s*)?(?:\([^)]*\)\s*)?", lines[i])
            target = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?\w*alloc\s*\(", lines[i])
            tname = target.group(1) if target else ""
            if wm and tname and tname != wm.group(1) and not re.search(r"\b%s\b" % re.escape(tname), body[body.find(wm.group(1)):][:200] if wm.group(1) in body else ""):
                # the write goes through a different pointer; accept only if it
                # was derived from this allocation (ptr = buf;)
                if not re.search(r"\b%s\s*=\s*%s\s*;" % (re.escape(wm.group(1)), re.escape(tname)), body):
                    continue
            new_line = lines[i].replace(am.group(0), "%s((%s) + 1);" % (am.group(1), am.group(2).strip()), 1)
            patched = lines[:i] + [new_line] + lines[i + 1:]
            diff = "".join(difflib.unified_diff(lines, patched, fromfile="a/" + rel, tofile="b/" + rel, n=3))
            out.append(PatchResult(diff=diff, rel_path=rel, source="offline-heuristic", attempts=1,
                                   rationale="The function writes one element past the buffer it allocates "
                                             "(a terminator or sentinel); size the allocation for it.",
                                   rejected=[], label="allocate room for terminator", strategy="root-cause",
                                   guard_line=i + 1, root_cause_line=i + 1, distance=0, added_lines=1))
            break

    # ---- Strategy B: unchecked memcpy length ------------------------------
    mm = re.search(r"memcpy\s*\(\s*([^,]+),\s*[^,]+,\s*([^)]+)\)", body)
    if mm:
        dst, length = mm.group(1).strip(), mm.group(2).strip()
        field = dst.split("->")[-1].split(".")[-1].strip()
        # capacity = a DECLARATION "field[CAP]" where CAP is a macro or integer
        # literal (never a lowercase index variable such as the length itself).
        fm = re.search(r"\b%s\s*\[\s*([A-Z_][A-Z0-9_]*|\d+)\s*\]" % re.escape(field), text)
        capname = fm.group(1) if fm else None
        if capname is None and re.search(r"\b%s\s*\[" % re.escape(field), text):
            capname = "sizeof(%s)" % dst
    if mm and capname is None:
        mm = None            # no fixed-capacity destination: guessing a macro would be noise
    if mm:
        # if the buffer is also written at [length] (a null terminator), the
        # safe bound is >= capacity, not > capacity.
        term = bool(re.search(r"\b%s\s*\[\s*%s\s*\]\s*=" % (re.escape(field), re.escape(length)), body))
        op = ">=" if term else ">"
        free_m = re.search(r"free\s*\(\s*(\w+)\s*\)", body)
        cleanup = ("free(%s); " % free_m.group(1)) if (free_m and not err_ret.startswith("goto")) else ""
        use_i = next((i for i in range(lo, min(hi + 1, len(lines))) if "memcpy(" in lines[i]), None)
        root = _first_assignment_line(lines, lo, hi, length)
        if use_i is not None:
            g = "%sif (%s %s %s) { %s%s }\n" % (indent_of(use_i), length, op, capname, cleanup, err_ret)
            out.append(_make_result(lines, rel, use_i, g, "length check at copy site", "use-site",
                                    root, "Reject records whose declared length exceeds the "
                                    "fixed field capacity, immediately before the copy."))
            if root and root - 1 != use_i and lo <= root - 1 <= hi:
                ins = root
                g2 = "%sif (%s %s %s) { %s%s }\n" % (indent_of(root - 1), length, op, capname, cleanup, err_ret)
                out.append(_make_result(lines, rel, ins, g2, "length check where length is read",
                                        "root-cause", root,
                                        "Validate the declared length at the point it is read "
                                        "from the input, before any use."))
            return out

    # ---- Strategy A: loop writing a fixed array indexed by an input count --
    lm = re.search(r"for\s*\(\s*\w[\w\s]*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;", body)
    if lm:
        count = lm.group(1)
        dm = (re.search(r"\[\s*([A-Z_][A-Z0-9_]*)\s*\]", body)
              or re.search(r"\[\s*(\d+)\s*\]", body))
        capname = dm.group(1) if dm else None
    if lm and capname is None:
        lm = None
    if lm:
        loop_i = next((i for i in range(lo, min(hi + 1, len(lines)))
                       if re.search(r"for\s*\(.*<\s*%s\s*;" % re.escape(count), lines[i])), None)
        root = _first_assignment_line(lines, lo, hi, count)
        if loop_i is not None:
            out.append(_make_result(lines, rel, loop_i,
                                    "%sif (%s > %s) %s\n" % (indent_of(loop_i), count, capname, err_ret),
                                    "count check before loop", "use-site", root,
                                    "Reject inputs whose declared count exceeds the fixed "
                                    "table capacity, immediately before the decode loop."))
            if root and lo <= root - 1 <= hi and root - 1 != loop_i:
                out.append(_make_result(lines, rel, root,
                                        "%sif (%s > %s) %s\n" % (indent_of(root - 1), count, capname, err_ret),
                                        "count check where count is read", "root-cause", root,
                                        "Validate the declared count at the point it is read "
                                        "from the header, before any use."))
                out.append(_make_result(lines, rel, root,
                                        "%sif (%s > %s) %s = %s;\n" % (indent_of(root - 1), count, capname, count, capname),
                                        "clamp count to capacity", "clamp", root,
                                        "Clamp the declared count to the table capacity "
                                        "(silently truncates oversized inputs)."))
    return out


def synth_patch(task: "config.Task", finding: "verifier.Finding") -> Optional[PatchResult]:
    """Single best-guess heuristic patch (use-site guard); kept for callers
    and tests that want one candidate."""
    v = synth_variants(task, finding)
    return v[0] if v else None


def fstart_line(text: str, char_off: int) -> int:
    return text[:char_off].count("\n") + 1


def _first_assignment_line(lines: List[str], lo: int, hi: int, var: str) -> int:
    """1-based line where `var` (e.g. n_channels, rec->length, idx) is first
    assigned inside the function spanning lines lo..hi (0-based)."""
    v = re.escape(var.split("->")[-1].split(".")[-1])
    pat = re.compile(r"(^|[^\w])%s\s*=[^=]" % v)
    for i in range(lo, min(hi + 1, len(lines))):
        if pat.search(lines[i]):
            return i + 1
    return 0


def _make_result(lines, rel, insert_at, guard, label, strategy, root_line,
                 rationale) -> PatchResult:
    patched = lines[:insert_at] + [guard] + lines[insert_at:]
    diff = "".join(difflib.unified_diff(
        lines, patched, fromfile="a/" + rel, tofile="b/" + rel, n=3))
    gl = insert_at + 1
    return PatchResult(diff=diff, rel_path=rel, source="offline-heuristic",
                       attempts=1, rationale=rationale, rejected=[],
                       label=label, strategy=strategy, guard_line=gl,
                       root_cause_line=root_line or gl, distance=abs(gl - (root_line or gl)),
                       added_lines=1)


def annotate(task: "config.Task", finding: "verifier.Finding", pr: PatchResult) -> PatchResult:
    """Fill guard_line / root_cause_line / distance / added_lines for any
    candidate (e.g. a model-written diff) from its hunk and the source."""
    added = [l[1:] for l in pr.diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    pr.added_lines = len(added)
    m = re.search(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", pr.diff, re.MULTILINE)
    if not m:
        return pr
    start = int(m.group(1))
    # guard line = position of the first added line within the hunk (new side)
    new_line = start
    for l in pr.diff.splitlines():
        if l.startswith("@@"):
            new_line = start
            continue
        if l.startswith("+++") or l.startswith("---"):
            continue
        if l.startswith("+"):
            pr.guard_line = new_line
            break
        if not l.startswith("-"):
            new_line += 1
    # controlling variable = identifier compared in the first added if(...)
    cond = next((a for a in added if re.search(r"\bif\s*\(", a)), "")
    cm = re.search(r"if\s*\(\s*([\w\->\.\[\]]+)\s*[<>]=?", cond)
    path = _find_source(task, finding)
    if cm and path:
        text = util.read_text(path)
        lines = text.splitlines(keepends=True)
        try:
            ln = int(finding.crash_file.split(":")[1])
        except (IndexError, ValueError):
            ln = 1
        fs, fe = _function_bounds(text, ln)
        lo, hi = text[:fs].count("\n"), text[:fe].count("\n")
        pr.root_cause_line = _first_assignment_line(lines, lo, hi, cm.group(1)) or pr.guard_line
        pr.distance = abs(pr.guard_line - pr.root_cause_line)
    return pr


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


def _normalize_report(text: str) -> str:
    """Strip run-specific noise (PIDs, addresses, absolute paths) so identical
    bugs produce identical prompts -> stable cache keys across runs."""
    text = re.sub(r"==\d+==", "==PID==", text)
    text = re.sub(r"0x[0-9a-fA-F]{4,}", "0xADDR", text)
    text = re.sub(r"(/[\w.\-]+)+/(?=[\w.\-]+\.(?:c|h|cc|cpp|inc):\d+)", "", text)
    return text


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
           finding.access, _normalize_report(finding.asan_report), rel, src, rel,
           reflect, rel, rel))


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


# ---------------------------------------------------------------------------
# Ensemble: several candidates from the model + the heuristic brain
# ---------------------------------------------------------------------------
def _ensemble_prompt(task, finding, rel, prior_reason: Optional[str]) -> str:
    base = _prompt(task, finding, rel, prior_reason)
    return base + (
        "\n\nProvide up to 3 ALTERNATIVE patches. For each, write a heading line "
        "exactly '### STRATEGY: <short name>' followed by a fenced unified diff. "
        "Prefer, in order: (1) validate the untrusted value at the point it is read "
        "from the input; (2) a guard immediately before the unsafe use; (3) any "
        "other minimal, behaviour-preserving construction. Each diff must stand alone.")


def _split_strategies(text: str) -> List[Tuple[str, str]]:
    parts = re.split(r"^###\s*STRATEGY:\s*(.+?)\s*$", text, flags=re.MULTILINE)
    out: List[Tuple[str, str]] = []
    if len(parts) >= 3:
        for i in range(1, len(parts) - 1, 2):
            out.append((parts[i].strip()[:40], _extract_diff(parts[i + 1])))
    else:
        out.append(("model patch", _extract_diff(text)))
    return [(n, d) for n, d in out if d.strip()]


def propose_ensemble(task: "config.Task", finding: "verifier.Finding",
                     client: "llm.LLMClient", attempts: int = 2,
                     max_candidates: int = 5) -> List[PatchResult]:
    """Collect candidate patches: model strategies (1 call, + 1 reflection
    call if none passed policy) and the heuristic brain's variants."""
    rel = config.rel_to_root(task, _find_source(task, finding) or finding.crash_file)
    cands: List[PatchResult] = []
    rejected: List[str] = []
    reason = None
    for attempt in range(1, attempts + 1):
        try:
            text = client.complete(_ensemble_prompt(task, finding, rel, reason),
                                   system=PATCH_SYSTEM, max_tokens=2000)
        except llm.LLMUnavailable:
            break
        got_valid = False
        for name, diff in _split_strategies(text):
            why = check_policy(task, diff)
            if why is None:
                pr = PatchResult(diff=diff, rel_path=rel, source=client.last_source,
                                 attempts=attempt, rejected=list(rejected),
                                 rationale="Model-proposed: %s" % name,
                                 label="LLM: " + name, strategy="llm")
                cands.append(annotate(task, finding, pr))
                got_valid = True
            else:
                rejected.append("attempt %d [%s]: %s" % (attempt, name, why))
        if got_valid:
            break
        reason = "; ".join(rejected[-3:])
    seen = {c.diff for c in cands}
    for v in synth_variants(task, finding):
        if v.diff not in seen:
            v.rejected = list(rejected) if not cands else []
            cands.append(v)
            seen.add(v.diff)
    return cands[:max_candidates]


STRATEGY_PENALTY = {"clamp": 1}   # silently altering data ranks below an explicit reject


def rank_key(pr: PatchResult, verified: bool):
    return (0 if verified else 1, pr.distance, STRATEGY_PENALTY.get(pr.strategy, 0),
            pr.added_lines, 0 if pr.strategy == "llm" else 1)
