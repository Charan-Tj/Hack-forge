"""Ingestion of real-world signals that feed the risk prioritizer:

  * unified diffs (a .diff/.patch file, or a live ``git diff`` of the target)
  * SARIF 2.1.0 static-analysis results (CodeQL, Semgrep, clang-tidy, ...)

Both are reduced to the two inputs the risk ledger consumes: a set of
changed files (relative to the target root) and a list of static alerts
``{file, line, rule}``.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Set

from . import util

_DIFF_FILE_RE = re.compile(r"^\+\+\+\s+(?:b/)?(\S+)", re.MULTILINE)
_HUNK_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@", re.MULTILINE)


def changed_files_from_diff_text(text: str) -> Dict[str, List[int]]:
    """Map changed file -> list of added/modified line numbers (new side)."""
    out: Dict[str, List[int]] = {}
    cur: Optional[str] = None
    new_line = 0
    for line in text.splitlines():
        m = _DIFF_FILE_RE.match(line)
        if m:
            cur = m.group(1)
            if cur == "/dev/null":
                cur = None
            else:
                out.setdefault(cur, [])
            continue
        h = _HUNK_RE.match(line)
        if h:
            new_line = int(h.group(1))
            continue
        if cur is None or line.startswith("---"):
            continue
        if line.startswith("+"):
            out[cur].append(new_line)
            new_line += 1
        elif line.startswith("-"):
            # a deletion touches the position where the line used to be
            if new_line not in out[cur]:
                out[cur].append(new_line)
        else:
            new_line += 1
    return out


def changed_files_from_diff_file(path: str) -> Dict[str, List[int]]:
    return changed_files_from_diff_text(util.read_text(path))


def changed_files_from_git(root: str) -> Dict[str, List[int]]:
    """Live ``git diff HEAD`` (staged + unstaged) of the target, if it is a
    git repository. Returns {} when not a repo or nothing changed."""
    r = util.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"])
    if not r.ok:
        return {}
    r = util.run(["git", "-C", root, "diff", "HEAD", "--unified=0", "--no-color"])
    if not r.ok:
        return {}
    return changed_files_from_diff_text(r.out)


def changed_files_from_git_range(root: str, base: str) -> Dict[str, List[int]]:
    """Diff of the target between `base` (merge-base with HEAD) and HEAD, with
    paths relative to the target root - what a CI run on a pull request needs."""
    r = util.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"])
    if not r.ok:
        return {}
    r = util.run(["git", "-C", root, "diff", "%s...HEAD" % base, "--relative",
                  "--unified=0", "--no-color", "--", "."])
    if not r.ok or not r.out.strip():
        # fall back to a plain two-dot diff (e.g. shallow clone without merge-base)
        r = util.run(["git", "-C", root, "diff", base, "HEAD", "--relative",
                      "--unified=0", "--no-color", "--", "."])
        if not r.ok:
            return {}
    return changed_files_from_diff_text(r.out)


def alerts_from_sarif(path: str, root: Optional[str] = None) -> List[Dict]:
    """Flatten SARIF results into [{file, line, rule, level}] with file paths
    made relative to `root` when possible."""
    data = json.loads(util.read_text(path))
    alerts: List[Dict] = []
    for run in data.get("runs", []):
        rules = {}
        drv = run.get("tool", {}).get("driver", {})
        for r in drv.get("rules", []):
            rules[r.get("id")] = (r.get("shortDescription", {}) or {}).get("text", "")
        for res in run.get("results", []):
            rid = res.get("ruleId", "rule")
            msg = (res.get("message", {}) or {}).get("text", "") or rules.get(rid, "")
            level = res.get("level", "warning")
            for loc in res.get("locations", []) or [{}]:
                phys = (loc.get("physicalLocation", {}) or {})
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine", 0)
                f = uri.replace("file://", "")
                if root and os.path.isabs(f):
                    try:
                        f = os.path.relpath(f, root)
                    except ValueError:
                        pass
                alerts.append({"file": f, "line": int(line or 0),
                               "rule": ("%s: %s" % (rid, msg)).strip(": "),
                               "level": level})
    return alerts


def summarize_sources(diff_src: str, n_changed: int, sarif_src: str,
                      n_alerts: int) -> str:
    return "diff: %s (%d file(s)) | static alerts: %s (%d)" % (
        diff_src, n_changed, sarif_src, n_alerts)
