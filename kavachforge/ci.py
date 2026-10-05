"""CI integration: run KavachForge on the targets a change touched, write a
pull-request-ready summary, emit repo-root patches for any verified fix, and
set the exit code so a CI check can fail on a security regression.

    kavach ci --base origin/main            # typical pull-request run

Outputs (under artifacts/):
    ci-summary.md         markdown for a PR comment / job summary
    ci-result.json        machine-readable outcome
    ci-fix/<task>-<id>.patch   fix + regression test, rebased to the repo root
                               (apply with `git apply` / `patch -p1` at the root)
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from . import config, util
from .pipeline import run_task

TASKS = ["tinyimg", "recordcfg", "cleanjson"]


def _changed_paths(base: str) -> List[str]:
    root = config.PROJECT_ROOT
    for args in (["diff", "--name-only", "%s...HEAD" % base],
                 ["diff", "--name-only", base, "HEAD"]):
        r = util.run(["git", "-C", root] + args)
        if r.ok and r.out.strip():
            return [l.strip() for l in r.out.splitlines() if l.strip()]
    return []


def _targets_for(paths: List[str], tasks: List[str]) -> List[str]:
    hit = []
    for name in tasks:
        try:
            t = config.load_task(name)
        except Exception:
            continue
        rel = os.path.relpath(t.root, config.PROJECT_ROOT).replace(os.sep, "/") + "/"
        if any(p.startswith(rel) for p in paths):
            hit.append(name)
    return hit


def _rebase_patch(diff: str, target_rel: str) -> str:
    """Rewrite a/b paths from target-root-relative to repo-root-relative."""
    out = []
    for line in diff.splitlines(keepends=True):
        for pfx in ("--- a/", "+++ b/", "--- b/", "+++ a/"):
            if line.startswith(pfx):
                line = pfx + target_rel + "/" + line[len(pfx):]
                break
        out.append(line)
    return "".join(out)


def run(base: Optional[str], all_targets: bool, fail_on: str,
        provider: Optional[str] = None, budget: int = 6) -> int:
    base = base or os.environ.get("KAVACH_CI_BASE") or "origin/main"
    changed = _changed_paths(base)
    targets = TASKS if all_targets else (_targets_for(changed, TASKS) or TASKS)
    util.plain(util.bold("\nKavachForge CI — base %s, %d changed path(s), targets: %s"
                         % (base, len(changed), ", ".join(targets))))

    rows: List[Dict] = []
    fixes: List[Dict] = []
    worst = "clean"
    for name in targets:
        try:
            r = run_task(name, provider=provider, budget=budget,
                         diff="git-range:" + base if changed else None)
        except Exception as e:
            rows.append({"target": name, "status": "error", "error": str(e)})
            worst = "error"
            continue
        ev = r["evidence"]
        m = ev["metrics"]
        findings = ev["findings"]
        status = ("clean" if not findings else
                  "fixed" if m["verified_patches"] == len(findings) else "unresolved")
        if status == "unresolved" or (status == "fixed" and worst != "unresolved"):
            worst = status if worst in ("clean", "fixed") else worst
        rows.append({"target": name, "status": status, "findings": len(findings),
                     "verified": m["verified_patches"], "execs": ev["discovery"].get("execs", 0),
                     "first_pov": m["time_to_first_pov"],
                     "details": [{"id": f["id"], "cwe": f["cwe"], "cwe_name": f["cwe_name"],
                                  "severity": f["severity"], "site": f["crash_file"],
                                  "status": f["validation"]["status"],
                                  "gates": f["validation"].get("gates", []),
                                  "pr_md": (f.get("pr_bundle") or {}).get("md")}
                                 for f in findings]})
        t = config.load_task(name)
        target_rel = os.path.relpath(t.root, config.PROJECT_ROOT).replace(os.sep, "/")
        for f in findings:
            pb = f.get("pr_bundle")
            if pb and f["validation"]["status"] == "Verified":
                src = os.path.join("artifacts", name, pb["patch"])
                dst = os.path.join("artifacts", "ci-fix", "%s-%s.patch" % (name, f["id"]))
                util.write_text(dst, _rebase_patch(util.read_text(src), target_rel))
                fixes.append({"target": name, "id": f["id"], "patch": dst,
                              "pr_md": os.path.join("artifacts", name, pb["md"]),
                              "title": "Fix %s %s in %s" % (f["cwe"], f["cwe_name"], f["crash_func"])})

    # ---- summary -----------------------------------------------------------
    icon = {"clean": "✅", "fixed": "\U0001f6e0️", "unresolved": "❌", "error": "⚠️"}
    md = ["## KavachForge security check", "",
          "| target | result | findings | verified patches | fuzz execs | first PoV |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        if r["status"] == "error":
            md.append("| `%s` | %s error | - | - | - | - |" % (r["target"], icon["error"]))
            continue
        md.append("| `%s` | %s %s | %d | %d | %s | %s |" % (
            r["target"], icon[r["status"]], r["status"], r["findings"], r["verified"],
            "{:,}".format(r["execs"]), r["first_pov"]))
    for r in rows:
        for d in r.get("details", []):
            md += ["", "<details><summary><b>%s</b> — %s %s (%s) at <code>%s</code> — %s</summary>"
                   % (d["id"], d["cwe"], d["cwe_name"], d["severity"], d["site"], d["status"]), ""]
            md += ["- [%s] **%s** — %s" % ("x" if g["passed"] else " ", g["name"], g["detail"])
                   for g in d["gates"]]
            md += ["", "</details>"]
    if fixes:
        md += ["", "### Proposed fixes (verified: build + PoV blocked + tests + regression test + behaviour preserved)"]
        for fx in fixes:
            md.append("- `%s` — %s (`%s`)" % (fx["id"], fx["title"], fx["patch"]))
        md.append("\nA fix pull request is opened automatically when the workflow has permission; "
                  "otherwise apply the patch above at the repository root with `patch -p1`.")
    md += ["", "<sub>No finding is reported without a reproducible proof-of-vulnerability; "
           "no patch is marked verified without passing every executable gate. Human review required.</sub>"]
    util.write_text(os.path.join("artifacts", "ci-summary.md"), "\n".join(md) + "\n")
    util.write_json(os.path.join("artifacts", "ci-result.json"),
                    {"base": base, "changed_paths": changed, "targets": rows,
                     "fixes": fixes, "worst": worst})

    util.plain("")
    for r in rows:
        util.info("%-12s %s" % (r["target"], r["status"]))
    util.good("summary: artifacts/ci-summary.md  (%d proposed fix(es))" % len(fixes))

    has_findings = any(r.get("findings", 0) for r in rows)
    has_unresolved = any(r["status"] in ("unresolved", "error") for r in rows)
    if fail_on == "any" and has_findings:
        util.bad("security regression detected — failing the check")
        return 1
    if fail_on == "unverified" and has_unresolved:
        util.bad("unresolved finding — failing the check")
        return 1
    return 0
