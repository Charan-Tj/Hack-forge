"""Task-file loading and path resolution.

A task is a small JSON (or YAML, if PyYAML is present) file describing one
target: its sources, harness, test build, the files a patch may touch, an
optional changed-files list / static alerts, and resource budgets. All paths
in the task are relative to the task's ``root`` directory, which itself is
resolved relative to the project root.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import util

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_raw(path: str) -> dict:
    text = util.read_text(path)
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # optional
            return yaml.safe_load(text)
        except Exception:
            raise RuntimeError("YAML task given but PyYAML not installed; "
                               "convert the task to JSON.")
    import json
    return json.loads(text)


@dataclass
class Task:
    name: str
    language: str
    root: str                       # absolute
    sources: List[str]              # absolute
    harness: str                    # absolute
    include_dirs: List[str]         # absolute
    test_sources: List[str]         # absolute
    patch_scope: List[str]          # absolute
    magic: Optional[str]
    diff_changed: List[str]         # relative-to-root display paths
    static_alerts: List[dict]
    description: str
    seeds: List[str]                # absolute, optional provided seeds
    raw: dict = field(default_factory=dict)
    diff_source: str = "task"       # "task" | "git" | <path to .diff>
    sarif_source: str = ""          # "" | <path to .sarif>
    changed_lines: Dict[str, List[int]] = field(default_factory=dict)
    probe: Optional[str] = None     # absolute path to behaviour probe main, optional
    seed_generator: Optional[str] = None  # absolute path to a seed-generator program, optional
    link_flags: List[str] = field(default_factory=list)  # extra linker flags, e.g. ['-lm']
    kind: str = "fuzz"              # "fuzz" (C/C++ sanitizer track) | "universal" (any stack, static)

    # budgets / limits (with defaults)
    time_budget_s: int = 60
    max_iters: int = 200000
    rss_mb: int = 2048
    rng_seed: int = 1337


def _abs(root: str, rel: str) -> str:
    return os.path.normpath(os.path.join(root, rel))


def load_task(path: str, diff_override: Optional[str] = None,
              sarif_override: Optional[str] = None) -> Task:
    """Load a task. `diff_override` / `sarif_override` (from the CLI) take
    precedence over the task file's ``diff`` / ``sarif`` keys."""
    if not os.path.exists(path):
        # allow bare task name -> tasks/<name>.json
        cand = os.path.join(PROJECT_ROOT, "tasks", path)
        for ext in ("", ".json", ".yaml", ".yml"):
            if os.path.exists(cand + ext):
                path = cand + ext
                break
    if not os.path.exists(path):
        raise FileNotFoundError("task file not found: %s" % path)

    d = _load_raw(path)
    root = _abs(PROJECT_ROOT, d["root"])
    budgets = d.get("budgets", {})

    # ---- real-world signal ingestion (diff / SARIF) ----------------------
    from . import ingest  # local import to avoid a cycle at module load
    diff_changed = list(d.get("diff_changed", []))
    changed_lines: Dict[str, List[int]] = {}
    diff_src = diff_override or d.get("diff") or "task"
    if diff_src == "git":
        changed_lines = ingest.changed_files_from_git(root)
    elif diff_src.startswith("git-range:"):
        changed_lines = ingest.changed_files_from_git_range(root, diff_src.split(":", 1)[1])
    elif diff_src != "task":
        dp = diff_src if os.path.isabs(diff_src) else _abs(root, diff_src)
        if not os.path.exists(dp):
            dp = _abs(PROJECT_ROOT, diff_src)
        changed_lines = ingest.changed_files_from_diff_file(dp)
    if diff_src != "task":
        # A live/real diff is authoritative: only what actually changed counts.
        diff_changed = sorted(changed_lines)

    static_alerts = list(d.get("static_alerts", []))
    sarif_src = sarif_override or d.get("sarif") or ""
    if sarif_src:
        sp = sarif_src if os.path.isabs(sarif_src) else _abs(root, sarif_src)
        if not os.path.exists(sp):
            sp = _abs(PROJECT_ROOT, sarif_src)
        static_alerts += ingest.alerts_from_sarif(sp, root)

    return Task(
        name=d["name"],
        language=d.get("language", "c"),
        root=root,
        sources=[_abs(root, s) for s in d.get("sources", [])],
        harness=(_abs(root, d["harness"]) if d.get("harness") else ""),
        include_dirs=[_abs(root, i) for i in d.get("include_dirs", ["."])],
        test_sources=[_abs(root, s) for s in d.get("test_sources", [])],
        patch_scope=[_abs(root, s) for s in d.get("patch_scope", d.get("sources", []))],
        magic=d.get("magic"),
        diff_changed=diff_changed,
        static_alerts=static_alerts,
        description=d.get("description", ""),
        seeds=[_abs(root, s) for s in d.get("seeds", [])],
        raw=d,
        diff_source=diff_src,
        sarif_source=sarif_src,
        changed_lines=changed_lines,
        probe=(_abs(root, d["probe"]) if d.get("probe") else None),
        seed_generator=(_abs(root, d["seed_generator"]) if d.get("seed_generator") else None),
        link_flags=list(d.get("link_flags", [])),
        kind=d.get("kind", "fuzz"),
        time_budget_s=int(budgets.get("time_budget_s", 60)),
        max_iters=int(budgets.get("max_iters", 200000)),
        rss_mb=int(budgets.get("rss_mb", 2048)),
        rng_seed=int(budgets.get("rng_seed", 1337)),
    )


def rel_to_root(task: Task, abspath: str) -> str:
    try:
        return os.path.relpath(abspath, task.root).replace(os.sep, "/")
    except ValueError:
        return abspath.replace(os.sep, "/")
