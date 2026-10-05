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

    # budgets / limits (with defaults)
    time_budget_s: int = 60
    max_iters: int = 200000
    rss_mb: int = 2048
    rng_seed: int = 1337


def _abs(root: str, rel: str) -> str:
    return os.path.normpath(os.path.join(root, rel))


def load_task(path: str) -> Task:
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

    return Task(
        name=d["name"],
        language=d.get("language", "c"),
        root=root,
        sources=[_abs(root, s) for s in d["sources"]],
        harness=_abs(root, d["harness"]),
        include_dirs=[_abs(root, i) for i in d.get("include_dirs", ["."])],
        test_sources=[_abs(root, s) for s in d.get("test_sources", [])],
        patch_scope=[_abs(root, s) for s in d.get("patch_scope", d["sources"])],
        magic=d.get("magic"),
        diff_changed=d.get("diff_changed", []),
        static_alerts=d.get("static_alerts", []),
        description=d.get("description", ""),
        seeds=[_abs(root, s) for s in d.get("seeds", [])],
        raw=d,
        time_budget_s=int(budgets.get("time_budget_s", 60)),
        max_iters=int(budgets.get("max_iters", 200000)),
        rss_mb=int(budgets.get("rss_mb", 2048)),
        rng_seed=int(budgets.get("rng_seed", 1337)),
    )


def rel_to_root(task: Task, abspath: str) -> str:
    try:
        return os.path.relpath(abspath, task.root)
    except ValueError:
        return abspath
