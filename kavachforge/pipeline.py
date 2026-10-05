"""The KavachForge orchestrator: runs the closed loop for one task and
emits the evidence bundle + dashboard.

    diff/alerts -> risk ranking -> LLM seeds + fuzzing -> reproduce & dedup
    -> LLM patch (+reflection) -> build + PoV-replay + tests -> evidence
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict
from typing import Dict

from . import (config, discovery, llm, patcher, report, risk, toolchain,
               util, validator, verifier)


def run_task(task_path: str, out_root: str = "artifacts",
             provider=None, model=None, budget: int = 6,
             engine_pref=None, keep_worktree: bool = False) -> Dict:
    t_start = time.time()
    task = config.load_task(task_path)
    work_dir = os.path.join(out_root, task.name)
    os.makedirs(work_dir, exist_ok=True)

    print(util.bold("\nKavachForge — target: %s" % task.name))
    util.info(util.dim(task.description))

    tc = toolchain.detect(engine_pref)
    client = llm.LLMClient(provider=provider, model=model, budget=budget,
                           cache_dir="cache/llm",
                           log_dir=os.path.join(work_dir, "llm_log"))
    util.info("toolchain : %s" % tc.note)
    util.info("model     : %s" % client.describe())

    # ---- Stage 1: risk ----------------------------------------------------
    util.stage("Risk prioritization (diff → sink)")
    harness_text = util.read_text(task.harness)
    ledger = risk.analyze(task, harness_text)
    for r in ledger[:5]:
        util.step("score %d  %s  (%s:%d)  %s"
                  % (r["score"], r["function"], r["file"], r["line"],
                     ", ".join(r["sinks"]) or "-"))
    if ledger:
        util.good("ranked %d function(s); top = %s (score %d)"
                  % (len(ledger), ledger[0]["function"], ledger[0]["score"]))

    # ---- Stage 2: build + seeds ------------------------------------------
    util.stage("Build target & generate seeds")
    try:
        fuzzer_bin = discovery.build_fuzzer(task, tc, work_dir)
    except discovery.BuildError as e:
        util.bad("target failed to build")
        print(e.log[-800:])
        raise
    util.good("built discovery binary (%s engine)" % tc.engine)
    seeds, seed_src = discovery.llm_seeds(task, client)
    util.good("%d seeds ready (%s); magic gate: %s"
              % (len(seeds), seed_src, task.magic or "none"))

    # ---- Stage 3: discovery ----------------------------------------------
    util.stage("Hybrid discovery (seeds + fuzzing)")
    disc = discovery.run(task, tc, fuzzer_bin, seeds, work_dir)
    st = disc["stats"]
    first_pov = None
    if disc["crashes"]:
        first_pov = "%.1fs" % st["seconds"]
        util.good("crash found via %s after %s (%d execs)"
                  % (st["engine"], first_pov, st["execs"]))
    else:
        util.warn("no crash within budget (%ds, %d execs) — clean target?"
                  % (st["seconds"], st["execs"]))

    # ---- Stage 4: verify + dedup -----------------------------------------
    util.stage("Reproduce, deduplicate & classify")
    findings = verifier.verify(task, fuzzer_bin, disc["crashes"])
    for f in findings:
        util.good("%s  %s (%s, %s)  at %s"
                  % (f.id, f.cwe, f.cwe_name, f.severity, f.crash_file))
    if not findings:
        util.info("no reproducible finding to report")

    # ---- Stage 5: patch + validate ---------------------------------------
    finding_dicts = []
    for f in findings:
        util.stage("Repair & verify — %s" % f.id)
        pr = patcher.propose(task, f, client, attempts=2)
        patch_entry = {}
        validation = {"status": "Unpatched", "gates": []}
        if pr is None:
            util.warn("no patch could be synthesized")
        else:
            util.step("patch via %s (%d attempt(s))" % (pr.source, pr.attempts))
            for rej in pr.rejected:
                util.step(util.dim("reflected: " + rej))
            v = validator.validate(task, tc, f, pr.diff, work_dir, keep=keep_worktree)
            validation = v.as_dict()
            for g in v.gates:
                (util.good if g.passed else util.bad)("%s — %s" % (g.name, g.detail))
            if v.status == "Verified":
                util.good(util.green("PATCH VERIFIED — builds, blocks PoV, tests pass"))
            else:
                util.bad("patch rejected at an evidence gate")
            patch_entry = {"diff": pr.diff, "rel_path": pr.rel_path,
                           "source": pr.source, "attempts": pr.attempts,
                           "rationale": pr.rationale, "rejected": pr.rejected}

        fd = {
            "id": f.id, "signature": f.signature, "asan_class": f.asan_class,
            "cwe": f.cwe, "cwe_name": f.cwe_name, "severity": f.severity,
            "access": f.access, "crash_file": f.crash_file, "crash_func": f.crash_func,
            "frames": f.frames,
            "pov_file": os.path.relpath(f.pov_path, work_dir),
            "pov_sha256": f.pov_sha256, "pov_size": f.pov_size,
            "pov_hexdump": util.hexdump(open(f.pov_path, "rb").read(), 128),
            "repro_cmd": f.repro_cmd, "asan_report": f.asan_report,
            "patch": patch_entry, "validation": validation,
        }
        finding_dicts.append(fd)

    # ---- baseline tests (context for judges) -----------------------------
    base = validator.baseline_tests(task, tc, work_dir)

    # ---- metrics & evidence ----------------------------------------------
    n_verified = sum(1 for f in finding_dicts
                     if f["validation"]["status"] == "Verified")
    metrics = {
        "unique_findings": len(finding_dicts),
        "verified_patches": n_verified,
        "unverified_alerts_reported": 0,
        "time_to_first_pov": first_pov or "n/a",
        "baseline_tests_pass": base.passed,
        "total_seconds": round(time.time() - t_start, 2),
        "llm_budget": client.budget,
    }
    ev = report.build_evidence(
        task, tc.note, client.describe(), ledger, st, finding_dicts, metrics,
        {"live": client.calls, "cached": client.cached, "budget": client.budget})
    paths = report.write_reports(ev, work_dir)

    util.stage("Evidence bundle")
    util.good("findings: %d   verified patches: %d   unverified alerts: 0"
              % (len(finding_dicts), n_verified))
    util.good("baseline regression tests: %s" % ("PASS" if base.passed else "FAIL"))
    util.good("evidence : %s" % paths["json"])
    util.good("dashboard: %s" % paths["html"])
    util.info(util.dim("total %.1fs | LLM live calls %d / budget %d"
                       % (metrics["total_seconds"], client.calls, client.budget)))
    return {"evidence": ev, "paths": paths, "metrics": metrics}
